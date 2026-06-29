package redact

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestRedact_Adversarial pins down the redactor's behaviour against inputs
// designed to slip past a naïve regex pass. Each row is either a "must redact"
// (regression if we ever stop catching it) or a "known gap" — documented as
// non-matching so a future tightening of the patterns is visible as a diff
// here, not as a silent privacy improvement nobody noticed.
func TestRedact_Adversarial(t *testing.T) {
	r := New("", false, 0, 0, 0, zap.NewNop())

	cases := []struct {
		name        string
		in          string
		mustRedact  []string // these substrings must NOT survive in the output
		knownGap    bool     // true = we don't catch it today; documents the limit
		mustContain string   // optional: marker we expect in redacted output
	}{
		{
			name:        "multiple-emails-one-line",
			in:          "from a@x.com cc b@y.com bcc c@z.com",
			mustRedact:  []string{"a@x.com", "b@y.com", "c@z.com"},
			mustContain: "[email]",
		},
		{
			name:        "email-with-plus-tag",
			in:          "owner=user+ops@example.com",
			mustRedact:  []string{"user+ops@example.com"},
			mustContain: "[email]",
		},
		{
			name:        "bearer-lowercase-header",
			in:          "authorization: bearer ZmFrZS50b2tlbi52YWx1ZQ",
			mustRedact:  []string{"ZmFrZS50b2tlbi52YWx1ZQ"},
			mustContain: "[token]",
		},
		{
			name:        "ipv4-inside-url",
			in:          "GET http://10.0.0.42:8080/healthz failed",
			mustRedact:  []string{"10.0.0.42"},
			mustContain: "[ip]",
		},
		{
			name:        "ipv6-loopback-compact",
			in:          "bound to ::1 port 5432",
			mustRedact:  []string{"::1"},
			mustContain: "[ip]",
		},
		{
			name:        "ipv6-ipv4-mapped",
			in:          "client ::ffff:127.0.0.1 connected",
			mustRedact:  []string{"::ffff"}, // IPv4 part also caught by ipv4 pattern
			mustContain: "[ip]",
		},
		{
			name:        "ipv6-leading-double-colon-multi",
			in:          "src=::2001:db8 dst=fe80::1",
			mustRedact:  []string{"::2001:db8", "fe80::1"},
			mustContain: "[ip]",
		},
		{
			name:        "email-after-newline",
			in:          "line1\nuser@example.com\nline3",
			mustRedact:  []string{"user@example.com"},
			mustContain: "[email]",
		},
		{
			name:       "ipv4-as-integer-not-an-ip",
			in:         "counter reached 3232235521",
			mustRedact: nil, // 3232235521 == 192.168.0.1 packed; we deliberately don't decode
		},
		{
			name:       "ipv4-with-spaces-not-an-ip",
			in:         "values: 192. 168. 1. 1 — table separator",
			mustRedact: nil, // spaces break the regex; this is not a real IP literal
		},
		{
			name:        "jwt-typical",
			in:          "session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHgifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA expired",
			mustRedact:  []string{"eyJhbGciOiJIUzI1NiJ9"},
			mustContain: "[jwt]",
		},
		{
			name:        "private-key-header",
			in:          "-----BEGIN RSA PRIVATE KEY-----",
			mustRedact:  []string{"BEGIN RSA PRIVATE KEY"},
			mustContain: "[private-key]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := r.Redact([]string{tc.in})
			got := strings.Join(out, "\n")

			if tc.knownGap {
				// Document the gap. If the redactor ever starts catching it
				// (good!), flip knownGap to false and add mustContain.
				for _, leak := range tc.mustRedact {
					if !strings.Contains(got, leak) {
						t.Logf("knownGap closed for %q — flip knownGap=false and pin the marker", tc.name)
					}
				}
				return
			}

			for _, leak := range tc.mustRedact {
				if strings.Contains(got, leak) {
					t.Errorf("leak: %q survived in %q", leak, got)
				}
			}
			if tc.mustContain != "" && !strings.Contains(got, tc.mustContain) {
				t.Errorf("want marker %q in %q", tc.mustContain, got)
			}
		})
	}
}

// FuzzRedact_NoEmailLeak asserts that no matter what junk surrounds a known
// email literal, the email substring never survives the redactor. Catches
// regex anchoring regressions (e.g. a future change adding ^/$ that breaks
// inline matching) and adjacent-character regressions (a pattern requiring
// whitespace boundaries that doesn't get hit when the email is glued to
// punctuation).
//
// Run with: go test ./internal/redact -fuzz=FuzzRedact_NoEmailLeak -fuzztime=30s
func FuzzRedact_NoEmailLeak(f *testing.F) {
	r := New("", false, 0, 0, 0, zap.NewNop())
	seeds := []string{
		"%s",
		"prefix %s suffix",
		"=%s=",
		"<%s>",
		"\"%s\"",
		"[%s]",
		"\t%s\t",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	const email = "leak@example.com"
	f.Fuzz(func(t *testing.T, tmpl string) {
		// Only feed templates that actually embed the secret; otherwise we're
		// not testing the redactor, we're testing strings.Contains.
		if !strings.Contains(tmpl, "%s") {
			return
		}
		// Bound input — fuzzer can generate massive strings that hit the size
		// guard and trivially "pass" by being dropped.
		if len(tmpl) > 2048 {
			return
		}
		line := strings.Replace(tmpl, "%s", email, 1)
		out, _ := r.Redact([]string{line})
		joined := strings.Join(out, "\n")

		if strings.Contains(joined, email) {
			t.Fatalf("email leaked through redactor:\n  template=%q\n  input=%q\n  output=%q",
				tmpl, line, joined)
		}
	})
}
