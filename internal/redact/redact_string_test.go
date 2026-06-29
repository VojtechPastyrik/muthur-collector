package redact

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestRedactString_Categories covers the non-log path (Summary, Description,
// label values, metric descriptions). It mirrors the per-category line tests
// so a pattern regression on either surface fails the same way.
func TestRedactString_Categories(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())

	cases := []struct {
		name string
		in   string
		want string // substring that must appear in the redacted output
		bad  string // substring that must NOT appear (the original secret)
	}{
		{"email", "owner: admin@example.com", "[email]", "admin@example.com"},
		{"ipv4", "host 10.1.2.3 is degraded", "[ip]", "10.1.2.3"},
		{"jwt", "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "[jwt]", "eyJhbGciOiJIUzI1NiJ9"},
		{"bearer", "Authorization: Bearer abc.def.ghi", "[token]", "abc.def.ghi"},
		{"aws-key", "AKIAIOSFODNN7EXAMPLE leaked", "[aws-key]", "AKIAIOSFODNN7EXAMPLE"},
		{"uuid", "req=550e8400-e29b-41d4-a716-446655440000", "[uuid]", "550e8400-e29b-41d4-a716-446655440000"},
		{"ssn", "ssn: 123-45-6789", "[ssn]", "123-45-6789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.RedactString(tc.in)
			if !strings.Contains(got, tc.want) {
				t.Errorf("want marker %q in %q", tc.want, got)
			}
			if strings.Contains(got, tc.bad) {
				t.Errorf("secret %q must not appear in %q", tc.bad, got)
			}
		})
	}
}

func TestRedactString_EmptyPassthrough(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	if got := r.RedactString(""); got != "" {
		t.Errorf("empty input must round-trip, got %q", got)
	}
}

func TestRedactString_BenignPassthrough(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	in := "Pod restarted: container runtime exited with code 137"
	if got := r.RedactString(in); got != in {
		t.Errorf("benign text must round-trip, got %q", got)
	}
}

// TestRedactString_OversizeFailsClosed verifies a string past maxStringBytes
// is replaced with droppedStringMarker — an annotation-driven inflation
// attack cannot push a multi-MB blob into the LLM prompt by hiding under the
// log path's per-line cap.
func TestRedactString_OversizeFailsClosed(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	// embed a secret inside an oversize blob; the whole string must be dropped,
	// not just the secret-shaped substring redacted around the rest.
	huge := strings.Repeat("A", maxStringBytes+1) + " admin@example.com"
	got := r.RedactString(huge)

	if got != droppedStringMarker {
		t.Errorf("oversize string must be replaced with %q, got %q", droppedStringMarker, got[:min(120, len(got))])
	}
	if strings.Contains(got, "admin@example.com") {
		t.Error("oversize string content must not be forwarded")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
