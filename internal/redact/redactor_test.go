package redact

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestRedact_Email(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"user logged in as admin@example.com from localhost"}
	result, stats := r.Redact(lines)

	if !strings.Contains(result[0], "[email]") {
		t.Errorf("expected [email], got: %s", result[0])
	}
	if strings.Contains(result[0], "admin@example.com") {
		t.Error("email should be redacted")
	}
	if stats.Replacements == 0 {
		t.Error("should have at least 1 replacement")
	}
}

func TestRedact_Phone(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"contact: +1 (555) 123-4567"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[phone]") {
		t.Errorf("expected [phone], got: %s", result[0])
	}
}

func TestRedact_SSN(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"SSN: 123-45-6789"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[ssn]") {
		t.Errorf("expected [ssn], got: %s", result[0])
	}
}

func TestRedact_IPv4(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"connection from 192.168.1.100 established"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[ip]") {
		t.Errorf("expected [ip], got: %s", result[0])
	}
}

func TestRedact_BearerToken(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[token]") && !strings.Contains(result[0], "[jwt]") {
		t.Errorf("expected token/jwt redaction, got: %s", result[0])
	}
}

func TestRedact_JWT(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[jwt]") {
		t.Errorf("expected [jwt], got: %s", result[0])
	}
}

func TestRedact_AWSKey(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"key=AKIAIOSFODNN7EXAMPLE"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[aws-key]") {
		t.Errorf("expected [aws-key], got: %s", result[0])
	}
}

func TestRedact_Password(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"password=SuperSecret123!"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[password]") {
		t.Errorf("expected [password], got: %s", result[0])
	}
}

func TestRedact_CreditCard_Visa(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"card: 4111111111111111"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[card]") {
		t.Errorf("expected [card], got: %s", result[0])
	}
}

func TestRedact_CreditCard_Mastercard(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"card: 5500000000000004"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[card]") {
		t.Errorf("expected [card], got: %s", result[0])
	}
}

func TestRedact_IBAN(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"account: DE89370400440532013000"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[iban]") {
		t.Errorf("expected [iban], got: %s", result[0])
	}
}

func TestRedact_UUID(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"request_id=550e8400-e29b-41d4-a716-446655440000"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[uuid]") {
		t.Errorf("expected [uuid], got: %s", result[0])
	}
}

func TestRedact_PrivateKey(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"-----BEGIN RSA PRIVATE KEY-----"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[private-key]") {
		t.Errorf("expected [private-key], got: %s", result[0])
	}
}

func TestRedact_APIKey(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"api_key=sk-1234567890abcdef"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[apikey]") {
		t.Errorf("expected [apikey], got: %s", result[0])
	}
}

func TestRedact_NoSensitiveData(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"application started successfully", "listening on port 8080"}
	result, stats := r.Redact(lines)

	if result[0] != lines[0] || result[1] != lines[1] {
		t.Error("non-sensitive lines should not be modified")
	}
	if stats.RedactedLines != 0 {
		t.Errorf("expected 0 redacted lines, got %d", stats.RedactedLines)
	}
}

func TestRedact_MultiplePatterns(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{"user admin@test.com connected from 10.0.0.1 with password=secret"}
	result, stats := r.Redact(lines)

	if strings.Contains(result[0], "admin@test.com") {
		t.Error("email should be redacted")
	}
	if strings.Contains(result[0], "10.0.0.1") {
		t.Error("IP should be redacted")
	}
	if strings.Contains(result[0], "secret") {
		t.Error("password should be redacted")
	}
	if stats.Replacements < 3 {
		t.Errorf("expected at least 3 replacements, got %d", stats.Replacements)
	}
}

func TestRedact_CustomPatterns(t *testing.T) {
	r := New(`CUSTOM-\d+,TICKET-\d+`, false, 0, 0, zap.NewNop())
	lines := []string{"processing CUSTOM-12345 and TICKET-67890"}
	result, _ := r.Redact(lines)

	if !strings.Contains(result[0], "[redacted]") {
		t.Errorf("expected [redacted], got: %s", result[0])
	}
	if strings.Contains(result[0], "CUSTOM-12345") {
		t.Error("custom pattern should be redacted")
	}
}

func TestRedact_InvalidCustomPattern(t *testing.T) {
	// Invalid regex should be skipped without crash
	r := New(`[invalid`, false, 0, 0, zap.NewNop())
	lines := []string{"normal log line"}
	result, _ := r.Redact(lines)

	if result[0] != "normal log line" {
		t.Error("invalid pattern should not affect output")
	}
}

func TestRedact_Stats(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	lines := []string{
		"normal line",
		"email: test@test.com",
		"ip: 192.168.1.1",
		"normal again",
	}
	_, stats := r.Redact(lines)

	if stats.TotalLines != 4 {
		t.Errorf("expected 4 total lines, got %d", stats.TotalLines)
	}
	if stats.RedactedLines != 2 {
		t.Errorf("expected 2 redacted lines, got %d", stats.RedactedLines)
	}
	if stats.ByCategory["pii"] < 1 {
		t.Error("expected pii category count")
	}
	if stats.ByCategory["network"] < 1 {
		t.Error("expected network category count")
	}
}

// TestRedact_OversizeLineFailsClosed verifies a line over the per-line byte cap
// is dropped (content never forwarded), not passed through.
func TestRedact_OversizeLineFailsClosed(t *testing.T) {
	r := New("", false, 32 /* tiny line cap */, 1<<20, zap.NewNop())
	secret := "password=" + strings.Repeat("A", 100) // 100-char value, well over 32B line
	result, stats := r.Redact([]string{secret})

	if len(result) != 1 {
		t.Fatalf("expected 1 line, got %d", len(result))
	}
	if strings.Contains(result[0], "AAAA") {
		t.Errorf("oversize line content must not be forwarded, got: %q", result[0])
	}
	if result[0] != droppedLineMarker {
		t.Errorf("expected dropped marker, got: %q", result[0])
	}
	if stats.DroppedLines != 1 {
		t.Errorf("expected DroppedLines=1, got %d", stats.DroppedLines)
	}
}

// TestRedact_TotalByteBudgetFailsClosed verifies that once the cumulative byte
// budget is exhausted, remaining lines are dropped rather than forwarded.
func TestRedact_TotalByteBudgetFailsClosed(t *testing.T) {
	r := New("", false, 1024, 20 /* tiny total budget */, zap.NewNop())
	lines := []string{"0123456789", "0123456789", "this-line-should-be-dropped"}
	result, stats := r.Redact(lines)

	joined := strings.Join(result, "\n")
	if strings.Contains(joined, "this-line-should-be-dropped") {
		t.Errorf("line past the byte budget must not be forwarded, got: %q", joined)
	}
	if stats.DroppedLines == 0 {
		t.Error("expected at least one dropped line once budget exhausted")
	}
}

// TestRedact_DefaultsApplied confirms non-positive caps fall back to safe
// defaults rather than disabling the guard.
func TestRedact_DefaultsApplied(t *testing.T) {
	r := New("", false, 0, 0, zap.NewNop())
	if r.maxLineBytes != defaultMaxLineBytes || r.maxTotalBytes != defaultMaxTotalBytes {
		t.Errorf("expected defaults, got line=%d total=%d", r.maxLineBytes, r.maxTotalBytes)
	}
}
