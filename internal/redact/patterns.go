package redact

import (
	"regexp"
)

type pattern struct {
	category    string
	name        string
	regex       *regexp.Regexp
	replacement string
}

// Order matters: longer/more-specific patterns first to prevent
// shorter patterns (like phone) from consuming parts of card numbers or IBANs.
var builtinPatterns = []pattern{
	// Credentials
	{category: "credentials", name: "bearer", regex: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`), replacement: "[token]"},
	{category: "credentials", name: "jwt", regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), replacement: "[jwt]"},
	{category: "credentials", name: "basic", regex: regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/]+=*`), replacement: "[basic]"},
	{category: "credentials", name: "aws-key", regex: regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`), replacement: "[aws-key]"},
	{category: "credentials", name: "aws-secret", regex: regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`), replacement: "[aws-secret]"},
	{category: "credentials", name: "private-key", regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`), replacement: "[private-key]"},
	{category: "credentials", name: "password", regex: regexp.MustCompile(`(?i)password\s*[=:]\s*\S+`), replacement: "[password]"},
	{category: "credentials", name: "apikey", regex: regexp.MustCompile(`(?i)api[_-]?key\s*[=:]\s*\S+`), replacement: "[apikey]"},

	// Financial (PCI DSS) — before phone to prevent partial matches
	{category: "financial", name: "visa", regex: regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), replacement: "[card]"},
	{category: "financial", name: "mastercard", regex: regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), replacement: "[card]"},
	{category: "financial", name: "amex", regex: regexp.MustCompile(`\b3[47][0-9]{13}\b`), replacement: "[card]"},
	{category: "financial", name: "discover", regex: regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`), replacement: "[card]"},
	{category: "financial", name: "iban", regex: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`), replacement: "[iban]"},

	// Other — before phone to prevent UUID partial matches
	{category: "other", name: "uuid", regex: regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), replacement: "[uuid]"},

	// PII
	{category: "pii", name: "email", regex: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), replacement: "[email]"},
	{category: "pii", name: "ssn", regex: regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`), replacement: "[ssn]"},
	{category: "pii", name: "phone", regex: regexp.MustCompile(`(?:\+?1[-.\s])?\(?[0-9]{3}\)[-.\s][0-9]{3}[-.\s][0-9]{4}\b`), replacement: "[phone]"},
	{category: "pii", name: "address", regex: regexp.MustCompile(`\b\d{1,5}\s+[A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Court|Ct|Way|Place|Pl)\b`), replacement: "[address]"},

	// Network
	{category: "network", name: "ipv4", regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), replacement: "[ip]"},
	{category: "network", name: "ipv6", regex: regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:){1,7}:|(?i)\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b`), replacement: "[ip]"},
}
