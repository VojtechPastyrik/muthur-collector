package auth

import (
	"encoding/hex"
	"math/rand/v2"
)

// Replay-protection metadata keys. The collector attaches both on every gRPC
// call that the brain replay-protects (Ingest, SignCSR — BootstrapCert
// ignores them but receives them too so the call shape stays uniform).
//
// Mirrors the brain side's lowercased gRPC metadata names.
const (
	MetaTimestamp = "x-muthur-timestamp"
	MetaNonce     = "x-muthur-nonce"
)

// FreshNonce returns a 32-hex-char random nonce. math/rand/v2 seeds itself
// from crypto/rand and is plenty for replay protection, where uniqueness —
// not unpredictability — is the load-bearing property.
func FreshNonce() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.Uint32())
	}
	return hex.EncodeToString(b[:])
}

// StripScheme normalises a configured brain URL to a bare host:port target.
// gRPC dial targets are scheme-less; the chart historically used
// https://muthur-api.example.com and we accept either form.
func StripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://", "grpcs://", "grpc://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			return s[len(prefix):]
		}
	}
	return s
}
