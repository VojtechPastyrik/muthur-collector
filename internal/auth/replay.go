package auth

import (
	"crypto/rand"
	"encoding/hex"
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

// FreshNonce returns a 32-hex-char random nonce. On the signed transport the
// nonce is also AAD for the HPKE envelope and part of the signed base, so it
// comes straight from crypto/rand rather than a seeded PRNG.
func FreshNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
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
