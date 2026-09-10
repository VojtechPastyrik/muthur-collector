package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func signedTestHeaders(t *testing.T) (http.Header, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := []byte("not-a-real-cert-but-stable-bytes")
	h := http.Header{}
	h.Set(HeaderContentDigest, ContentDigest([]byte("body")))
	h.Set(HeaderTimestamp, "1700000000")
	h.Set(HeaderNonce, strings.Repeat("ab", 16))
	h.Set(HeaderCert, "Y2VydA==")
	h.Set(HeaderHPKEKid, "0123456789abcdef")
	if err := SignRequest(h, "POST", "/muthur/v1/ingest", key, leafDER, 1700000000); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return h, key, leafDER
}

func TestSignRequest_RoundTrip(t *testing.T) {
	h, key, leafDER := signedTestHeaders(t)
	info, err := VerifyRequest("post", "/muthur/v1/ingest", h, &key.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if info.Created != 1700000000 || info.KeyID != CertKeyID(leafDER) {
		t.Fatalf("unexpected info %+v", info)
	}
}

func TestVerifyRequest_DetectsTampering(t *testing.T) {
	cases := map[string]func(h http.Header){
		"timestamp": func(h http.Header) { h.Set(HeaderTimestamp, "1700000001") },
		"nonce":     func(h http.Header) { h.Set(HeaderNonce, strings.Repeat("cd", 16)) },
		"digest":    func(h http.Header) { h.Set(HeaderContentDigest, ContentDigest([]byte("other"))) },
		"cert":      func(h http.Header) { h.Set(HeaderCert, "b3RoZXI=") },
		"kid":       func(h http.Header) { h.Set(HeaderHPKEKid, "ffffffffffffffff") },
		"signature": func(h http.Header) { h.Set(HeaderSignature, "sig1=:"+strings.Repeat("A", 88)+":") },
		"created": func(h http.Header) {
			h.Set(HeaderSignatureInput, strings.Replace(h.Get(HeaderSignatureInput), "created=1700000000", "created=1700000001", 1))
		},
		"components": func(h http.Header) {
			h.Set(HeaderSignatureInput, strings.Replace(h.Get(HeaderSignatureInput), ` "x-muthur-hpke-kid"`, "", 1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, key, _ := signedTestHeaders(t)
			mutate(h)
			if _, err := VerifyRequest("POST", "/muthur/v1/ingest", h, &key.PublicKey); err == nil {
				t.Fatal("expected verification failure")
			}
		})
	}
}

func TestVerifyRequest_WrongMethodOrPath(t *testing.T) {
	h, key, _ := signedTestHeaders(t)
	if _, err := VerifyRequest("GET", "/muthur/v1/ingest", h, &key.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("method: got %v", err)
	}
	if _, err := VerifyRequest("POST", "/muthur/v1/sign-csr", h, &key.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("path: got %v", err)
	}
}

func TestVerifyRequest_WrongKey(t *testing.T) {
	h, _, _ := signedTestHeaders(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := VerifyRequest("POST", "/muthur/v1/ingest", h, &other.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRequest_MissingHeaders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := VerifyRequest("POST", "/x", http.Header{}, &key.PublicKey); !errors.Is(err, ErrSignatureMissing) {
		t.Fatalf("got %v", err)
	}
}

func TestSignRequest_RejectsNonP256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := SignRequest(http.Header{}, "POST", "/x", key, nil, 1); !errors.Is(err, ErrSignatureKeyType) {
		t.Fatalf("got %v", err)
	}
}

func TestContentDigest(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderContentDigest, ContentDigest([]byte("hello")))
	if err := VerifyContentDigest(h, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContentDigest(h, []byte("hellp")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("got %v", err)
	}
}
