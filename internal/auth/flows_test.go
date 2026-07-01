package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// stubPersister tracks whether Write was called so tests can assert renewal
// happened (or didn't) without wiring a real brain.
type stubPersister struct {
	exists     bool
	certPEM    []byte
	keyPEM     []byte
	caPEM      []byte
	writeCount int
	readErr    error
}

func (s *stubPersister) Exists(context.Context) (bool, error) { return s.exists, nil }
func (s *stubPersister) Read(context.Context) ([]byte, []byte, []byte, error) {
	if s.readErr != nil {
		return nil, nil, nil, s.readErr
	}
	return s.certPEM, s.keyPEM, s.caPEM, nil
}
func (s *stubPersister) Write(_ context.Context, cert, key, ca []byte) error {
	s.writeCount++
	s.certPEM = cert
	s.keyPEM = key
	s.caPEM = ca
	return nil
}

// mintSelfSignedCert produces a self-signed leaf valid until notAfter and a
// matching PKCS#8-encoded PEM private key. Enough to satisfy x509.ParseCertificate
// + tls.X509KeyPair for tests that exercise RenewBefore skip logic.
func mintSelfSignedCert(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa gen: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cluster"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func TestRenewFlow_SkipsWhenCertStillFresh(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	// Cert expires in 6 days; RenewBefore=48h → 6d > 48h → skip.
	certPEM, keyPEM := mintSelfSignedCert(t, now.Add(6*24*time.Hour))
	p := &stubPersister{exists: true, certPEM: certPEM, keyPEM: keyPEM}

	flow := RenewFlow{
		ClusterID:   "test-cluster",
		BrainURL:    "https://unreachable.invalid",
		Persister:   p,
		Logger:      zaptest.NewLogger(t),
		RenewBefore: 48 * time.Hour,
		Now:         func() time.Time { return now },
	}
	if err := flow.Run(context.Background()); err != nil {
		t.Fatalf("Run err = %v, want nil (skip path)", err)
	}
	if p.writeCount != 0 {
		t.Errorf("Persister.Write called %d times, want 0 (skip should not rotate)", p.writeCount)
	}
}

func TestRenewFlow_ProceedsWhenCertNearExpiry(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	// Cert expires in 24h; RenewBefore=48h → 24h < 48h → proceed to brain call.
	certPEM, keyPEM := mintSelfSignedCert(t, now.Add(24*time.Hour))
	p := &stubPersister{exists: true, certPEM: certPEM, keyPEM: keyPEM}

	flow := RenewFlow{
		ClusterID:   "test-cluster",
		BrainURL:    "https://127.0.0.1:1",
		Persister:   p,
		Logger:      zaptest.NewLogger(t),
		RenewBefore: 48 * time.Hour,
		Now:         func() time.Time { return now },
	}
	err := flow.Run(context.Background())
	// We do not stand up a fake brain — the point is that flow got past the
	// skip check and tried to reach out. Any error deeper than the skip is
	// acceptable; a nil error would mean the skip fired (regression).
	if err == nil {
		t.Fatalf("Run err = nil, want brain-side error (skip should not have fired)")
	}
}

func TestRenewFlow_RenewBeforeZeroAlwaysRotates(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	certPEM, keyPEM := mintSelfSignedCert(t, now.Add(30*24*time.Hour))
	p := &stubPersister{exists: true, certPEM: certPEM, keyPEM: keyPEM}

	flow := RenewFlow{
		ClusterID:   "test-cluster",
		BrainURL:    "https://127.0.0.1:1",
		Persister:   p,
		Logger:      zaptest.NewLogger(t),
		RenewBefore: 0, // disabled
		Now:         func() time.Time { return now },
	}
	err := flow.Run(context.Background())
	if err == nil {
		t.Fatalf("Run err = nil, want brain-side error (disabled skip → must proceed)")
	}
}

func TestRenewFlow_MalformedCertProceedsWithRenewal(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	p := &stubPersister{
		exists:  true,
		certPEM: []byte("not a real PEM"),
		keyPEM:  []byte("also not a PEM"),
	}

	flow := RenewFlow{
		ClusterID:   "test-cluster",
		BrainURL:    "https://127.0.0.1:1",
		Persister:   p,
		Logger:      zaptest.NewLogger(t),
		RenewBefore: 48 * time.Hour,
		Now:         func() time.Time { return now },
	}
	err := flow.Run(context.Background())
	if err == nil {
		t.Fatal("Run err = nil, want error (malformed cert should still trip keypair parse or brain call)")
	}
	// tls.X509KeyPair should fail before the brain call — that's the expected
	// failure path. We just want to confirm the skip did NOT swallow the run.
}

func TestCertRemaining(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	certPEM, _ := mintSelfSignedCert(t, now.Add(72*time.Hour))
	got, err := certRemaining(certPEM, now)
	if err != nil {
		t.Fatalf("certRemaining err = %v", err)
	}
	if got != 72*time.Hour {
		t.Errorf("certRemaining = %v, want 72h", got)
	}
}

func TestCertRemaining_NoPEMBlock(t *testing.T) {
	_, err := certRemaining([]byte("garbage"), time.Now())
	if err == nil {
		t.Fatal("certRemaining err = nil, want error on non-PEM input")
	}
	if !errors.Is(err, err) { // sanity: err implements error
		t.Fatal("unexpected error type")
	}
}
