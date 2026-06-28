package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientReloader_Reloads(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeClientCert(t, certPath, keyPath, "first")

	r, err := NewClientReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewClientReloader: %v", err)
	}
	first, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("get first: %v", err)
	}
	if name := commonName(t, first.Certificate[0]); name != "first" {
		t.Fatalf("first CN = %q, want first", name)
	}

	writeClientCert(t, certPath, keyPath, "second")
	bumpMtime(t, certPath)

	second, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("get second: %v", err)
	}
	if name := commonName(t, second.Certificate[0]); name != "second" {
		t.Errorf("second CN = %q, want second (hot reload failed)", name)
	}
}

func TestClientReloader_KeepsCacheOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeClientCert(t, certPath, keyPath, "good")

	r, err := NewClientReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewClientReloader: %v", err)
	}
	good, _ := r.GetClientCertificate(nil)

	// Mid-rotation corruption.
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, certPath)

	got, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("after corruption: %v", err)
	}
	if &got.Certificate[0][0] != &good.Certificate[0][0] {
		t.Error("reloader did not retain cached cert across reload failure")
	}
}

func TestClientReloader_RequiresPaths(t *testing.T) {
	if _, err := NewClientReloader("", ""); err == nil {
		t.Error("NewClientReloader accepted empty paths")
	}
}

func TestClientReloader_Current(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeClientCert(t, certPath, keyPath, "x")

	r, _ := NewClientReloader(certPath, keyPath)
	cur := r.Current()
	if len(cur.Certificate) == 0 {
		t.Error("Current returned empty cert after successful load")
	}
}

func writeClientCert(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bumpMtime(t *testing.T, path string) {
	t.Helper()
	st, _ := os.Stat(path)
	future := st.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func commonName(t *testing.T, der []byte) string {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert.Subject.CommonName
}
