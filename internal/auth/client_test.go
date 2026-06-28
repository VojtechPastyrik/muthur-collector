package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewBrainClient_RequiresPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBrainClient("https://x", bad); err == nil {
		t.Error("NewBrainClient accepted a non-PEM CA file")
	}
}

func TestBootstrap_PostsExpectedBody(t *testing.T) {
	server, caFile := newFakeBrain(t, func(r *http.Request) (int, signResponse) {
		if r.URL.Path != "/bootstrap-cert" {
			t.Errorf("path = %q, want /bootstrap-cert", r.URL.Path)
		}
		if r.Header.Get(HeaderTimestamp) == "" {
			t.Error("missing X-Muthur-Timestamp")
		}
		if r.Header.Get(HeaderNonce) == "" {
			t.Error("missing X-Muthur-Nonce")
		}
		var req bootstrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.ClusterID != "cluster-a" || req.BootstrapToken != "tok" || req.CSR == "" {
			t.Errorf("unexpected body: %+v", req)
		}
		return http.StatusOK, signResponse{Certificate: "CERT", CA: "CA"}
	})
	defer server.Close()

	client, err := NewBrainClient(server.URL, caFile)
	if err != nil {
		t.Fatalf("NewBrainClient: %v", err)
	}
	csrPEM, _, err := GenerateCSR("acme", "cluster-a")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	cert, ca, err := client.Bootstrap(context.Background(), "cluster-a", "tok", csrPEM)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if string(cert) != "CERT" {
		t.Errorf("cert = %q, want CERT", cert)
	}
	if string(ca) != "CA" {
		t.Errorf("ca = %q, want CA", ca)
	}
}

func TestBootstrap_PropagatesBrainErrors(t *testing.T) {
	server, caFile := newFakeBrain(t, func(*http.Request) (int, signResponse) {
		return http.StatusUnauthorized, signResponse{}
	})
	defer server.Close()

	client, _ := NewBrainClient(server.URL, caFile)
	csrPEM, _, _ := GenerateCSR("acme", "cluster-a")

	_, _, err := client.Bootstrap(context.Background(), "cluster-a", "tok", csrPEM)
	if err == nil {
		t.Fatal("Bootstrap accepted a 401 from brain")
	}
}

func TestRenew_SendsClientCert(t *testing.T) {
	// Build a CA + leaf so renew can present a valid client cert. The fake
	// brain enforces VerifyClientCertIfGiven and checks the call hit
	// /sign-csr with a client cert attached.
	caCert, caKey, caPEM := makeCA(t)
	leaf := makeLeaf(t, caCert, caKey, "cluster-a")

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign-csr" {
			t.Errorf("path = %q, want /sign-csr", r.URL.Path)
		}
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("expected client cert; none received")
		}
		var req renewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CSR == "" {
			t.Error("missing CSR")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(signResponse{Certificate: "RENEWED", CA: "CA"})
	}))
	serverCert := makeServerCert(t, caCert, caKey)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()

	caDir := t.TempDir()
	caPath := filepath.Join(caDir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewBrainClient(srv.URL, caPath)
	if err != nil {
		t.Fatalf("NewBrainClient: %v", err)
	}

	csrPEM, _, _ := GenerateCSR("acme", "cluster-a")
	cert, _, err := client.Renew(context.Background(), leaf, csrPEM)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if string(cert) != "RENEWED" {
		t.Errorf("cert = %q, want RENEWED", cert)
	}
}

func TestStampReplayHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	stampReplayHeaders(req)
	if req.Header.Get(HeaderTimestamp) == "" {
		t.Error("timestamp header empty")
	}
	nonce := req.Header.Get(HeaderNonce)
	if len(nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 hex chars", len(nonce))
	}
}

// --- helpers ---

// newFakeBrain returns a TLS server whose CA file path is also returned so the
// BrainClient can verify it. The supplied handler decides the response.
func newFakeBrain(t *testing.T, h func(*http.Request) (int, signResponse)) (*httptest.Server, string) {
	t.Helper()
	caCert, caKey, caPEM := makeCA(t)
	serverCert := makeServerCert(t, caCert, caKey)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, resp := h(r)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caPath
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, priv, pemBytes
}

func makeServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "muthur-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, caCert, &priv.PublicKey, caKey)
	parsed, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: parsed}
}

func makeLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) tls.Certificate {
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
	der, _ := x509.CreateCertificate(rand.Reader, tpl, caCert, &priv.PublicKey, caKey)
	parsed, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: parsed}
}

// silence unused import warning in case a future refactor drops io usage.
var _ = io.Discard
