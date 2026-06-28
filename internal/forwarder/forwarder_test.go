package forwarder

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// newTestForwarder spins up a TLS server with the supplied handler, builds
// the matching collector keypair, and returns a Forwarder configured to dial
// the server. The cleanup closes the server.
func newTestForwarder(t *testing.T, handler http.HandlerFunc) (*Forwarder, *httptest.Server) {
	t.Helper()

	caCert, caKey, caPEM := newCA(t)
	serverCert := newServerCert(t, caCert, caKey)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
	srv.StartTLS()

	// Persist CA + client cert/key to disk so the production loaders see real
	// files (Forwarder reads CA from a path, ClientReloader reads cert/key).
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	clientCertPath := filepath.Join(dir, "tls.crt")
	clientKeyPath := filepath.Join(dir, "tls.key")
	writeClientKeypair(t, caCert, caKey, clientCertPath, clientKeyPath)

	reloader, err := auth.NewClientReloader(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("NewClientReloader: %v", err)
	}

	f, err := New(Config{
		URL:        srv.URL + "/ingest",
		CARootFile: caPath,
		Reloader:   reloader,
		Timeout:    5 * time.Second,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, srv
}

func TestForwarder_Success(t *testing.T) {
	f, srv := newTestForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Error("missing protobuf content type")
		}
		if r.Header.Get(auth.HeaderTimestamp) == "" {
			t.Error("missing X-Muthur-Timestamp")
		}
		if r.Header.Get(auth.HeaderNonce) == "" {
			t.Error("missing X-Muthur-Nonce")
		}
		// The legacy bearer token must NOT be sent any more.
		if r.Header.Get("X-Collector-Token") != "" {
			t.Error("legacy X-Collector-Token header is still being sent")
		}
		// The TLS client cert must have reached the server.
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("no peer cert; collector failed to present mTLS material")
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("empty body")
		}
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	err := f.Forward(context.Background(), &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "TestAlert",
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
}

func TestForwarder_ClientErrorDoesNotRetry(t *testing.T) {
	calls := 0
	f, srv := newTestForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer srv.Close()

	err := f.Forward(context.Background(), &pb.AlertPayload{})
	if err == nil {
		t.Error("expected error on 401")
	}
	if calls != 1 {
		t.Errorf("retried a 4xx response: %d calls (want 1)", calls)
	}
}

func TestForwarder_ServerErrorRetries(t *testing.T) {
	attempts := 0
	f, srv := newTestForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	defer srv.Close()

	err := f.Forward(context.Background(), &pb.AlertPayload{})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestNew_RequiresURL(t *testing.T) {
	if _, err := New(Config{}, zap.NewNop()); err == nil {
		t.Error("New accepted empty config")
	}
}

func TestNew_RequiresReloader(t *testing.T) {
	if _, err := New(Config{URL: "https://x", CARootFile: "/no/such"}, zap.NewNop()); err == nil {
		t.Error("New accepted nil reloader")
	}
}

// --- helpers ---

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
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
	return cert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "brain"},
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

func writeClientKeypair(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, certPath, keyPath string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "cluster-a"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, caCert, &priv.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
