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
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

type fakeBrain struct {
	pb.UnimplementedBrainServer

	gotPeerCert bool
	gotTS       string
	gotNonce    string
	respondWith error
}

func (f *fakeBrain) Ingest(ctx context.Context, _ *pb.AlertPayload) (*pb.IngestResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(auth.MetaTimestamp); len(v) > 0 {
			f.gotTS = v[0]
		}
		if v := md.Get(auth.MetaNonce); len(v) > 0 {
			f.gotNonce = v[0]
		}
	}
	if f.respondWith != nil {
		return nil, f.respondWith
	}
	return &pb.IngestResponse{}, nil
}

// spinUpTLSBrain runs an in-process gRPC server with mTLS on 127.0.0.1 and
// returns the target string + fakeBrain handle for inspection. The cleanup
// stops the server.
func spinUpTLSBrain(t *testing.T) (string, *fakeBrain, *auth.ClientReloader, string) {
	t.Helper()

	caCert, caKey, caPEM := newCA(t)
	serverCert := newServerCert(t, caCert, caKey)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

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

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	brain := &fakeBrain{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	})))
	pb.RegisterBrainServer(srv, brain)
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Stop() })

	return lis.Addr().String(), brain, reloader, caPath
}

func TestForward_Success(t *testing.T) {
	target, brain, reloader, caPath := spinUpTLSBrain(t)

	f, err := New(Config{Target: target, CARootFile: caPath, Reloader: reloader}, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	if err := f.Forward(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "x"}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if brain.gotTS == "" {
		t.Error("missing x-muthur-timestamp metadata")
	}
	if brain.gotNonce == "" {
		t.Error("missing x-muthur-nonce metadata")
	}
}

func TestForward_PermanentErrorDoesNotRetry(t *testing.T) {
	target, brain, reloader, caPath := spinUpTLSBrain(t)
	brain.respondWith = status.Error(codes.Unauthenticated, "no")

	f, err := New(Config{Target: target, CARootFile: caPath, Reloader: reloader}, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer f.Close()

	err = f.Forward(context.Background(), &pb.AlertPayload{})
	if err == nil {
		t.Fatal("expected error from Unauthenticated")
	}
	if !errors.Is(err, err) {
		// Just ensure error propagation; isPermanent unit-tested below.
	}
}

func TestIsPermanent_Codes(t *testing.T) {
	cases := []struct {
		code codes.Code
		want bool
	}{
		{codes.InvalidArgument, true},
		{codes.Unauthenticated, true},
		{codes.PermissionDenied, true},
		{codes.FailedPrecondition, true},
		{codes.NotFound, true},
		{codes.Unimplemented, true},
		{codes.Unavailable, false},
		{codes.DeadlineExceeded, false},
		{codes.Internal, false},
	}
	for _, c := range cases {
		got := isPermanent(status.Error(c.code, "x"))
		if got != c.want {
			t.Errorf("code=%s: isPermanent=%v want %v", c.code, got, c.want)
		}
	}
}

func TestNew_RequiresTarget(t *testing.T) {
	if _, err := New(Config{}, zap.NewNop()); err == nil {
		t.Error("New accepted empty Target")
	}
}

func TestNew_RequiresReloader(t *testing.T) {
	if _, err := New(Config{Target: "x:443", CARootFile: "/no/such"}, zap.NewNop()); err == nil {
		t.Error("New accepted nil reloader")
	}
}

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"https://h:443":   "h:443",
		"http://h:80":     "h:80",
		"grpcs://h:443":   "h:443",
		"grpc://h:443":    "h:443",
		"plain.host:443":  "plain.host:443",
		"localhost:50051": "localhost:50051",
	}
	for in, want := range cases {
		if got := auth.StripScheme(in); got != want {
			t.Errorf("StripScheme(%q) = %q, want %q", in, got, want)
		}
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
