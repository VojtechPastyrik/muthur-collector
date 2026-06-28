package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

type fakeBrainServer struct {
	pb.UnimplementedBrainServer

	gotClusterID string
	gotToken     string
	gotCSR       string
	gotTS        string
	gotNonce     string
	gotPeerCert  bool
	bootstrapErr error
	renewErr     error
}

func (f *fakeBrainServer) BootstrapCert(ctx context.Context, req *pb.BootstrapRequest) (*pb.BootstrapResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(MetaTimestamp); len(v) > 0 {
			f.gotTS = v[0]
		}
		if v := md.Get(MetaNonce); len(v) > 0 {
			f.gotNonce = v[0]
		}
	}
	f.gotClusterID = req.GetClusterId()
	f.gotToken = req.GetBootstrapToken()
	f.gotCSR = req.GetCsr()
	if f.bootstrapErr != nil {
		return nil, f.bootstrapErr
	}
	return &pb.BootstrapResponse{Certificate: "CERT", Ca: "CA"}, nil
}

func (f *fakeBrainServer) SignCSR(ctx context.Context, req *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	if p, ok := peer.FromContext(ctx); ok && p != nil {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			f.gotPeerCert = true
		}
	}
	f.gotCSR = req.GetCsr()
	if f.renewErr != nil {
		return nil, f.renewErr
	}
	return &pb.SignCSRResponse{Certificate: "RENEWED", Ca: "CA"}, nil
}

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

func TestBootstrap_SendsExpectedFields(t *testing.T) {
	target, brain, caPath := spinUpFakeBrain(t, nil)

	client, err := NewBrainClient(target, caPath)
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
	if brain.gotClusterID != "cluster-a" || brain.gotToken != "tok" || brain.gotCSR == "" {
		t.Errorf("brain received unexpected request: cluster=%q token=%q csrEmpty=%v",
			brain.gotClusterID, brain.gotToken, brain.gotCSR == "")
	}
	if brain.gotTS == "" || brain.gotNonce == "" {
		t.Errorf("missing replay metadata: ts=%q nonce=%q", brain.gotTS, brain.gotNonce)
	}
	if string(cert) != "CERT" || string(ca) != "CA" {
		t.Errorf("response = cert=%q ca=%q, want CERT/CA", cert, ca)
	}
}

func TestBootstrap_PropagatesBrainErrors(t *testing.T) {
	brain := &fakeBrainServer{bootstrapErr: status.Error(codes.Unauthenticated, "no")}
	target, _, caPath := spinUpFakeBrain(t, brain)

	client, _ := NewBrainClient(target, caPath)
	csrPEM, _, _ := GenerateCSR("acme", "cluster-a")

	_, _, err := client.Bootstrap(context.Background(), "cluster-a", "tok", csrPEM)
	if err == nil {
		t.Fatal("Bootstrap accepted Unauthenticated from brain")
	}
}

func TestRenew_SendsClientCert(t *testing.T) {
	target, brain, caPath, clientLeaf := spinUpMTLSFakeBrain(t)

	client, err := NewBrainClient(target, caPath)
	if err != nil {
		t.Fatalf("NewBrainClient: %v", err)
	}
	csrPEM, _, _ := GenerateCSR("acme", "cluster-a")
	cert, _, err := client.Renew(context.Background(), clientLeaf, csrPEM)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !brain.gotPeerCert {
		t.Error("server did not observe a client cert on Renew")
	}
	if string(cert) != "RENEWED" {
		t.Errorf("cert = %q, want RENEWED", cert)
	}
}

func TestFreshNonce_Length(t *testing.T) {
	n := FreshNonce()
	if len(n) != 32 {
		t.Errorf("len = %d, want 32 hex chars", len(n))
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
		if got := StripScheme(in); got != want {
			t.Errorf("StripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- helpers ---

// spinUpFakeBrain runs an in-process TLS gRPC server. ClientAuth is
// VerifyClientCertIfGiven so Bootstrap (no cert) and Renew (cert) both
// reach the handler. If brain is nil a fresh empty one is allocated.
func spinUpFakeBrain(t *testing.T, brain *fakeBrainServer) (target string, b *fakeBrainServer, caPath string) {
	t.Helper()
	if brain == nil {
		brain = &fakeBrainServer{}
	}
	caCert, caKey, caPEM := makeCA(t)
	serverCert := makeServerCert(t, caCert, caKey)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	dir := t.TempDir()
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	})))
	pb.RegisterBrainServer(srv, brain)
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Stop() })

	return lis.Addr().String(), brain, caPath
}

// spinUpMTLSFakeBrain is spinUpFakeBrain plus a client leaf cert ready for
// the Renew call.
func spinUpMTLSFakeBrain(t *testing.T) (target string, b *fakeBrainServer, caPath string, clientCert tls.Certificate) {
	t.Helper()
	caCert, caKey, caPEM := makeCA(t)
	serverCert := makeServerCert(t, caCert, caKey)
	clientCert = makeLeaf(t, caCert, caKey, "cluster-a")

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	dir := t.TempDir()
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b = &fakeBrainServer{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	})))
	pb.RegisterBrainServer(srv, b)
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Stop() })

	return lis.Addr().String(), b, caPath, clientCert
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
