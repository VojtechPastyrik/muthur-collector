package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// BrainClient talks to the brain's gRPC Brain.BootstrapCert / Brain.SignCSR
// RPCs. It does not hold a long-lived ClientConn because both flows are
// one-shot subcommands (init container + CronJob); a fresh dial per call
// keeps the surface small and avoids surfacing connection lifecycle to the
// caller.
type BrainClient struct {
	target string
	caPool *x509.CertPool
}

// NewBrainClient returns a client that trusts the supplied vendor root CA
// when verifying the brain. caRootFile MUST be a PEM bundle containing the
// brain's trust root — this is what cert-manager wrote into the collector's
// chart as ca.crt at install time (preseeded with the chart) or from a
// previous successful bootstrap.
//
// brainTarget accepts either host:port or a URL (https://host:port); the
// scheme is stripped.
func NewBrainClient(brainTarget, caRootFile string) (*BrainClient, error) {
	pem, err := os.ReadFile(caRootFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("auth: CA bundle has no usable PEM certificates")
	}
	return &BrainClient{target: StripScheme(brainTarget), caPool: pool}, nil
}

// Bootstrap exchanges a one-time token + CSR for the collector's first leaf
// cert. The dial deliberately presents NO client cert: the bootstrap path
// authenticates by hashed token. The brain accepts cert-less handshakes for
// BootstrapCert (TLS ClientAuth=VerifyClientCertIfGiven).
//
// The returned certificate and CA bundle are PEM-encoded and ready to be
// passed to WriteMaterial.
func (c *BrainClient) Bootstrap(ctx context.Context, clusterID, token string, csrPEM []byte) (cert, ca []byte, err error) {
	if clusterID == "" || token == "" || len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: clusterID, token, and CSR are required")
	}

	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    c.caPool,
	})
	conn, err := grpc.NewClient(c.target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap dial: %w", err)
	}
	defer conn.Close()

	rpcCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rpcCtx = stampReplay(rpcCtx)

	resp, err := pb.NewBrainClient(conn).BootstrapCert(rpcCtx, &pb.BootstrapRequest{
		ClusterId:      clusterID,
		BootstrapToken: token,
		Csr:            string(csrPEM),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap call: %w", err)
	}
	if resp.GetCertificate() == "" {
		return nil, nil, errors.New("brain returned empty certificate")
	}
	return []byte(resp.GetCertificate()), []byte(resp.GetCa()), nil
}

// Renew exchanges a CSR for a fresh leaf using the collector's existing
// client cert. The CSR carries a new public key; the brain re-uses the
// identity from the verified peer cert.
func (c *BrainClient) Renew(ctx context.Context, clientCert tls.Certificate, csrPEM []byte) (cert, ca []byte, err error) {
	if len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: CSR required")
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      c.caPool,
		Certificates: []tls.Certificate{clientCert},
	})
	conn, err := grpc.NewClient(c.target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("renew dial: %w", err)
	}
	defer conn.Close()

	rpcCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rpcCtx = stampReplay(rpcCtx)

	resp, err := pb.NewBrainClient(conn).SignCSR(rpcCtx, &pb.SignCSRRequest{Csr: string(csrPEM)})
	if err != nil {
		return nil, nil, fmt.Errorf("renew call: %w", err)
	}
	if resp.GetCertificate() == "" {
		return nil, nil, errors.New("brain returned empty certificate")
	}
	return []byte(resp.GetCertificate()), []byte(resp.GetCa()), nil
}

// stampReplay attaches the freshness timestamp + nonce metadata to the
// outgoing gRPC context. Both Bootstrap and Renew use it so the call shape
// stays uniform; BootstrapCert ignores the metadata server-side, SignCSR
// requires it.
func stampReplay(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		MetaTimestamp, strconv.FormatInt(time.Now().Unix(), 10),
		MetaNonce, FreshNonce(),
	)
}

