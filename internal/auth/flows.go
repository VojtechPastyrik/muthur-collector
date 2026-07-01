package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Persister abstracts cert material storage. The production binary uses
// SecretStore (writes a Kubernetes Secret via the API); tests use FilePersister
// (writes to a temp directory).
type Persister interface {
	Exists(ctx context.Context) (bool, error)
	Read(ctx context.Context) (cert, key, ca []byte, err error)
	Write(ctx context.Context, cert, key, ca []byte) error
}

// FilePersister is the on-disk implementation backed by CertMaterial. Used by
// tests and any non-K8s runtime; production wires SecretStore instead.
type FilePersister struct{ Material CertMaterial }

func (f FilePersister) Exists(_ context.Context) (bool, error) {
	return f.Material.Exists(), nil
}
func (f FilePersister) Read(_ context.Context) (cert, key, ca []byte, err error) {
	cert, err = os.ReadFile(f.Material.CertFile)
	if err != nil {
		return
	}
	key, err = os.ReadFile(f.Material.KeyFile)
	if err != nil {
		return
	}
	if data, e := os.ReadFile(f.Material.CAFile); e == nil {
		ca = data
	}
	return
}
func (f FilePersister) Write(_ context.Context, cert, key, ca []byte) error {
	return WriteMaterial(f.Material, cert, key, ca)
}

// BootstrapFlow runs the init-container side of the enrolment dance:
//
//  1. If a cert is already persisted, return immediately. Lets the init
//     container restart safely without re-burning bootstrap tokens.
//  2. Otherwise, read the one-time bootstrap token, generate a fresh keypair,
//     send a CSR + token to /bootstrap-cert, and persist the returned leaf
//     and CA so the main container can mount them.
type BootstrapFlow struct {
	ClusterID          string
	TenantID           string
	BrainURL           string
	BootstrapTokenFile string
	VendorCAFile       string // pre-installed CA bundle (chart-provided)
	Persister          Persister
	Logger             *zap.Logger
}

func (b BootstrapFlow) Run(ctx context.Context) error {
	if b.Persister == nil {
		return errors.New("bootstrap: Persister is required")
	}
	if b.ClusterID == "" || b.BrainURL == "" {
		return errors.New("bootstrap: ClusterID and BrainURL are required")
	}

	already, err := b.Persister.Exists(ctx)
	if err != nil {
		return fmt.Errorf("check existing cert: %w", err)
	}
	if already {
		b.Logger.Info("cert already provisioned — skipping bootstrap",
			zap.String("cluster_id", b.ClusterID),
		)
		return nil
	}

	tokenBytes, err := os.ReadFile(b.BootstrapTokenFile)
	if err != nil {
		return fmt.Errorf("read bootstrap token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return errors.New("bootstrap: token file is empty")
	}

	csrPEM, keyPEM, err := GenerateCSR(b.TenantID, b.ClusterID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	client, err := NewBrainClient(b.BrainURL, b.VendorCAFile)
	if err != nil {
		return fmt.Errorf("brain client: %w", err)
	}
	certPEM, caPEM, err := client.Bootstrap(ctx, b.ClusterID, token, csrPEM)
	if err != nil {
		return fmt.Errorf("bootstrap call: %w", err)
	}
	if err := b.Persister.Write(ctx, certPEM, keyPEM, caPEM); err != nil {
		return fmt.Errorf("persist material: %w", err)
	}

	b.Logger.Info("bootstrap complete — cert installed",
		zap.String("cluster_id", b.ClusterID),
	)
	return nil
}

// RenewFlow runs the CronJob side of cert rotation:
//
//  1. Read the current cert + key + CA from the Persister.
//  2. Generate a fresh keypair + CSR.
//  3. POST to /sign-csr over mTLS using the OLD cert.
//  4. Persist the returned leaf + new key + (optional) CA.
//
// The running collector picks up the rotated cert at the next outbound TLS
// handshake via ClientReloader.
type RenewFlow struct {
	ClusterID    string
	TenantID     string
	BrainURL     string
	VendorCAFile string // pre-installed bundle; falls back to ca from Persister
	Persister    Persister
	Logger       *zap.Logger

	// RenewBefore is the runway threshold: if the current cert's remaining
	// validity is greater than this, Run exits early without contacting the
	// brain. Zero disables the check (rotate on every invocation — legacy
	// behaviour). Typical value: 48h with a 168h cert.
	RenewBefore time.Duration

	// Now is injected for tests. Nil = time.Now.
	Now func() time.Time
}

func (r RenewFlow) Run(ctx context.Context) error {
	if r.Persister == nil {
		return errors.New("renew: Persister is required")
	}
	if r.ClusterID == "" || r.BrainURL == "" {
		return errors.New("renew: ClusterID and BrainURL are required")
	}

	exists, err := r.Persister.Exists(ctx)
	if err != nil {
		return fmt.Errorf("check existing cert: %w", err)
	}
	if !exists {
		return errors.New("renew: no existing cert; bootstrap must run first")
	}

	certPEM, keyPEM, caPEM, err := r.Persister.Read(ctx)
	if err != nil {
		return fmt.Errorf("read current cert: %w", err)
	}

	if r.RenewBefore > 0 {
		now := time.Now
		if r.Now != nil {
			now = r.Now
		}
		remaining, parseErr := certRemaining(certPEM, now())
		switch {
		case parseErr != nil:
			// Malformed cert — fall through to renewal. Fresh cert will
			// overwrite the bad one; failing closed here would strand a
			// collector whose Secret got corrupted.
			r.Logger.Warn("renew: could not parse current cert; proceeding with renewal",
				zap.Error(parseErr),
			)
		case remaining > r.RenewBefore:
			r.Logger.Info("renew: cert still fresh, skipping",
				zap.Duration("remaining", remaining),
				zap.Duration("renew_before", r.RenewBefore),
				zap.String("cluster_id", r.ClusterID),
			)
			return nil
		}
	}

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse current keypair: %w", err)
	}

	csrPEM, newKeyPEM, err := GenerateCSR(r.TenantID, r.ClusterID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	caFile := r.VendorCAFile
	if caFile == "" {
		// Fall back to writing the current CA to a temp file so BrainClient
		// can read it from a path. Renewal-as-a-CronJob can't always rely on
		// the vendor CA being mounted separately, so this keeps the flow
		// self-contained.
		tmp, err := os.CreateTemp("", "muthur-ca-*.pem")
		if err != nil {
			return fmt.Errorf("temp CA file: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(caPEM); err != nil {
			tmp.Close()
			return fmt.Errorf("write temp CA: %w", err)
		}
		tmp.Close()
		caFile = tmp.Name()
	}

	client, err := NewBrainClient(r.BrainURL, caFile)
	if err != nil {
		return fmt.Errorf("brain client: %w", err)
	}
	newCertPEM, newCAPEM, err := client.Renew(ctx, clientCert, csrPEM)
	if err != nil {
		return fmt.Errorf("renew call: %w", err)
	}
	if err := r.Persister.Write(ctx, newCertPEM, newKeyPEM, newCAPEM); err != nil {
		return fmt.Errorf("persist material: %w", err)
	}

	r.Logger.Info("renewal complete — cert rotated",
		zap.String("cluster_id", r.ClusterID),
	)
	return nil
}

// certRemaining returns how much validity the leaf in certPEM has left at
// the given moment. The first PEM block is treated as the leaf.
func certRemaining(certPEM []byte, now time.Time) (time.Duration, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return 0, errors.New("no PEM block in cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("parse cert: %w", err)
	}
	return crt.NotAfter.Sub(now), nil
}
