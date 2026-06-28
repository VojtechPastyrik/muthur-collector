package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// BootstrapFlow runs the init-container side of the enrolment dance:
//
//  1. If a valid cert is already on disk, return immediately. Lets the init
//     container restart safely without re-burning bootstrap tokens.
//  2. Otherwise, read the one-time bootstrap token, generate a fresh keypair,
//     send a CSR + token to /bootstrap-cert, write the returned leaf + CA
//     into the mounted Secret directory.
//
// Returns nil on success or when the cert was already provisioned.
type BootstrapFlow struct {
	ClusterID         string
	TenantID          string
	BrainURL          string
	BootstrapTokenFile string
	CACertFile        string // pre-installed CA bundle (chart-provided)
	Material          CertMaterial
	Logger            *zap.Logger
}

func (b BootstrapFlow) Run(ctx context.Context) error {
	if b.Material.Exists() {
		b.Logger.Info("cert material already present — skipping bootstrap",
			zap.String("cert_dir", b.Material.Dir),
		)
		return nil
	}
	if b.ClusterID == "" || b.BrainURL == "" {
		return errors.New("bootstrap: ClusterID and BrainURL are required")
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

	client, err := NewBrainClient(b.BrainURL, b.CACertFile)
	if err != nil {
		return fmt.Errorf("brain client: %w", err)
	}
	certPEM, caPEM, err := client.Bootstrap(ctx, b.ClusterID, token, csrPEM)
	if err != nil {
		return fmt.Errorf("bootstrap call: %w", err)
	}
	if err := WriteMaterial(b.Material, certPEM, keyPEM, caPEM); err != nil {
		return fmt.Errorf("write material: %w", err)
	}

	b.Logger.Info("bootstrap complete — cert installed",
		zap.String("cert_dir", b.Material.Dir),
		zap.String("cluster_id", b.ClusterID),
	)
	return nil
}

// RenewFlow runs the CronJob side of cert rotation:
//
//  1. Load the current keypair from disk (no shortcut — we MUST present the
//     existing cert to /sign-csr).
//  2. Generate a fresh keypair + CSR.
//  3. POST to /sign-csr over mTLS.
//  4. Write the returned leaf + CA atomically.
//
// The running collector picks up the rotated cert at the next outbound TLS
// handshake via ClientReloader.
type RenewFlow struct {
	ClusterID  string
	TenantID   string
	BrainURL   string
	Material   CertMaterial
	Logger     *zap.Logger
}

func (r RenewFlow) Run(ctx context.Context) error {
	if r.ClusterID == "" || r.BrainURL == "" {
		return errors.New("renew: ClusterID and BrainURL are required")
	}
	if !r.Material.Exists() {
		return errors.New("renew: no existing cert; bootstrap must run first")
	}

	clientCert, err := tls.LoadX509KeyPair(r.Material.CertFile, r.Material.KeyFile)
	if err != nil {
		return fmt.Errorf("load current keypair: %w", err)
	}

	csrPEM, keyPEM, err := GenerateCSR(r.TenantID, r.ClusterID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	client, err := NewBrainClient(r.BrainURL, r.Material.CAFile)
	if err != nil {
		return fmt.Errorf("brain client: %w", err)
	}
	certPEM, caPEM, err := client.Renew(ctx, clientCert, csrPEM)
	if err != nil {
		return fmt.Errorf("renew call: %w", err)
	}
	// Allow caPEM to be empty: a renewal that doesn't ship a CA leaves the
	// existing ca.crt untouched (handled by WriteMaterial). We pass it through
	// either way to keep behaviour explicit.
	if err := WriteMaterial(r.Material, certPEM, keyPEM, caPEM); err != nil {
		return fmt.Errorf("write material: %w", err)
	}

	r.Logger.Info("renewal complete — cert rotated",
		zap.String("cert_dir", r.Material.Dir),
		zap.String("cluster_id", r.ClusterID),
	)
	return nil
}
