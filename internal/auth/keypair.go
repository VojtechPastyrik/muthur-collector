// Package auth handles the collector's mTLS material: generating keypairs
// and CSRs, persisting them to a mounted Secret, and exchanging CSRs for
// signed leaf certificates via the brain's bootstrap and renewal endpoints.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// CertMaterial is the trio of files that lives in the collector's TLS Secret:
// the leaf cert chained back to the vendor root, the matching private key, and
// the vendor root CA bundle the collector uses to verify the brain. All three
// MUST live in the same directory so cert-manager-style atomic Secret rotations
// move them as a unit.
type CertMaterial struct {
	Dir      string
	CertFile string
	KeyFile  string
	CAFile   string
}

// NewMaterial returns CertMaterial with the canonical file names this package
// reads and writes (tls.crt, tls.key, ca.crt — matching the cert-manager
// Secret layout).
func NewMaterial(dir string) CertMaterial {
	return CertMaterial{
		Dir:      dir,
		CertFile: filepath.Join(dir, "tls.crt"),
		KeyFile:  filepath.Join(dir, "tls.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
}

// Exists reports whether the cert+key pair is already on disk and parseable.
// Used by the bootstrap entry point to skip enrolment idempotently when the
// init container restarts.
func (m CertMaterial) Exists() bool {
	if _, err := os.Stat(m.CertFile); err != nil {
		return false
	}
	if _, err := os.Stat(m.KeyFile); err != nil {
		return false
	}
	return true
}

// GenerateCSR creates a P-256 ECDSA keypair and a corresponding CSR for the
// supplied tenant/cluster identity. The CSR's CommonName mirrors the
// authoritative cluster id; the SPIFFE URI SAN is the authoritative form the
// brain reads back. The brain ignores both — but emitting them here makes
// human inspection of the CSR (kubectl describe certificaterequest, etc.)
// match what the brain ends up putting in the leaf, which avoids confusion
// during postmortems.
//
// The private key is returned PEM-encoded (PKCS#8) so callers can write it to
// the Secret without re-marshalling. The CSR is returned PEM-encoded so it can
// be embedded directly in the JSON payload to /bootstrap-cert and /sign-csr.
func GenerateCSR(tenantID, clusterID string) (csrPEM, keyPEM []byte, err error) {
	if clusterID == "" {
		return nil, nil, errors.New("auth: clusterID required for CSR")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: clusterID},
	}
	if tenantID != "" {
		u, perr := url.Parse("spiffe://muthur/" + tenantID + "/" + clusterID)
		if perr == nil {
			tpl.URIs = []*url.URL{u}
		}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

// WriteMaterial atomically persists cert, key, and CA bytes into the Secret
// directory, replacing any previous contents. Writes go through a temp file
// + rename so a crash mid-write can't leave a half-rotated state that would
// trip the mTLS handshake.
//
// caPEM is permitted to be empty for renewals where the CA hasn't changed.
func WriteMaterial(m CertMaterial, certPEM, keyPEM, caPEM []byte) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("auth: cert and key are required")
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", m.Dir, err)
	}
	if err := writeAtomic(m.CertFile, certPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(m.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if len(caPEM) > 0 {
		if err := writeAtomic(m.CAFile, caPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
