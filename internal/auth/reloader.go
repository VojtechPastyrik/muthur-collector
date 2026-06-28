package auth

import (
	"crypto/tls"
	"errors"
	"os"
	"sync/atomic"
	"time"
)

// ClientReloader hot-reloads the collector's mTLS keypair from disk when the
// cert file's mtime advances. The renewal CronJob writes new files to the
// same paths; the next outbound TLS handshake observes the change and uses
// the rotated cert without restarting the process.
//
// Mirrors the server-side reloader on the brain. Keeps the implementation
// dependency-free (no fsnotify) because cert renewals happen weekly, so a
// per-handshake stat is cheap and avoids dragging in another module.
type ClientReloader struct {
	certFile string
	keyFile  string
	cached   atomic.Pointer[clientCertState]
}

type clientCertState struct {
	cert  tls.Certificate
	mtime time.Time
}

// NewClientReloader preloads the keypair so the caller fails fast on
// startup if the Secret hasn't been provisioned yet. Subsequent reloads
// happen lazily on each TLS handshake.
func NewClientReloader(certFile, keyFile string) (*ClientReloader, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("auth: cert and key paths are required")
	}
	r := &ClientReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetClientCertificate is the tls.Config.GetClientCertificate callback. The
// CertificateRequestInfo is unused — the collector talks to exactly one
// brain that always accepts the same cert.
func (r *ClientReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	info, err := os.Stat(r.certFile)
	if err != nil {
		// Preserve the cached cert across transient Stat failures so a single
		// missed file during cert-manager's swap does not break the listener.
		if cached := r.cached.Load(); cached != nil {
			return &cached.cert, nil
		}
		return nil, err
	}
	if cached := r.cached.Load(); cached != nil && !info.ModTime().After(cached.mtime) {
		return &cached.cert, nil
	}
	cert, err := r.load()
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (r *ClientReloader) load() (*tls.Certificate, error) {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Half-written file during rotation — keep serving the cached cert
		// rather than failing.
		if cached := r.cached.Load(); cached != nil {
			return &cached.cert, nil
		}
		return nil, err
	}
	r.cached.Store(&clientCertState{cert: cert, mtime: info.ModTime()})
	return &cert, nil
}

// Current returns the cached cert without performing a reload. Useful for
// callers that need a tls.Certificate value at a specific moment (e.g.
// renewal flow that builds its own one-off TLS dialer).
func (r *ClientReloader) Current() tls.Certificate {
	if cached := r.cached.Load(); cached != nil {
		return cached.cert
	}
	return tls.Certificate{}
}
