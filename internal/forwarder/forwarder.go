package forwarder

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	"github.com/VojtechPastyrik/muthur-collector/internal/metrics"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// Forwarder ships marshalled AlertPayloads to the brain over mTLS. The client
// cert is sourced through ClientReloader so cert-manager / the renew CronJob
// can rotate the keypair without restarting the collector. The vendor root CA
// authenticates the brain.
type Forwarder struct {
	url    string
	client *http.Client
	logger *zap.Logger
}

// Config bundles the inputs Forwarder needs to wire its TLS transport.
type Config struct {
	URL          string
	CARootFile   string
	Reloader     *auth.ClientReloader
	Timeout      time.Duration
}

// New constructs a Forwarder. Returns an error if the root CA file cannot be
// parsed — the collector cannot safely talk to the brain without a verified
// trust anchor, so failing fast at startup is preferable to dialling without
// verification.
func New(cfg Config, logger *zap.Logger) (*Forwarder, error) {
	if cfg.URL == "" {
		return nil, errors.New("forwarder: URL is required")
	}
	if cfg.Reloader == nil {
		return nil, errors.New("forwarder: ClientReloader is required")
	}
	pool, err := loadCAPool(cfg.CARootFile)
	if err != nil {
		return nil, fmt.Errorf("forwarder: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Forwarder{
		url: cfg.URL,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:           tls.VersionTLS12,
					RootCAs:              pool,
					GetClientCertificate: cfg.Reloader.GetClientCertificate,
				},
			},
		},
		logger: logger,
	}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("CA root file path is required")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("CA root file has no usable PEM certificates")
	}
	return pool, nil
}

// Forward marshals the payload and POSTs it to the brain's /ingest. Retries
// transient (5xx / network) errors with exponential backoff up to 3 attempts.
// 4xx responses are treated as permanent — they typically mean the brain
// rejected the cert identity binding, which a retry will not fix.
func (f *Forwarder) Forward(ctx context.Context, payload *pb.AlertPayload) error {
	start := time.Now()
	defer func() { metrics.ForwardDuration.Observe(time.Since(start).Seconds()) }()

	data, err := proto.Marshal(payload)
	if err != nil {
		metrics.Forwards.WithLabelValues("error").Inc()
		return fmt.Errorf("marshal protobuf: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			metrics.ForwardRetries.Inc()
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			f.logger.Warn("retrying forward",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			// Honour cancellation during backoff so a shutdown or deadline
			// doesn't get stuck sleeping on a dead central.
			select {
			case <-ctx.Done():
				metrics.Forwards.WithLabelValues("error").Inc()
				return fmt.Errorf("forward cancelled during backoff: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		err := f.send(ctx, data)
		if err == nil {
			metrics.Forwards.WithLabelValues("ok").Inc()
			return nil
		}
		lastErr = err
		f.logger.Error("forward failed",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
		// 4xx is permanent: the brain rejected us by identity, replay, or
		// proto. Retrying won't change the answer.
		if isPermanent(err) {
			break
		}
	}

	metrics.Forwards.WithLabelValues("error").Inc()
	return fmt.Errorf("forward failed: %w", lastErr)
}

// permanentError is the sentinel that isPermanent detects to short-circuit
// retries on the brain's 4xx responses.
type permanentError struct{ inner error }

func (p *permanentError) Error() string { return p.inner.Error() }
func (p *permanentError) Unwrap() error { return p.inner }

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

func (f *Forwarder) send(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Muthur-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Muthur-Nonce", freshNonce())

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return &permanentError{inner: fmt.Errorf("client error: %d (not retryable)", resp.StatusCode)}
	}
	return nil
}

// freshNonce returns a 32-hex-char random nonce. crypto/rand would be the
// ideal source but math/rand/v2 already seeds from crypto/rand and is plenty
// for replay protection where uniqueness — not unpredictability — is the
// load-bearing property.
func freshNonce() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.Uint32())
	}
	return hex.EncodeToString(b[:])
}
