package forwarder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	"github.com/VojtechPastyrik/muthur-collector/internal/metrics"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// Forwarder ships AlertPayloads to the brain over the gRPC Brain.Ingest RPC.
// The mTLS client cert is sourced through ClientReloader so cert-manager / the
// renew CronJob can rotate the keypair without restarting the collector. The
// vendor root CA authenticates the brain.
type Forwarder struct {
	conn   *grpc.ClientConn
	client pb.BrainClient
	logger *zap.Logger
}

// Config bundles the inputs Forwarder needs to wire its gRPC transport.
type Config struct {
	// Target is the brain's gRPC endpoint as host:port. URLs with a scheme
	// (https://, grpcs://) are accepted and the scheme is stripped.
	Target     string
	CARootFile string
	Reloader   *auth.ClientReloader
	Timeout    time.Duration
}

// New constructs a Forwarder. Returns an error if the root CA file cannot be
// parsed — the collector cannot safely talk to the brain without a verified
// trust anchor, so failing fast at startup is preferable to dialling without
// verification.
func New(cfg Config, logger *zap.Logger) (*Forwarder, error) {
	if cfg.Target == "" {
		return nil, errors.New("forwarder: Target is required")
	}
	if cfg.Reloader == nil {
		return nil, errors.New("forwarder: ClientReloader is required")
	}
	pool, err := loadCAPool(cfg.CARootFile)
	if err != nil {
		return nil, fmt.Errorf("forwarder: %w", err)
	}
	target := auth.StripScheme(cfg.Target)

	creds := credentials.NewTLS(&tls.Config{
		MinVersion:           tls.VersionTLS12,
		RootCAs:              pool,
		GetClientCertificate: cfg.Reloader.GetClientCertificate,
	})
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("forwarder: dial: %w", err)
	}
	return &Forwarder{
		conn:   conn,
		client: pb.NewBrainClient(conn),
		logger: logger,
	}, nil
}

// Close releases the underlying gRPC connection. Safe to call once at shutdown.
func (f *Forwarder) Close() error {
	if f.conn == nil {
		return nil
	}
	return f.conn.Close()
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

// Forward issues the gRPC Ingest call. Retries transient (Unavailable /
// DeadlineExceeded) failures with exponential backoff up to 3 attempts.
// InvalidArgument / Unauthenticated / PermissionDenied are treated as
// permanent — they typically mean the brain rejected the cert identity
// binding or replay metadata, which a retry will not fix.
func (f *Forwarder) Forward(ctx context.Context, payload *pb.AlertPayload) error {
	start := time.Now()
	defer func() { metrics.ForwardDuration.Observe(time.Since(start).Seconds()) }()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			metrics.ForwardRetries.Inc()
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			f.logger.Warn("retrying forward",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				metrics.Forwards.WithLabelValues("error").Inc()
				return fmt.Errorf("forward cancelled during backoff: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		err := f.send(ctx, payload)
		if err == nil {
			metrics.Forwards.WithLabelValues("ok").Inc()
			return nil
		}
		lastErr = err
		f.logger.Error("forward failed",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
		if isPermanent(err) {
			break
		}
	}

	metrics.Forwards.WithLabelValues("error").Inc()
	return fmt.Errorf("forward failed: %w", lastErr)
}

func (f *Forwarder) send(ctx context.Context, payload *pb.AlertPayload) error {
	ctx = metadata.AppendToOutgoingContext(ctx,
		auth.MetaTimestamp, strconv.FormatInt(time.Now().Unix(), 10),
		auth.MetaNonce, auth.FreshNonce(),
	)
	if _, err := f.client.Ingest(ctx, payload); err != nil {
		return err
	}
	return nil
}

// isPermanent reports whether the gRPC error should short-circuit retries.
// Server-side rejections (auth, replay, identity binding, malformed payload)
// are all permanent — a retry without operator intervention will not change
// the answer.
func isPermanent(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.Unauthenticated, codes.PermissionDenied,
		codes.FailedPrecondition, codes.NotFound, codes.Unimplemented:
		return true
	}
	return false
}

