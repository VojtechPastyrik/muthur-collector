package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	"github.com/VojtechPastyrik/muthur-collector/internal/config"
	"github.com/VojtechPastyrik/muthur-collector/internal/forwarder"
	"github.com/VojtechPastyrik/muthur-collector/internal/k8s"
	"github.com/VojtechPastyrik/muthur-collector/internal/loki"
	"github.com/VojtechPastyrik/muthur-collector/internal/pipeline"
	"github.com/VojtechPastyrik/muthur-collector/internal/prometheus"
	"github.com/VojtechPastyrik/muthur-collector/internal/redact"
	"github.com/VojtechPastyrik/muthur-collector/internal/resolver"
	"github.com/VojtechPastyrik/muthur-collector/internal/webhook"
)

func main() {
	if err := dispatch(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// dispatch reads the operating mode from os.Args[1] (or MODE env) and routes
// to the matching entry point. The default ("serve") runs the main forwarder
// loop. "bootstrap" and "renew" are one-shot subcommands the chart wires into
// an initContainer and a CronJob respectively.
//
// A single binary keeps the chart simple — one image, three commands.
func dispatch() error {
	mode := "serve"
	if len(os.Args) > 1 && os.Args[1] != "" {
		mode = os.Args[1]
	} else if v := os.Getenv("MODE"); v != "" {
		mode = v
	}

	switch mode {
	case "serve":
		return runServer()
	case "bootstrap":
		return runBootstrap()
	case "renew":
		return runRenew()
	default:
		return fmt.Errorf("unknown mode %q (want serve|bootstrap|renew)", mode)
	}
}

func runBootstrap() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	persister, err := newPersister(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return auth.BootstrapFlow{
		ClusterID:          cfg.ClusterID,
		TenantID:           cfg.TenantID,
		BrainURL:           cfg.CentralAgentURL,
		BootstrapTokenFile: cfg.BootstrapTokenFile,
		VendorCAFile:       cfg.VendorCAFile,
		Persister:          persister,
		Logger:             logger,
	}.Run(ctx)
}

func runRenew() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	persister, err := newPersister(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return auth.RenewFlow{
		ClusterID:    cfg.ClusterID,
		TenantID:     cfg.TenantID,
		BrainURL:     cfg.CentralAgentURL,
		VendorCAFile: cfg.VendorCAFile,
		Persister:    persister,
		Logger:       logger,
		RenewBefore:  cfg.RenewBefore,
	}.Run(ctx)
}

// newPersister picks the right cert-storage backend. In production
// (POD_NAMESPACE + CERT_SECRET_NAME set) we write to a Kubernetes Secret;
// the main container then mounts that Secret normally. For local dev or
// integration tests, the file-backed persister writes to CERT_DIR.
func newPersister(cfg *config.Config) (auth.Persister, error) {
	if cfg.Namespace != "" && cfg.CertSecretName != "" {
		return auth.NewSecretStoreInCluster(cfg.Namespace, cfg.CertSecretName)
	}
	return auth.FilePersister{Material: auth.NewMaterial(cfg.CertDir)}, nil
}

func runServer() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	// K8s client (optional — may fail outside cluster)
	k8sClient, err := k8s.NewClient(logger)
	if err != nil {
		logger.Warn("K8s client unavailable, running without pod metadata", zap.Error(err))
		k8sClient = nil
	}

	// Components — loki is optional (clusters without a logging stack can
	// disable it via LOKI_ENABLED=false and the collector will forward
	// alerts without log excerpts instead of spamming warnings).
	var lokiClient *loki.Client
	if cfg.LokiEnabled {
		lokiClient = loki.NewClient(cfg.LokiURL, cfg.LokiLookbackMinutes, cfg.LokiMaxLogLines, logger)
	} else {
		logger.Info("Loki integration disabled — alerts will be forwarded without log excerpts")
	}
	promClient := prometheus.NewClient(cfg.PrometheusURL, cfg.PrometheusLookbackMin, cfg.PrometheusEnabled, logger)
	redactor := redact.New(cfg.RedactExtraPatterns, cfg.RedactLogStats, cfg.RedactMaxLineBytes, cfg.RedactMaxTotalBytes, cfg.RedactMaxStringBytes, logger)

	// mTLS keypair is hot-reloaded from the mounted Secret. The renew CronJob
	// writes a fresh cert before expiry; the reloader picks it up on the next
	// outbound handshake, no restart required.
	reloader, err := auth.NewClientReloader(cfg.CertFile(), cfg.KeyFile())
	if err != nil {
		return fmt.Errorf("load client cert (bootstrap not run?): %w", err)
	}

	fwd, err := forwarder.New(forwarder.Config{
		Target:     cfg.CentralAgentURL,
		CARootFile: cfg.CACertFile(),
		Reloader:   reloader,
	}, logger)
	if err != nil {
		return fmt.Errorf("init forwarder: %w", err)
	}
	defer fwd.Close()
	res := resolver.New(k8sClient, logger)
	pipe := pipeline.New(cfg.ClusterID, cfg.GrafanaBaseURL, res, lokiClient, promClient, k8sClient, redactor, fwd, logger)

	// HTTP server
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	handler := webhook.NewHandler(pipe, cfg.WebhookMaxConcurrent, logger)
	r.Post("/webhook", handler.ServeHTTP)

	r.Handle("/metrics", promhttp.Handler())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Info("starting muthur-collector (mTLS)",
		zap.String("addr", addr),
		zap.String("cluster_id", cfg.ClusterID),
	)
	return http.ListenAndServe(addr, r)
}

func newLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build()
}
