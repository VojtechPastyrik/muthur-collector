package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/VojtechPastyrik/muthur-collector/internal/auth"
	"github.com/VojtechPastyrik/muthur-collector/internal/config"
	"github.com/VojtechPastyrik/muthur-collector/internal/forwarder"
	"github.com/VojtechPastyrik/muthur-collector/internal/heartbeat"
	"github.com/VojtechPastyrik/muthur-collector/internal/k8s"
	"github.com/VojtechPastyrik/muthur-collector/internal/loki"
	"github.com/VojtechPastyrik/muthur-collector/internal/pipeline"
	"github.com/VojtechPastyrik/muthur-collector/internal/prometheus"
	"github.com/VojtechPastyrik/muthur-collector/internal/redact"
	"github.com/VojtechPastyrik/muthur-collector/internal/resolver"
	"github.com/VojtechPastyrik/muthur-collector/internal/victorialogs"
	"github.com/VojtechPastyrik/muthur-collector/internal/webhook"
)

// version is reported in heartbeats so the brain can show fleet version drift.
// Set from the chart (COLLECTOR_VERSION, wired to .Chart.AppVersion) rather
// than at build time, so one image can report the chart it was deployed by.
var version = "dev"

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
		Transport:          cfg.AuthMode,
		EdgeCAFile:         cfg.SignedEdgeCAFile,
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
		Transport:    cfg.AuthMode,
		EdgeCAFile:   cfg.SignedEdgeCAFile,
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

	// Log enrichment is optional (clusters without a logging stack set
	// LOKI_ENABLED=false and the collector forwards alerts without excerpts
	// instead of spamming warnings). The interface variable stays nil in that
	// case — assigning a typed nil pointer to it would produce a non-nil
	// interface and a panic on the first alert.
	var logFetcher pipeline.LogFetcher
	if cfg.LogsEnabled() {
		switch cfg.LogsBackend {
		case config.BackendVictoriaLogs:
			logFetcher = victorialogs.NewClient(victorialogs.Config{
				BaseURL:     cfg.VictoriaLogsURL,
				LookbackMin: cfg.VictoriaLogsLookbackMinutes,
				MaxLines:    cfg.VictoriaLogsMaxLogLines,
				ExtraFilter: cfg.LogsExtraSelector,
				AccountID:   cfg.VictoriaLogsAccountID,
				ProjectID:   cfg.VictoriaLogsProjectID,
			}, logger)
		default:
			logFetcher = loki.NewClient(cfg.LokiURL, cfg.LokiLookbackMinutes, cfg.LokiMaxLogLines, cfg.LogsExtraSelector, logger)
		}
		logger.Info("log enrichment enabled", zap.String("backend", cfg.LogsBackend))
	} else {
		logger.Info("log enrichment disabled — alerts will be forwarded without log excerpts")
	}

	var metricFetcher pipeline.MetricFetcher
	switch cfg.MetricsBackend {
	case config.BackendVictoriaMetrics:
		metricFetcher = prometheus.NewVictoriaMetrics(prometheus.Config{
			BaseURL:       cfg.VictoriaMetricsURL,
			LookbackMin:   cfg.VictoriaMetricsLookbackMinutes,
			Enabled:       cfg.PrometheusEnabled,
			ExtraSelector: cfg.MetricsExtraSelector,
			AccountID:     cfg.VictoriaMetricsAccountID,
			ProjectID:     cfg.VictoriaMetricsProjectID,
		}, logger)
	default:
		metricFetcher = prometheus.NewClient(cfg.PrometheusURL, cfg.PrometheusLookbackMin, cfg.PrometheusEnabled, logger)
	}
	logger.Info("metric enrichment configured", zap.String("backend", cfg.MetricsBackend))
	redactor := redact.New(cfg.RedactExtraPatterns, cfg.RedactLogStats, cfg.RedactMaxLineBytes, cfg.RedactMaxTotalBytes, cfg.RedactMaxStringBytes, logger)

	// mTLS keypair is hot-reloaded from the mounted Secret. The renew CronJob
	// writes a fresh cert before expiry; the reloader picks it up on the next
	// outbound handshake, no restart required.
	reloader, err := auth.NewClientReloader(cfg.CertFile(), cfg.KeyFile())
	if err != nil {
		return fmt.Errorf("load client cert (bootstrap not run?): %w", err)
	}

	var fwd *forwarder.Forwarder
	if cfg.AuthMode == config.AuthModeSigned {
		fwd, err = forwarder.NewSigned(forwarder.SignedConfig{
			BaseURL:    cfg.CentralAgentURL,
			CARootFile: cfg.CACertFile(),
			EdgeCAFile: cfg.SignedEdgeCAFile,
			Reloader:   reloader,
		}, logger)
	} else {
		fwd, err = forwarder.New(forwarder.Config{
			Target:     cfg.CentralAgentURL,
			CARootFile: cfg.CACertFile(),
			Reloader:   reloader,
		}, logger)
	}
	if err != nil {
		return fmt.Errorf("init forwarder: %w", err)
	}
	defer fwd.Close()
	res := resolver.New(k8sClient, logger)
	pipe := pipeline.New(pipeline.Config{
		ClusterID:             cfg.ClusterID,
		GrafanaBaseURL:        cfg.GrafanaBaseURL,
		GrafanaLogsDatasource: cfg.GrafanaLogsDatasource,
		Resolver:              res,
		Logs:                  logFetcher,
		Metrics:               metricFetcher,
		K8s:                   k8sClient,
		Redactor:              redactor,
		Forwarder:             fwd,
	}, logger)

	// Liveness. Without this the brain cannot tell a quiet cluster from a dead
	// one: a collector that stops forwarding simply stops being heard from.
	// The Watchdog probe upgrades the heartbeat from "this process runs" to
	// "the whole alerting path runs". Always constructed; it simply reports
	// zero until an operator routes Watchdog here, which the brain reads as
	// "not configured" rather than as a broken pipeline.
	probe := heartbeat.NewProbe()

	beater := heartbeat.New(fwd, pipe, probe, heartbeat.Config{
		Enabled:   cfg.HeartbeatEnabled,
		ClusterID: cfg.ClusterID,
		Version:   collectorVersion(),
		Interval:  cfg.HeartbeatInterval,
	}, logger)
	beater.Start()

	// HTTP server
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	handler := webhook.NewHandler(pipe, cfg.WebhookMaxConcurrent, logger)
	r.Post("/webhook", handler.ServeHTTP)

	// Separate route from /webhook on purpose: a Watchdog alert must never be
	// forwarded to the brain, never reach the LLM, and never cost a token. It
	// fires every minute forever — routing it as an alert would be a
	// permanent self-inflicted storm.
	probeHandler := webhook.NewPipelineHandler(probe, cfg.PipelineProbeAlertName, logger)
	r.Post("/pipeline-ok", probeHandler.ServeHTTP)

	r.Handle("/metrics", promhttp.Handler())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	srv := &http.Server{Addr: addr, Handler: r}

	logger.Info("starting muthur-collector",
		zap.String("addr", addr),
		zap.String("cluster_id", cfg.ClusterID),
		zap.String("auth_mode", cfg.AuthMode),
		zap.String("logs_backend", cfg.LogsBackend),
		zap.String("metrics_backend", cfg.MetricsBackend),
		zap.String("version", collectorVersion()),
	)

	// Graceful shutdown exists for one reason: the final heartbeat. Without
	// it every rollout, drain and `helm uninstall` would look identical to a
	// crash and page somebody. SIGTERM is what Kubernetes sends first.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	// Stop accepting alerts first, so the goodbye beat is the last word the
	// brain hears from this collector.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown failed", zap.Error(err))
	}
	beater.Stop(shutdownCtx)
	return nil
}

// collectorVersion reports the chart-supplied version, falling back to the
// build-time default when the chart did not set one.
func collectorVersion() string {
	if v := os.Getenv("COLLECTOR_VERSION"); v != "" {
		return v
	}
	return version
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
