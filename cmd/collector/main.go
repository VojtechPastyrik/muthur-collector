package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
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
	var k8sClient *k8s.Client
	k8sClient, err = k8s.NewClient(logger)
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
	redactor := redact.New(cfg.RedactExtraPatterns, cfg.RedactLogStats, logger)
	fwd := forwarder.New(cfg.CentralAgentURL, cfg.CentralAgentToken, logger)
	res := resolver.New(k8sClient, logger)

	pipe := pipeline.New(cfg.ClusterID, res, lokiClient, promClient, k8sClient, redactor, fwd, logger)

	// HTTP server
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	handler := webhook.NewHandler(pipe, logger)
	r.Post("/webhook", handler.ServeHTTP)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Info("starting muthur-collector",
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
