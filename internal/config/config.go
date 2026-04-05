package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	ClusterID            string
	CentralAgentURL      string
	CentralAgentToken    string
	LokiEnabled          bool
	LokiURL              string
	LokiLookbackMinutes  int
	LokiMaxLogLines      int
	PrometheusURL        string
	PrometheusLookbackMin int
	PrometheusEnabled    bool
	GrafanaBaseURL       string
	RedactExtraPatterns  string
	RedactLogStats       bool
	Port                 string
	LogLevel             string
}

func Load() (*Config, error) {
	lokiEnabled, _ := strconv.ParseBool(envOr("LOKI_ENABLED", "true"))
	lokiLookback, _ := strconv.Atoi(envOr("LOKI_LOOKBACK_MINUTES", "15"))
	lokiMaxLines, _ := strconv.Atoi(envOr("LOKI_MAX_LOG_LINES", "200"))
	promLookback, _ := strconv.Atoi(envOr("PROMETHEUS_LOOKBACK_MINUTES", "30"))
	promEnabled, _ := strconv.ParseBool(envOr("PROMETHEUS_ENABLED", "true"))
	redactStats, _ := strconv.ParseBool(envOr("REDACT_LOG_STATS", "true"))

	cfg := &Config{
		ClusterID:            os.Getenv("CLUSTER_ID"),
		CentralAgentURL:      os.Getenv("CENTRAL_AGENT_URL"),
		CentralAgentToken:    os.Getenv("CENTRAL_AGENT_TOKEN"),
		LokiEnabled:          lokiEnabled,
		LokiURL:              envOr("LOKI_URL", "http://loki.monitoring.svc:3100"),
		LokiLookbackMinutes:  lokiLookback,
		LokiMaxLogLines:      lokiMaxLines,
		PrometheusURL:        envOr("PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090"),
		PrometheusLookbackMin: promLookback,
		PrometheusEnabled:    promEnabled,
		GrafanaBaseURL:       os.Getenv("GRAFANA_BASE_URL"),
		RedactExtraPatterns:  os.Getenv("REDACT_EXTRA_PATTERNS"),
		RedactLogStats:       redactStats,
		Port:                 envOr("PORT", "8080"),
		LogLevel:             envOr("LOG_LEVEL", "info"),
	}

	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("CLUSTER_ID is required")
	}
	if cfg.CentralAgentURL == "" {
		return nil, fmt.Errorf("CENTRAL_AGENT_URL is required")
	}
	if cfg.CentralAgentToken == "" {
		return nil, fmt.Errorf("CENTRAL_AGENT_TOKEN is required")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
