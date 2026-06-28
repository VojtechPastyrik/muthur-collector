package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	ClusterID             string
	TenantID              string
	CentralAgentURL       string
	LokiEnabled           bool
	LokiURL               string
	LokiLookbackMinutes   int
	LokiMaxLogLines       int
	PrometheusURL         string
	PrometheusLookbackMin int
	PrometheusEnabled     bool
	GrafanaBaseURL        string
	RedactExtraPatterns   string
	RedactLogStats        bool
	RedactMaxLineBytes    int
	RedactMaxTotalBytes   int
	WebhookMaxConcurrent  int
	Port                  string
	LogLevel              string

	// mTLS paths. CertDir holds the collector's leaf cert (tls.crt), its key
	// (tls.key), and the vendor CA bundle (ca.crt) used to verify the brain.
	// All three live in a single mounted Secret. BootstrapTokenFile is a
	// one-shot secret consumed by the init container; the running collector
	// never needs to read it. VendorCAFile points at the chart-provided
	// trust root used during the first bootstrap call (before the collector
	// has its own cert yet).
	//
	// CertSecretName + Namespace let the init/renew flows write into a
	// Kubernetes Secret directly rather than a PVC.
	CertDir            string
	BootstrapTokenFile string
	VendorCAFile       string
	CertSecretName     string
	Namespace          string
}

func Load() (*Config, error) {
	lokiEnabled, _ := strconv.ParseBool(envOr("LOKI_ENABLED", "true"))
	lokiLookback, _ := strconv.Atoi(envOr("LOKI_LOOKBACK_MINUTES", "15"))
	lokiMaxLines, _ := strconv.Atoi(envOr("LOKI_MAX_LOG_LINES", "200"))
	promLookback, _ := strconv.Atoi(envOr("PROMETHEUS_LOOKBACK_MINUTES", "30"))
	promEnabled, _ := strconv.ParseBool(envOr("PROMETHEUS_ENABLED", "true"))
	redactStats, _ := strconv.ParseBool(envOr("REDACT_LOG_STATS", "true"))
	redactMaxLineBytes, _ := strconv.Atoi(envOr("REDACT_MAX_LINE_BYTES", "8192"))
	redactMaxTotalBytes, _ := strconv.Atoi(envOr("REDACT_MAX_TOTAL_BYTES", "262144"))
	webhookMaxConcurrent, _ := strconv.Atoi(envOr("WEBHOOK_MAX_CONCURRENT", "50"))

	cfg := &Config{
		ClusterID:             os.Getenv("CLUSTER_ID"),
		TenantID:              os.Getenv("TENANT_ID"),
		CentralAgentURL:       os.Getenv("CENTRAL_AGENT_URL"),
		LokiEnabled:           lokiEnabled,
		LokiURL:               envOr("LOKI_URL", "http://loki.monitoring.svc:3100"),
		LokiLookbackMinutes:   lokiLookback,
		LokiMaxLogLines:       lokiMaxLines,
		PrometheusURL:         envOr("PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090"),
		PrometheusLookbackMin: promLookback,
		PrometheusEnabled:     promEnabled,
		GrafanaBaseURL:        os.Getenv("GRAFANA_BASE_URL"),
		RedactExtraPatterns:   os.Getenv("REDACT_EXTRA_PATTERNS"),
		RedactLogStats:        redactStats,
		RedactMaxLineBytes:    redactMaxLineBytes,
		RedactMaxTotalBytes:   redactMaxTotalBytes,
		WebhookMaxConcurrent:  webhookMaxConcurrent,
		Port:                  envOr("PORT", "8080"),
		LogLevel:              envOr("LOG_LEVEL", "info"),

		CertDir:            envOr("CERT_DIR", "/secrets/tls/collector"),
		BootstrapTokenFile: envOr("BOOTSTRAP_TOKEN_FILE", "/secrets/bootstrap/token"),
		VendorCAFile:       envOr("VENDOR_CA_FILE", "/secrets/vendor-ca/ca.crt"),
		CertSecretName:     os.Getenv("CERT_SECRET_NAME"),
		Namespace:          os.Getenv("POD_NAMESPACE"),
	}

	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("CLUSTER_ID is required")
	}
	if cfg.CentralAgentURL == "" {
		return nil, fmt.Errorf("CENTRAL_AGENT_URL is required")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// CACertFile returns the path to the vendor CA bundle inside CertDir. Used by
// the forwarder + bootstrap/renew clients to verify the brain.
func (c *Config) CACertFile() string { return c.CertDir + "/ca.crt" }

// CertFile returns the path to the collector's leaf cert inside CertDir.
func (c *Config) CertFile() string { return c.CertDir + "/tls.crt" }

// KeyFile returns the path to the collector's private key inside CertDir.
func (c *Config) KeyFile() string { return c.CertDir + "/tls.key" }
