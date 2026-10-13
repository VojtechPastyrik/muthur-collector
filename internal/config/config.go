package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ClusterID       string
	TenantID        string
	CentralAgentURL string

	// AuthMode selects the transport to the brain: "mtls" (gRPC, the brain
	// terminates TLS itself) or "signed" (HTTPS through any TLS-terminating
	// edge; requests are signed with the collector cert and HPKE-sealed).
	AuthMode string
	// SignedEdgeCAFile optionally pins the CA of the edge's TLS certificate
	// in signed mode. Empty means system roots.
	SignedEdgeCAFile string

	// LogsBackend selects where log excerpts come from: "loki" (default) or
	// "victorialogs". The two are not interchangeable by URL — VictoriaLogs'
	// Loki compatibility covers ingestion only, not querying.
	LogsBackend string
	// MetricsBackend selects where metric series come from: "prometheus"
	// (default) or "victoriametrics". These two DO share the query API; the
	// distinction buys tenant headers and accurate labelling, not a different
	// protocol.
	MetricsBackend string

	LokiEnabled           bool
	LokiURL               string
	LokiLookbackMinutes   int
	LokiMaxLogLines       int
	PrometheusURL         string
	PrometheusLookbackMin int
	PrometheusEnabled     bool

	// VictoriaLogs settings, used when LogsBackend is "victorialogs".
	VictoriaLogsURL             string
	VictoriaLogsLookbackMinutes int
	VictoriaLogsMaxLogLines     int
	VictoriaLogsAccountID       string
	VictoriaLogsProjectID       string

	// VictoriaMetrics settings, used when MetricsBackend is "victoriametrics".
	// The URL must already carry the tenant prefix on a cluster deployment,
	// e.g. http://vmselect:8481/select/0/prometheus.
	VictoriaMetricsURL             string
	VictoriaMetricsLookbackMinutes int
	VictoriaMetricsAccountID       string
	VictoriaMetricsProjectID       string

	// LogsExtraSelector / MetricsExtraSelector are label matchers ANDed into
	// every query, e.g. `cluster="prod"`. Required when one backend instance
	// holds several clusters' data: namespace+pod alone is then ambiguous and
	// the collector would enrich an alert with another cluster's logs.
	LogsExtraSelector    string
	MetricsExtraSelector string

	GrafanaBaseURL string
	// GrafanaLogsDatasource names the Grafana datasource holding this
	// cluster's logs, sent to the brain for the Explore deep link. Defaults
	// to a name matching the selected logs backend.
	GrafanaLogsDatasource string

	// Heartbeat reports liveness to the brain so a dead collector is noticed
	// rather than mistaken for a quiet cluster.
	HeartbeatEnabled  bool
	HeartbeatInterval time.Duration

	// PipelineProbeAlertName is the alert accepted at /pipeline-ok as proof
	// that the cluster's own alerting path works end to end. Route it from
	// AlertManager instead of dropping it; see the README.
	PipelineProbeAlertName string
	RedactExtraPatterns    string
	RedactLogStats         bool
	RedactMaxLineBytes     int
	RedactMaxTotalBytes    int
	RedactMaxStringBytes   int
	WebhookMaxConcurrent   int
	Port                   string
	LogLevel               string

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

	// RenewBefore is the runway threshold for the renew CronJob. If the
	// current cert has more remaining validity than this, the renew run
	// exits early without contacting the brain. Lets the CronJob fire
	// often (self-healing on transient brain outages) without rotating
	// the cert on every tick.
	RenewBefore time.Duration
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
	redactMaxStringBytes, _ := strconv.Atoi(envOr("REDACT_MAX_STRING_BYTES", "16384"))
	webhookMaxConcurrent, _ := strconv.Atoi(envOr("WEBHOOK_MAX_CONCURRENT", "50"))

	vlLookback, _ := strconv.Atoi(envOr("VICTORIALOGS_LOOKBACK_MINUTES", "15"))
	vlMaxLines, _ := strconv.Atoi(envOr("VICTORIALOGS_MAX_LOG_LINES", "200"))
	vmLookback, _ := strconv.Atoi(envOr("VICTORIAMETRICS_LOOKBACK_MINUTES", "30"))

	heartbeatEnabled, _ := strconv.ParseBool(envOr("HEARTBEAT_ENABLED", "true"))
	heartbeatIntervalRaw := envOr("HEARTBEAT_INTERVAL", "60s")
	heartbeatInterval, err := time.ParseDuration(heartbeatIntervalRaw)
	if err != nil {
		return nil, fmt.Errorf("parse HEARTBEAT_INTERVAL %q: %w", heartbeatIntervalRaw, err)
	}

	renewBeforeRaw := envOr("RENEW_BEFORE", "48h")
	renewBefore, err := time.ParseDuration(renewBeforeRaw)
	if err != nil {
		return nil, fmt.Errorf("parse RENEW_BEFORE %q: %w", renewBeforeRaw, err)
	}

	cfg := &Config{
		ClusterID:                   os.Getenv("CLUSTER_ID"),
		TenantID:                    os.Getenv("TENANT_ID"),
		CentralAgentURL:             os.Getenv("CENTRAL_AGENT_URL"),
		AuthMode:                    envOr("AUTH_MODE", AuthModeMTLS),
		SignedEdgeCAFile:            os.Getenv("SIGNED_TLS_CA_FILE"),
		LogsBackend:                 envOr("LOGS_BACKEND", BackendLoki),
		MetricsBackend:              envOr("METRICS_BACKEND", BackendPrometheus),
		LokiEnabled:                 lokiEnabled,
		LokiURL:                     envOr("LOKI_URL", "http://loki.monitoring.svc:3100"),
		LokiLookbackMinutes:         lokiLookback,
		LokiMaxLogLines:             lokiMaxLines,
		PrometheusURL:               envOr("PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090"),
		PrometheusLookbackMin:       promLookback,
		PrometheusEnabled:           promEnabled,
		VictoriaLogsURL:             envOr("VICTORIALOGS_URL", "http://victoria-logs-single-server.monitoring.svc:9428"),
		VictoriaLogsLookbackMinutes: vlLookback,
		VictoriaLogsMaxLogLines:     vlMaxLines,
		VictoriaLogsAccountID:       os.Getenv("VICTORIALOGS_ACCOUNT_ID"),
		VictoriaLogsProjectID:       os.Getenv("VICTORIALOGS_PROJECT_ID"),

		VictoriaMetricsURL:             envOr("VICTORIAMETRICS_URL", "http://vmselect.monitoring.svc:8481/select/0/prometheus"),
		VictoriaMetricsLookbackMinutes: vmLookback,
		VictoriaMetricsAccountID:       os.Getenv("VICTORIAMETRICS_ACCOUNT_ID"),
		VictoriaMetricsProjectID:       os.Getenv("VICTORIAMETRICS_PROJECT_ID"),

		LogsExtraSelector:    os.Getenv("LOGS_EXTRA_SELECTOR"),
		MetricsExtraSelector: os.Getenv("METRICS_EXTRA_SELECTOR"),

		GrafanaBaseURL:        os.Getenv("GRAFANA_BASE_URL"),
		GrafanaLogsDatasource: os.Getenv("GRAFANA_LOGS_DATASOURCE"),

		HeartbeatEnabled:  heartbeatEnabled,
		HeartbeatInterval: heartbeatInterval,

		PipelineProbeAlertName: envOr("PIPELINE_PROBE_ALERTNAME", "Watchdog"),
		RedactExtraPatterns:    os.Getenv("REDACT_EXTRA_PATTERNS"),
		RedactLogStats:         redactStats,
		RedactMaxLineBytes:     redactMaxLineBytes,
		RedactMaxTotalBytes:    redactMaxTotalBytes,
		RedactMaxStringBytes:   redactMaxStringBytes,
		WebhookMaxConcurrent:   webhookMaxConcurrent,
		Port:                   envOr("PORT", "8080"),
		LogLevel:               envOr("LOG_LEVEL", "info"),

		CertDir:            envOr("CERT_DIR", "/secrets/tls/collector"),
		BootstrapTokenFile: envOr("BOOTSTRAP_TOKEN_FILE", "/secrets/bootstrap/token"),
		VendorCAFile:       envOr("VENDOR_CA_FILE", "/secrets/vendor-ca/ca.crt"),
		CertSecretName:     os.Getenv("CERT_SECRET_NAME"),
		Namespace:          os.Getenv("POD_NAMESPACE"),

		RenewBefore: renewBefore,
	}

	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("CLUSTER_ID is required")
	}
	if cfg.CentralAgentURL == "" {
		return nil, fmt.Errorf("CENTRAL_AGENT_URL is required")
	}
	switch cfg.AuthMode {
	case AuthModeMTLS, AuthModeSigned:
	default:
		return nil, fmt.Errorf("unknown AUTH_MODE %q (want mtls or signed)", cfg.AuthMode)
	}
	switch cfg.LogsBackend {
	case BackendLoki, BackendVictoriaLogs:
	default:
		return nil, fmt.Errorf("unknown LOGS_BACKEND %q (want %s or %s)", cfg.LogsBackend, BackendLoki, BackendVictoriaLogs)
	}
	switch cfg.MetricsBackend {
	case BackendPrometheus, BackendVictoriaMetrics:
	default:
		return nil, fmt.Errorf("unknown METRICS_BACKEND %q (want %s or %s)", cfg.MetricsBackend, BackendPrometheus, BackendVictoriaMetrics)
	}
	if cfg.GrafanaLogsDatasource == "" {
		cfg.GrafanaLogsDatasource = defaultGrafanaDatasource(cfg.LogsBackend)
	}

	return cfg, nil
}

// Backend names accepted in LOGS_BACKEND / METRICS_BACKEND.
const (
	BackendLoki            = "loki"
	BackendVictoriaLogs    = "victorialogs"
	BackendPrometheus      = "prometheus"
	BackendVictoriaMetrics = "victoriametrics"
)

// defaultGrafanaDatasource maps a logs backend to the datasource name Grafana
// uses by convention. VictoriaLogs needs its own datasource plugin
// (victoriametrics-logs-datasource) — the Loki datasource cannot query it.
func defaultGrafanaDatasource(backend string) string {
	if backend == BackendVictoriaLogs {
		return "VictoriaLogs"
	}
	return "Loki"
}

// LogsEnabled reports whether log enrichment is on. LOKI_ENABLED keeps its
// historical name and meaning — it gates log enrichment regardless of which
// backend serves it — so an existing values.yaml keeps working unchanged.
func (c *Config) LogsEnabled() bool { return c.LokiEnabled }

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

// Auth mode names accepted in AUTH_MODE.
const (
	AuthModeMTLS   = "mtls"
	AuthModeSigned = "signed"
)
