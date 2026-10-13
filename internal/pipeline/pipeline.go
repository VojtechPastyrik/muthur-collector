package pipeline

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/forwarder"
	"github.com/VojtechPastyrik/muthur-collector/internal/k8s"
	"github.com/VojtechPastyrik/muthur-collector/internal/metrics"
	"github.com/VojtechPastyrik/muthur-collector/internal/redact"
	"github.com/VojtechPastyrik/muthur-collector/internal/resolver"
	"github.com/VojtechPastyrik/muthur-collector/internal/webhook"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// maxEventsPerPayload caps total events across all target objects; the
// per-object cap lives in the k8s client.
const maxEventsPerPayload = 50

// LogFetcher returns recent log lines for the alert target. Implemented by
// internal/loki and internal/victorialogs; the pipeline does not care which,
// beyond labelling its enrichment metrics with Name().
type LogFetcher interface {
	FetchLogs(ctx context.Context, namespace string, pods []string) ([]string, error)
	Name() string
}

// MetricFetcher returns recent metric series for the alert target. Implemented
// by internal/prometheus for both Prometheus and VictoriaMetrics, which share
// the /api/v1/query_range contract.
type MetricFetcher interface {
	FetchMetrics(ctx context.Context, targetType, namespace string, pods []string, node string) ([]*pb.MetricSeries, error)
	Name() string
}

type Pipeline struct {
	clusterID       string
	grafanaBaseURL  string
	grafanaLogsDS   string
	resolver        *resolver.Resolver
	logs            LogFetcher
	metricsBackend  MetricFetcher
	k8sClient       *k8s.Client
	redactor        *redact.Redactor
	forwarder       *forwarder.Forwarder
	alertsForwarded atomic.Int64
	logger          *zap.Logger
}

// Config carries the pipeline's collaborators. A nil Logs disables log
// enrichment entirely; a nil Metrics does the same for metrics.
type Config struct {
	ClusterID      string
	GrafanaBaseURL string
	// GrafanaLogsDatasource names the Grafana datasource holding this
	// cluster's logs. Sent to the brain so the Explore deep link points at the
	// right datasource — "Loki" and "VictoriaLogs" need different ones.
	GrafanaLogsDatasource string
	Resolver              *resolver.Resolver
	Logs                  LogFetcher
	Metrics               MetricFetcher
	K8s                   *k8s.Client
	Redactor              *redact.Redactor
	Forwarder             *forwarder.Forwarder
}

func New(cfg Config, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		clusterID:      cfg.ClusterID,
		grafanaBaseURL: cfg.GrafanaBaseURL,
		grafanaLogsDS:  cfg.GrafanaLogsDatasource,
		resolver:       cfg.Resolver,
		logs:           cfg.Logs,
		metricsBackend: cfg.Metrics,
		k8sClient:      cfg.K8s,
		redactor:       cfg.Redactor,
		forwarder:      cfg.Forwarder,
		logger:         logger,
	}
}

// AlertsForwarded reports how many alerts this process has forwarded. Read by
// the heartbeat sender so the brain can show throughput per cluster.
func (p *Pipeline) AlertsForwarded() int64 { return p.alertsForwarded.Load() }

func (p *Pipeline) ProcessAlert(alert webhook.Alert) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alertName := alert.Labels["alertname"]
	severity := alert.Labels["severity"]
	namespace := alert.Labels["namespace"]
	status := alert.Status
	if status == "" {
		status = "firing"
	}
	metrics.AlertsReceived.WithLabelValues(status).Inc()

	p.logger.Info("processing alert",
		zap.String("alert", alertName),
		zap.String("severity", severity),
		zap.String("namespace", namespace),
		zap.String("status", status),
	)

	// Resolve target
	target := p.resolver.Resolve(alert.Labels)

	// Build payload
	payload := &pb.AlertPayload{
		ClusterId:             p.clusterID,
		AlertName:             alertName,
		Severity:              severity,
		Namespace:             namespace,
		PodName:               target.PodName,
		FiredAt:               alert.StartsAt.Unix(),
		Summary:               p.redactor.RedactString(alert.Annotations["summary"]),
		Description:           p.redactor.RedactString(alert.Annotations["description"]),
		Target:                target,
		Status:                status,
		GrafanaBaseUrl:        p.grafanaBaseURL,
		GrafanaLogsDatasource: p.grafanaLogsDS,
	}

	// Convert labels. Both name and value go through the redactor — values are
	// the obvious PII vector (user IDs, emails, IPs in label values), but
	// custom k8s labels can also leak through the *name* (e.g. a label
	// `customer_email_alice_at_example_com=true` exposes structure even with
	// a redacted value).
	for k, v := range alert.Labels {
		payload.Labels = append(payload.Labels, &pb.Label{
			Name:  p.redactor.RedactString(k),
			Value: p.redactor.RedactString(v),
		})
	}

	// Resolved alerts need no enrichment — central only sends a "resolved"
	// notification, no Claude evaluation, no logs/metrics required.
	if status == "resolved" {
		if err := p.forwarder.Forward(ctx, payload); err != nil {
			p.logger.Error("failed to forward resolved alert",
				zap.String("alert", alertName),
				zap.Error(err),
			)
		} else {
			p.alertsForwarded.Add(1)
			p.logger.Info("resolved alert forwarded", zap.String("alert", alertName))
		}
		return
	}

	// Fetch logs from the configured backend (skipped entirely when logs are
	// disabled, which leaves the collector forwarding alerts without excerpts
	// rather than warning on every alert).
	if p.logs != nil && len(target.ResolvedPods) > 0 && namespace != "" {
		backend := p.logs.Name()
		logsStart := time.Now()
		logs, err := p.logs.FetchLogs(ctx, namespace, target.ResolvedPods)
		metrics.EnrichDuration.WithLabelValues(backend).Observe(time.Since(logsStart).Seconds())
		if err != nil {
			metrics.EnrichErrors.WithLabelValues(backend).Inc()
			p.logger.Warn("failed to fetch logs",
				zap.String("backend", backend), zap.Error(err))
		} else if len(logs) > 0 {
			redacted, stats := p.redactor.Redact(logs)
			payload.RedactedLogs = redacted
			payload.TotalLogLines = int32(stats.TotalLines)
			payload.RedactedLogLines = int32(stats.RedactedLines)
			payload.TotalReplacements = int32(stats.Replacements)
		}
	}

	// Fetch metrics from the configured backend.
	if p.metricsBackend != nil {
		backend := p.metricsBackend.Name()
		metricsStart := time.Now()
		series, err := p.metricsBackend.FetchMetrics(ctx, target.TargetType, namespace, target.ResolvedPods, target.Node)
		metrics.EnrichDuration.WithLabelValues(backend).Observe(time.Since(metricsStart).Seconds())
		if err != nil {
			metrics.EnrichErrors.WithLabelValues(backend).Inc()
			p.logger.Warn("failed to fetch metrics",
				zap.String("backend", backend), zap.Error(err))
		} else {
			for _, m := range series {
				m.Description = p.redactor.RedactString(m.Description)
			}
			payload.Metrics = series
		}
	}

	// Fetch pod metadata
	if p.k8sClient != nil {
		for _, podName := range target.ResolvedPods {
			meta, err := p.k8sClient.PodMeta(ctx, namespace, podName)
			if err != nil {
				p.logger.Warn("failed to get pod meta",
					zap.String("pod", podName), zap.Error(err))
				continue
			}
			payload.PodMetas = append(payload.PodMetas, meta)
		}
	}

	// Fetch Kubernetes events for the target objects. A pod stuck in Pending
	// produces no logs and no container metrics — the reason (FailedScheduling,
	// FailedMount, PVC not bound, ImagePullBackOff) exists only as events.
	if p.k8sClient != nil && namespace != "" {
		objects := append([]string{}, target.ResolvedPods...)
		if target.Pvc != "" {
			objects = append(objects, target.Pvc)
		}
		evStart := time.Now()
		for _, name := range objects {
			events, err := p.k8sClient.FetchEvents(ctx, namespace, name)
			if err != nil {
				metrics.EnrichErrors.WithLabelValues("events").Inc()
				p.logger.Warn("failed to fetch events",
					zap.String("object", name), zap.Error(err))
				continue
			}
			for _, ev := range events {
				ev.Message = p.redactor.RedactString(ev.Message)
			}
			payload.Events = append(payload.Events, events...)
		}
		metrics.EnrichDuration.WithLabelValues("events").Observe(time.Since(evStart).Seconds())
		if len(payload.Events) > maxEventsPerPayload {
			payload.Events = payload.Events[:maxEventsPerPayload]
		}
	}

	// Forward to central
	if err := p.forwarder.Forward(ctx, payload); err != nil {
		p.logger.Error("failed to forward alert",
			zap.String("alert", alertName),
			zap.Error(err),
		)
	} else {
		p.alertsForwarded.Add(1)
		p.logger.Info("alert forwarded successfully",
			zap.String("alert", alertName),
			zap.String("target_type", target.TargetType),
			zap.Int("log_lines", len(payload.RedactedLogs)),
			zap.Int("metric_series", len(payload.Metrics)),
		)
	}
}
