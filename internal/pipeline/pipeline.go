package pipeline

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/forwarder"
	"github.com/VojtechPastyrik/muthur-collector/internal/k8s"
	"github.com/VojtechPastyrik/muthur-collector/internal/loki"
	"github.com/VojtechPastyrik/muthur-collector/internal/prometheus"
	"github.com/VojtechPastyrik/muthur-collector/internal/redact"
	"github.com/VojtechPastyrik/muthur-collector/internal/resolver"
	"github.com/VojtechPastyrik/muthur-collector/internal/webhook"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

type Pipeline struct {
	clusterID  string
	resolver   *resolver.Resolver
	loki       *loki.Client
	prom       *prometheus.Client
	k8sClient  *k8s.Client
	redactor   *redact.Redactor
	forwarder  *forwarder.Forwarder
	logger     *zap.Logger
}

func New(
	clusterID string,
	resolver *resolver.Resolver,
	lokiClient *loki.Client,
	promClient *prometheus.Client,
	k8sClient *k8s.Client,
	redactor *redact.Redactor,
	fwd *forwarder.Forwarder,
	logger *zap.Logger,
) *Pipeline {
	return &Pipeline{
		clusterID: clusterID,
		resolver:  resolver,
		loki:      lokiClient,
		prom:      promClient,
		k8sClient: k8sClient,
		redactor:  redactor,
		forwarder: fwd,
		logger:    logger,
	}
}

func (p *Pipeline) ProcessAlert(alert webhook.Alert) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alertName := alert.Labels["alertname"]
	severity := alert.Labels["severity"]
	namespace := alert.Labels["namespace"]

	p.logger.Info("processing alert",
		zap.String("alert", alertName),
		zap.String("severity", severity),
		zap.String("namespace", namespace),
	)

	// Resolve target
	target := p.resolver.Resolve(alert.Labels)

	// Build payload
	payload := &pb.AlertPayload{
		ClusterId:   p.clusterID,
		AlertName:   alertName,
		Severity:    severity,
		Namespace:   namespace,
		PodName:     target.PodName,
		FiredAt:     alert.StartsAt.Unix(),
		Summary:     alert.Annotations["summary"],
		Description: alert.Annotations["description"],
		Target:      target,
	}

	// Convert labels
	for k, v := range alert.Labels {
		payload.Labels = append(payload.Labels, &pb.Label{Name: k, Value: v})
	}

	// Fetch logs from Loki
	if len(target.ResolvedPods) > 0 && namespace != "" {
		logs, err := p.loki.FetchLogs(ctx, namespace, target.ResolvedPods)
		if err != nil {
			p.logger.Warn("failed to fetch logs", zap.Error(err))
		} else if len(logs) > 0 {
			redacted, stats := p.redactor.Redact(logs)
			payload.RedactedLogs = redacted
			payload.TotalLogLines = int32(stats.TotalLines)
			payload.RedactedLogLines = int32(stats.RedactedLines)
			payload.TotalReplacements = int32(stats.Replacements)
		}
	}

	// Fetch metrics from Prometheus
	metrics, err := p.prom.FetchMetrics(ctx, target.TargetType, namespace, target.ResolvedPods, target.Node)
	if err != nil {
		p.logger.Warn("failed to fetch metrics", zap.Error(err))
	} else {
		payload.Metrics = metrics
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

	// Forward to central
	if err := p.forwarder.Forward(ctx, payload); err != nil {
		p.logger.Error("failed to forward alert",
			zap.String("alert", alertName),
			zap.Error(err),
		)
	} else {
		p.logger.Info("alert forwarded successfully",
			zap.String("alert", alertName),
			zap.String("target_type", target.TargetType),
			zap.Int("log_lines", len(payload.RedactedLogs)),
			zap.Int("metric_series", len(payload.Metrics)),
		)
	}
}
