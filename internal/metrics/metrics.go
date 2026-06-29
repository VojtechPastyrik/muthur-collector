// Package metrics exposes Prometheus instrumentation for muthur-collector:
// alert throughput, forwarding success/latency, and enrichment (Loki /
// Prometheus) latency and errors. Served at /metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AlertsReceived counts alerts handled, by status (firing|resolved).
	AlertsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_collector_alerts_received_total",
		Help: "Alerts processed by the collector, by status.",
	}, []string{"status"})

	// Forwards counts forward attempts to central, by result (ok|error).
	Forwards = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_collector_forwards_total",
		Help: "Alert payloads forwarded to central, by result.",
	}, []string{"result"})

	// ForwardRetries counts retry attempts on transient forward failures.
	ForwardRetries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "muthur_collector_forward_retries_total",
		Help: "Retry attempts while forwarding to central.",
	})

	// ForwardDuration tracks end-to-end forward latency including retries.
	ForwardDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "muthur_collector_forward_duration_seconds",
		Help:    "Forward latency to central including retries.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 15},
	})

	// EnrichDuration tracks enrichment-fetch latency by source (loki|prometheus).
	EnrichDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "muthur_collector_enrich_duration_seconds",
		Help:    "Enrichment fetch latency by source.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
	}, []string{"source"})

	// EnrichErrors counts enrichment-fetch failures by source.
	EnrichErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_collector_enrich_errors_total",
		Help: "Enrichment fetch failures by source.",
	}, []string{"source"})

	// LinesDropped counts log lines dropped before forwarding, by reason:
	// oversize (a single line exceeds the per-line byte cap) or budget (the
	// total payload byte budget was exhausted). Redaction fails closed — a line
	// it cannot safely bound is dropped, never forwarded raw.
	LinesDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_collector_log_lines_dropped_total",
		Help: "Log lines dropped by the redactor's fail-closed size guards, by reason.",
	}, []string{"reason"})

	// AlertsDropped counts alerts dropped at the webhook because the collector
	// was already at its concurrency ceiling — storm protection that keeps the
	// AlertManager webhook from wedging.
	AlertsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "muthur_collector_alerts_dropped_total",
		Help: "Alerts dropped at the webhook due to the concurrency ceiling.",
	})

	// RedactReplacements counts individual pattern replacements made by the
	// redactor across both log lines and free-text fields (Summary, Description,
	// label values, metric descriptions). Labelled by surface so an unexpected
	// drop in one path (e.g. labels going to 0) surfaces as a metric regression
	// rather than a silent privacy leak.
	RedactReplacements = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_collector_redact_replacements_total",
		Help: "Pattern replacements made by the redactor, by surface (log_line | string).",
	}, []string{"surface"})
)
