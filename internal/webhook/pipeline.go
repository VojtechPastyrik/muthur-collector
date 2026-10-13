package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/metrics"
)

// maxProbeBody bounds the Watchdog webhook body. The real payload is a few
// hundred bytes; this endpoint is reachable by anything inside the cluster,
// so it must not become a way to make the collector buffer arbitrary input.
const maxProbeBody = 64 << 10

// PipelineRecorder is the liveness probe the handler touches, implemented by
// heartbeat.Probe.
type PipelineRecorder interface {
	Touch(now time.Time)
}

// PipelineHandler receives the cluster's Watchdog alert and records that the
// alerting pipeline is working end to end.
//
// It deliberately does not implement AlertProcessor: a Watchdog alert must
// never be forwarded to the brain, never reach the LLM, and never cost a
// token. It fires every minute forever — treating it as an alert would be a
// permanent, self-inflicted alert storm. All it does here is move a timestamp.
type PipelineHandler struct {
	probe PipelineRecorder
	// alertName is the alert accepted as proof. Configurable because not every
	// stack calls it Watchdog, but matched strictly: without the check, any
	// POST to this path would forge proof that alerting works, which is
	// exactly the lie this endpoint exists to prevent.
	alertName string
	logger    *zap.Logger
	now       func() time.Time
}

// NewPipelineHandler builds the handler. An empty alertName falls back to
// "Watchdog", the name kube-prometheus-stack ships.
func NewPipelineHandler(probe PipelineRecorder, alertName string, logger *zap.Logger) *PipelineHandler {
	if alertName == "" {
		alertName = "Watchdog"
	}
	return &PipelineHandler{
		probe:     probe,
		alertName: alertName,
		logger:    logger,
		now:       time.Now,
	}
}

func (h *PipelineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProbeBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var payload AlertManagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Ack regardless of what we found. AlertManager retries on a non-2xx and
	// a retry loop on the liveness probe would be a self-inflicted outage on
	// the very path being measured.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))

	for _, alert := range payload.Alerts {
		if alert.Labels["alertname"] != h.alertName {
			continue
		}
		// A resolved Watchdog means the pipeline is being torn down, not that
		// it works. Only a firing one is proof.
		if alert.Status != "" && alert.Status != "firing" {
			continue
		}
		h.probe.Touch(h.now())
		metrics.PipelineProbes.Inc()
		return
	}

	h.logger.Debug("pipeline probe received no matching alert",
		zap.String("expected_alertname", h.alertName),
		zap.Int("alerts", len(payload.Alerts)),
	)
}
