package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// AlertManagerPayload represents the AlertManager webhook JSON body.
type AlertManagerPayload struct {
	Alerts []Alert `json:"alerts"`
}

type Alert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

type AlertProcessor interface {
	ProcessAlert(alert Alert)
}

type Handler struct {
	processor AlertProcessor
	logger    *zap.Logger
}

func NewHandler(processor AlertProcessor, logger *zap.Logger) *Handler {
	return &Handler{
		processor: processor,
		logger:    logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("failed to read request body", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload AlertManagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.logger.Error("failed to unmarshal alertmanager payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	h.logger.Info("received alertmanager webhook", zap.Int("alert_count", len(payload.Alerts)))

	// Process alerts asynchronously — AlertManager has a short webhook timeout
	// (10s default) and the full pipeline (k8s lookup, Loki, Prometheus, forward
	// to central, Claude evaluation) routinely exceeds it. Ack immediately and
	// let goroutines do the work in the background.
	for _, alert := range payload.Alerts {
		a := alert
		go h.processor.ProcessAlert(a)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
