package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

type mockProcessor struct {
	alerts []Alert
}

func (m *mockProcessor) ProcessAlert(alert Alert) {
	m.alerts = append(m.alerts, alert)
}

func TestHandler_FiringAlert(t *testing.T) {
	proc := &mockProcessor{}
	handler := NewHandler(proc, zap.NewNop())

	payload := AlertManagerPayload{
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "HighMemory",
					"severity":  "critical",
					"namespace": "default",
					"pod":       "app-123",
				},
				Annotations: map[string]string{
					"summary": "Memory too high",
				},
			},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(proc.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(proc.alerts))
	}
	if proc.alerts[0].Labels["alertname"] != "HighMemory" {
		t.Error("wrong alert name")
	}
}

func TestHandler_ResolvedAlertSkipped(t *testing.T) {
	proc := &mockProcessor{}
	handler := NewHandler(proc, zap.NewNop())

	payload := AlertManagerPayload{
		Alerts: []Alert{
			{Status: "resolved", Labels: map[string]string{"alertname": "Test"}},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if len(proc.alerts) != 0 {
		t.Error("resolved alerts should be skipped")
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	handler := NewHandler(&mockProcessor{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(&mockProcessor{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_MultipleAlerts(t *testing.T) {
	proc := &mockProcessor{}
	handler := NewHandler(proc, zap.NewNop())

	payload := AlertManagerPayload{
		Alerts: []Alert{
			{Status: "firing", Labels: map[string]string{"alertname": "A"}},
			{Status: "resolved", Labels: map[string]string{"alertname": "B"}},
			{Status: "firing", Labels: map[string]string{"alertname": "C"}},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if len(proc.alerts) != 2 {
		t.Fatalf("expected 2 firing alerts, got %d", len(proc.alerts))
	}
}
