package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

type mockProcessor struct {
	alerts chan Alert
}

func newMockProcessor() *mockProcessor {
	return &mockProcessor{alerts: make(chan Alert, 8)}
}

func (m *mockProcessor) ProcessAlert(alert Alert) {
	m.alerts <- alert
}

// drain returns all alerts received within the timeout window.
func (m *mockProcessor) drain(t *testing.T, want int, timeout time.Duration) []Alert {
	t.Helper()
	got := make([]Alert, 0, want)
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case a := <-m.alerts:
			got = append(got, a)
		case <-deadline:
			return got
		}
	}
	// Drain any extra that may arrive immediately after (to detect over-delivery).
	for {
		select {
		case a := <-m.alerts:
			got = append(got, a)
		case <-time.After(50 * time.Millisecond):
			return got
		}
	}
}

func TestHandler_FiringAlert(t *testing.T) {
	proc := newMockProcessor()
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
	alerts := proc.drain(t, 1, time.Second)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Labels["alertname"] != "HighMemory" {
		t.Error("wrong alert name")
	}
}

// Resolved alerts are now forwarded to central so the pipeline can emit a
// "resolved" notification. The collector no longer filters them out.
func TestHandler_ResolvedAlertForwarded(t *testing.T) {
	proc := newMockProcessor()
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

	alerts := proc.drain(t, 1, time.Second)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 resolved alert forwarded, got %d", len(alerts))
	}
	if alerts[0].Status != "resolved" {
		t.Errorf("expected status resolved, got %q", alerts[0].Status)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	handler := NewHandler(newMockProcessor(), zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(newMockProcessor(), zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_MultipleAlerts(t *testing.T) {
	proc := newMockProcessor()
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

	// All three alerts (including resolved) should be forwarded.
	alerts := proc.drain(t, 3, time.Second)
	if len(alerts) != 3 {
		t.Fatalf("expected 3 alerts forwarded, got %d", len(alerts))
	}
}
