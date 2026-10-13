package webhook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeProbe struct{ touches atomic.Int64 }

func (f *fakeProbe) Touch(time.Time) { f.touches.Add(1) }

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/pipeline-ok", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWatchdogAlertTouchesProbe(t *testing.T) {
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	rec := post(t, h, `{"alerts":[{"status":"firing","labels":{"alertname":"Watchdog"}}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if probe.touches.Load() != 1 {
		t.Fatalf("expected the probe to be touched once, got %d", probe.touches.Load())
	}
}

func TestOtherAlertsDoNotForgeProof(t *testing.T) {
	// Without the alertname check, any POST to this path would claim the
	// alerting pipeline works — which is precisely the lie the endpoint
	// exists to detect.
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	post(t, h, `{"alerts":[{"status":"firing","labels":{"alertname":"KubePodCrashLooping"}}]}`)
	if probe.touches.Load() != 0 {
		t.Fatal("a non-Watchdog alert must not count as proof the pipeline works")
	}
}

func TestResolvedWatchdogIsNotProof(t *testing.T) {
	// A resolved Watchdog means the pipeline is being torn down, not that it
	// is delivering.
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	post(t, h, `{"alerts":[{"status":"resolved","labels":{"alertname":"Watchdog"}}]}`)
	if probe.touches.Load() != 0 {
		t.Fatal("a resolved Watchdog must not count as proof")
	}
}

func TestCustomAlertNameHonoured(t *testing.T) {
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "DeadMansSwitch", zap.NewNop())

	post(t, h, `{"alerts":[{"status":"firing","labels":{"alertname":"DeadMansSwitch"}}]}`)
	if probe.touches.Load() != 1 {
		t.Fatal("configured alert name must be accepted")
	}
	post(t, h, `{"alerts":[{"status":"firing","labels":{"alertname":"Watchdog"}}]}`)
	if probe.touches.Load() != 1 {
		t.Fatal("the default name must not be accepted once a custom one is set")
	}
}

func TestMalformedBodyIsRejectedNotPanicking(t *testing.T) {
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	rec := post(t, h, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if probe.touches.Load() != 0 {
		t.Fatal("a malformed body must not touch the probe")
	}
}

func TestEmptyAlertListAcksWithoutTouching(t *testing.T) {
	// AlertManager sends grouped payloads; an empty or non-matching group
	// must still be acked, because a non-2xx would make AlertManager retry
	// against the very path being measured.
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	rec := post(t, h, `{"alerts":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 ack, got %d", rec.Code)
	}
	if probe.touches.Load() != 0 {
		t.Fatal("an empty group proves nothing")
	}
}

func TestGetIsRejected(t *testing.T) {
	probe := &fakeProbe{}
	h := NewPipelineHandler(probe, "", zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/pipeline-ok", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
