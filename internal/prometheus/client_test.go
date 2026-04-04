package prometheus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestClient_FetchMetrics_Pod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := promResponse{
			Status: "success",
			Data: promData{
				ResultType: "matrix",
				Result: []json.RawMessage{
					json.RawMessage(`{"metric":{"__name__":"test"},"values":[[1700000000,"123.45"],[1700000060,"130.00"]]}`),
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewClient(server.URL, 30, true, zap.NewNop())
	c.httpClient = server.Client()

	series, err := c.FetchMetrics(context.Background(), "pod", "default", []string{"app-123"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(series) == 0 {
		t.Fatal("expected at least one metric series")
	}
	if len(series[0].Points) != 2 {
		t.Errorf("expected 2 data points, got %d", len(series[0].Points))
	}
}

func TestClient_FetchMetrics_Disabled(t *testing.T) {
	c := NewClient("http://localhost", 30, false, zap.NewNop())

	series, err := c.FetchMetrics(context.Background(), "pod", "default", []string{"app"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if series != nil {
		t.Error("expected nil when disabled")
	}
}

func TestClient_FetchMetrics_Unknown(t *testing.T) {
	c := NewClient("http://localhost", 30, true, zap.NewNop())

	series, err := c.FetchMetrics(context.Background(), "unknown", "default", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if series != nil {
		t.Error("expected nil for unknown target type")
	}
}
