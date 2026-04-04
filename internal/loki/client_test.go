package loki

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestClient_FetchLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if query == "" {
			t.Error("expected query parameter")
		}

		resp := response{
			Status: "success",
			Data: data{
				ResultType: "streams",
				Result: []stream{
					{
						Stream: map[string]string{"pod": "app-123"},
						Values: [][]string{
							{"1700000000000000000", "log line 1"},
							{"1700000001000000000", "log line 2"},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewClient(server.URL, 15, 200, zap.NewNop())
	c.httpClient = server.Client()

	logs, err := c.FetchLogs(context.Background(), "default", []string{"app-123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(logs))
	}
	if logs[0] != "log line 1" {
		t.Errorf("expected 'log line 1', got %q", logs[0])
	}
}

func TestClient_FetchLogs_NoPods(t *testing.T) {
	c := NewClient("http://localhost", 15, 200, zap.NewNop())

	logs, err := c.FetchLogs(context.Background(), "default", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logs != nil {
		t.Error("expected nil for no pods")
	}
}

func TestClient_FetchLogs_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	c := NewClient(server.URL, 15, 200, zap.NewNop())
	c.httpClient = server.Client()

	logs, err := c.FetchLogs(context.Background(), "default", []string{"app-123"})
	// Should not return error — just empty logs with warning
	if err != nil {
		t.Fatalf("expected no error (graceful), got: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs on error, got %d", len(logs))
	}
}
