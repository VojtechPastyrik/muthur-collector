package forwarder

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

func TestForwarder_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Error("expected application/x-protobuf content type")
		}
		if r.Header.Get("X-Collector-Token") != "test-token" {
			t.Errorf("expected token test-token, got %s", r.Header.Get("X-Collector-Token"))
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("expected non-empty body")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	f := New(server.URL, "test-token", zap.NewNop())
	f.client = server.Client()

	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "TestAlert",
	}

	err := f.Forward(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestForwarder_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	f := New(server.URL, "bad-token", zap.NewNop())
	f.client = server.Client()

	err := f.Forward(context.Background(), &pb.AlertPayload{})
	if err == nil {
		t.Error("expected error on 401")
	}
}

func TestForwarder_ServerErrorRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	f := New(server.URL, "token", zap.NewNop())
	f.client = server.Client()

	err := f.Forward(context.Background(), &pb.AlertPayload{})
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}
