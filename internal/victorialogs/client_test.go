package victorialogs

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func testClient(t *testing.T, srv *httptest.Server, cfg Config) *Client {
	t.Helper()
	cfg.BaseURL = srv.URL
	if cfg.LookbackMin == 0 {
		cfg.LookbackMin = 15
	}
	if cfg.MaxLines == 0 {
		cfg.MaxLines = 200
	}
	return NewClient(cfg, zap.NewNop())
}

func TestFetchLogsParsesNDJSON(t *testing.T) {
	// VictoriaLogs streams one JSON object per line, not a wrapped envelope.
	body := `{"_msg":"first line","_stream":"{pod=\"api-0\"}","_time":"2026-10-13T10:00:00Z"}
{"_msg":"second line","_stream":"{pod=\"api-0\"}","_time":"2026-10-13T10:00:01Z"}
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{})
	lines, err := c.FetchLogs(context.Background(), "prod", []string{"api-0"})
	if err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if len(lines) != 2 || lines[0] != "first line" || lines[1] != "second line" {
		t.Fatalf("unexpected lines: %q", lines)
	}
}

func TestFetchLogsSkipsMalformedLines(t *testing.T) {
	// One broken line must not discard the lines around it — a truncated
	// record mid-stream is a VictoriaLogs reality, not a reason to lose the
	// whole excerpt.
	body := "{\"_msg\":\"good\"}\nnot json at all\n{\"_msg\":\"also good\"}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{})
	lines, err := c.FetchLogs(context.Background(), "prod", []string{"api-0"})
	if err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected the two decodable lines, got %q", lines)
	}
}

func TestQueryCarriesStreamSelectorAndExtraFilter(t *testing.T) {
	var gotQuery, gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		gotQuery = form.Get("query")
		gotLimit = form.Get("limit")
		w.Write([]byte("{\"_msg\":\"x\"}\n"))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{ExtraFilter: `cluster:="prod"`, MaxLines: 50})
	if _, err := c.FetchLogs(context.Background(), "ns1", []string{"pod-a"}); err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}

	// LogsQL accepts Loki's stream-selector syntax verbatim; that shared shape
	// is the only thing the two backends have in common on the read path.
	if !strings.Contains(gotQuery, `{namespace="ns1", pod="pod-a"}`) {
		t.Fatalf("stream selector missing from query: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, `cluster:="prod"`) {
		t.Fatalf("extra filter missing from query: %q", gotQuery)
	}
	if gotLimit != "50" {
		t.Fatalf("limit not propagated, got %q", gotLimit)
	}
}

func TestTenantHeadersSentWhenConfigured(t *testing.T) {
	var account, project string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account = r.Header.Get("AccountID")
		project = r.Header.Get("ProjectID")
		w.Write([]byte("{\"_msg\":\"x\"}\n"))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{AccountID: "12", ProjectID: "34"})
	if _, err := c.FetchLogs(context.Background(), "ns", []string{"pod"}); err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if account != "12" || project != "34" {
		t.Fatalf("tenant headers not sent: AccountID=%q ProjectID=%q", account, project)
	}
}

func TestNoTenantHeadersWhenUnset(t *testing.T) {
	// A single-tenant VictoriaLogs rejects nothing, but sending AccountID: ""
	// would still be a lie about the deployment shape.
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["Accountid"]
		w.Write([]byte("{\"_msg\":\"x\"}\n"))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{})
	if _, err := c.FetchLogs(context.Background(), "ns", []string{"pod"}); err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if present {
		t.Fatal("AccountID header must be absent when no tenant is configured")
	}
}

func TestFetchLogsCapsAtMaxLines(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 50; i++ {
		body.WriteString("{\"_msg\":\"line\"}\n")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body.String()))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{MaxLines: 10})
	lines, err := c.FetchLogs(context.Background(), "ns", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if len(lines) > 10 {
		t.Fatalf("expected at most 10 lines, got %d", len(lines))
	}
}

func TestFetchLogsSurvivesBackendError(t *testing.T) {
	// One failing pod must not fail the whole enrichment: a partial excerpt
	// still beats forwarding the alert bare.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "broken") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("boom"))
			return
		}
		w.Write([]byte("{\"_msg\":\"fine\"}\n"))
	}))
	defer srv.Close()

	c := testClient(t, srv, Config{})
	lines, err := c.FetchLogs(context.Background(), "ns", []string{"broken", "healthy"})
	if err != nil {
		t.Fatalf("a per-pod failure must not surface as an error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "fine" {
		t.Fatalf("expected the healthy pod's line, got %q", lines)
	}
}

func TestFetchLogsNoPods(t *testing.T) {
	c := NewClient(Config{BaseURL: "http://unused"}, zap.NewNop())
	lines, err := c.FetchLogs(context.Background(), "ns", nil)
	if err != nil || lines != nil {
		t.Fatalf("expected no work and no error, got %q / %v", lines, err)
	}
}

func TestNameIdentifiesBackend(t *testing.T) {
	if got := NewClient(Config{}, zap.NewNop()).Name(); got != "victorialogs" {
		t.Fatalf("Name() = %q", got)
	}
}
