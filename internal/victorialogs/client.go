// Package victorialogs fetches log excerpts from VictoriaLogs.
//
// This is a separate client rather than a Loki URL swap because VictoriaLogs'
// Loki compatibility is ingestion-only: it accepts /insert/loki/api/v1/push,
// but it has no /loki/api/v1/query_range. Reads go to /select/logsql/query,
// speak LogsQL instead of LogQL, and stream newline-delimited JSON objects
// rather than a wrapped result envelope.
//
// The one thing that does carry over is the stream selector: LogsQL accepts
// Loki's {label="value"} syntax verbatim, so the query this client builds is
// textually the same as the Loki client's.
package victorialogs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// maxLineBytes bounds a single scanned log line. VictoriaLogs streams one JSON
// object per line and a stacktrace-heavy line can be large; bufio.Scanner's
// 64 KiB default would abort the whole stream on the first long line.
const maxLineBytes = 1 << 20

// Client reads logs from a VictoriaLogs instance.
type Client struct {
	baseURL     string
	lookbackMin int
	maxLines    int
	// extraFilter is an optional LogsQL fragment ANDed into every query, e.g.
	// a cluster selector when one VictoriaLogs instance holds several clusters'
	// logs. Without it a shared instance returns another cluster's pods for the
	// same namespace/pod name.
	extraFilter string
	accountID   string
	projectID   string
	httpClient  *http.Client
	logger      *zap.Logger
}

// entry is one line of the NDJSON response. Only _msg is used; the rest of the
// fields are the stream labels, which the collector already knows.
type entry struct {
	Msg string `json:"_msg"`
}

// Config carries the connection settings.
type Config struct {
	BaseURL     string
	LookbackMin int
	MaxLines    int
	ExtraFilter string
	AccountID   string
	ProjectID   string
}

// NewClient returns a VictoriaLogs client.
func NewClient(cfg Config, logger *zap.Logger) *Client {
	return &Client{
		baseURL:     strings.TrimRight(cfg.BaseURL, "/"),
		lookbackMin: cfg.LookbackMin,
		maxLines:    cfg.MaxLines,
		extraFilter: strings.TrimSpace(cfg.ExtraFilter),
		accountID:   cfg.AccountID,
		projectID:   cfg.ProjectID,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		logger:      logger,
	}
}

// Name identifies the backend in metrics and logs.
func (c *Client) Name() string { return "victorialogs" }

// FetchLogs returns recent log lines for the given pods, newest first, capped
// at the configured maximum. A failure on one pod is logged and skipped rather
// than failing the whole enrichment: a partial excerpt still beats none.
func (c *Client) FetchLogs(ctx context.Context, namespace string, pods []string) ([]string, error) {
	if len(pods) == 0 {
		return nil, nil
	}

	var allLines []string
	for _, pod := range pods {
		lines, err := c.fetchPodLogs(ctx, namespace, pod)
		if err != nil {
			c.logger.Warn("failed to fetch logs from VictoriaLogs",
				zap.String("pod", pod), zap.Error(err))
			continue
		}
		allLines = append(allLines, lines...)
		if len(allLines) >= c.maxLines {
			allLines = allLines[:c.maxLines]
			break
		}
	}
	return allLines, nil
}

func (c *Client) fetchPodLogs(ctx context.Context, namespace, pod string) ([]string, error) {
	now := time.Now()
	start := now.Add(-time.Duration(c.lookbackMin) * time.Minute)

	query := fmt.Sprintf(`{namespace=%q, pod=%q}`, namespace, pod)
	if c.extraFilter != "" {
		query += " " + c.extraFilter
	}

	params := url.Values{}
	params.Set("query", query)
	// RFC3339 is one of the accepted timestamp formats and is far easier to
	// read in a request log than epoch nanoseconds. end is exclusive.
	params.Set("start", start.Format(time.RFC3339Nano))
	params.Set("end", now.Format(time.RFC3339Nano))
	params.Set("limit", fmt.Sprintf("%d", c.maxLines))

	// POST with a form body rather than a query string: a LogsQL query with a
	// long extra filter can exceed what intermediaries allow in a URL.
	reqURL := c.baseURL + "/select/logsql/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.accountID != "" {
		req.Header.Set("AccountID", c.accountID)
	}
	if c.projectID != "" {
		req.Header.Set("ProjectID", c.projectID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("victorialogs request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("victorialogs returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e entry
		if err := json.Unmarshal(raw, &e); err != nil {
			// A single malformed line must not discard the lines around it.
			continue
		}
		if e.Msg == "" {
			continue
		}
		lines = append(lines, e.Msg)
		if len(lines) >= c.maxLines {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		// Partial results are still useful — return what was read before the
		// stream broke rather than discarding it.
		c.logger.Warn("victorialogs stream ended early",
			zap.String("pod", pod), zap.Int("lines", len(lines)), zap.Error(err))
	}

	return lines, nil
}
