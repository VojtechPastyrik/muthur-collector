package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

type Client struct {
	baseURL     string
	lookbackMin int
	maxLines    int
	httpClient  *http.Client
	logger      *zap.Logger
}

type response struct {
	Status string `json:"status"`
	Data   data   `json:"data"`
}

type data struct {
	ResultType string   `json:"resultType"`
	Result     []stream `json:"result"`
}

type stream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

func NewClient(baseURL string, lookbackMin, maxLines int, logger *zap.Logger) *Client {
	return &Client{
		baseURL:     baseURL,
		lookbackMin: lookbackMin,
		maxLines:    maxLines,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		logger:      logger,
	}
}

func (c *Client) FetchLogs(ctx context.Context, namespace string, pods []string) ([]string, error) {
	if len(pods) == 0 {
		return nil, nil
	}

	var allLines []string

	for _, pod := range pods {
		lines, err := c.fetchPodLogs(ctx, namespace, pod)
		if err != nil {
			c.logger.Warn("failed to fetch logs from Loki",
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

	params := url.Values{}
	params.Set("query", query)
	params.Set("start", fmt.Sprintf("%d", start.UnixNano()))
	params.Set("end", fmt.Sprintf("%d", now.UnixNano()))
	params.Set("limit", fmt.Sprintf("%d", c.maxLines))
	params.Set("direction", "backward")

	reqURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("loki returned %d: %s", resp.StatusCode, string(body))
	}

	var lokiResp response
	if err := json.NewDecoder(resp.Body).Decode(&lokiResp); err != nil {
		return nil, fmt.Errorf("decode loki response: %w", err)
	}

	if lokiResp.Status != "success" {
		return nil, fmt.Errorf("loki status: %s", lokiResp.Status)
	}

	var lines []string
	for _, s := range lokiResp.Data.Result {
		for _, v := range s.Values {
			if len(v) >= 2 {
				lines = append(lines, v[1])
			}
		}
	}

	return lines, nil
}
