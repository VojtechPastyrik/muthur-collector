package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// Client queries a Prometheus-compatible range API. VictoriaMetrics speaks the
// same /api/v1/query_range with a PromQL superset, so it is served by this same
// client under a different name — the only differences are the tenant headers
// and, on the cluster build, the /select/<accountID>/prometheus URL prefix the
// operator puts in the configured base URL.
type Client struct {
	baseURL     string
	lookbackMin int
	enabled     bool
	name        string
	// extraSelector is an optional label matcher ANDed into every query, e.g.
	// `cluster="prod"`. Required when one Prometheus/VictoriaMetrics instance
	// holds several clusters' metrics: without it, a query for namespace/pod
	// matches the same-named pod in a different cluster.
	extraSelector string
	headers       map[string]string
	httpClient    *http.Client
	logger        *zap.Logger
}

// Backend names reported by Name().
const (
	BackendPrometheus     = "prometheus"
	BackendVictoriaMetric = "victoriametrics"
)

type promResponse struct {
	Status string   `json:"status"`
	Data   promData `json:"data"`
}

type promData struct {
	ResultType string            `json:"resultType"`
	Result     []json.RawMessage `json:"result"`
}

type matrixResult struct {
	Metric map[string]string `json:"metric"`
	Values [][]interface{}   `json:"values"`
}

// Config carries the connection settings shared by both backends.
type Config struct {
	BaseURL       string
	LookbackMin   int
	Enabled       bool
	ExtraSelector string
	// AccountID / ProjectID are VictoriaMetrics tenant headers. They are only
	// honoured by a cluster build started with -enableMultitenancyViaHeaders
	// (default since v1.150); otherwise the tenant belongs in the URL path.
	AccountID string
	ProjectID string
}

// NewClient returns a client for a stock Prometheus endpoint.
func NewClient(baseURL string, lookbackMin int, enabled bool, logger *zap.Logger) *Client {
	return newClient(Config{BaseURL: baseURL, LookbackMin: lookbackMin, Enabled: enabled}, BackendPrometheus, logger)
}

// NewVictoriaMetrics returns a client for a VictoriaMetrics endpoint. The base
// URL must already contain the tenant prefix on a cluster deployment, e.g.
// http://vmselect:8481/select/0/prometheus.
func NewVictoriaMetrics(cfg Config, logger *zap.Logger) *Client {
	return newClient(cfg, BackendVictoriaMetric, logger)
}

func newClient(cfg Config, name string, logger *zap.Logger) *Client {
	headers := map[string]string{}
	if cfg.AccountID != "" {
		headers["AccountID"] = cfg.AccountID
	}
	if cfg.ProjectID != "" {
		headers["ProjectID"] = cfg.ProjectID
	}
	return &Client{
		baseURL:       strings.TrimRight(cfg.BaseURL, "/"),
		lookbackMin:   cfg.LookbackMin,
		enabled:       cfg.Enabled,
		name:          name,
		extraSelector: strings.TrimSpace(strings.Trim(strings.TrimSpace(cfg.ExtraSelector), ",")),
		headers:       headers,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		logger:        logger,
	}
}

// Name identifies the backend in metrics and logs.
func (c *Client) Name() string { return c.name }

func (c *Client) FetchMetrics(ctx context.Context, targetType, namespace string, pods []string, node string) ([]*pb.MetricSeries, error) {
	if !c.enabled {
		return nil, nil
	}

	var queries []metricQuery

	switch targetType {
	case "pod":
		queries = podQueries(namespace, pods, c.extraSelector)
	case "deployment":
		queries = deploymentQueries(namespace, pods, c.extraSelector)
	case "node":
		queries = nodeQueries(node, c.extraSelector)
	case "pvc":
		queries = pvcQueries(namespace, c.extraSelector)
	default:
		c.logger.Warn("no metrics for target type", zap.String("type", targetType))
		return nil, nil
	}

	var series []*pb.MetricSeries
	for _, q := range queries {
		s, err := c.queryRange(ctx, q)
		if err != nil {
			c.logger.Warn("metric query failed",
				zap.String("metric", q.name), zap.Error(err))
			continue
		}
		if s != nil {
			series = append(series, s)
		}
	}

	return series, nil
}

type metricQuery struct {
	name        string
	query       string
	description string
	unit        string
}

// sel appends the configured extra selector to a label-matcher list. Empty
// extra selector leaves the matcher byte-for-byte as it was.
func sel(filter, extra string) string {
	if extra == "" {
		return filter
	}
	return filter + ", " + extra
}

func podQueries(namespace string, pods []string, extra string) []metricQuery {
	if len(pods) == 0 {
		return nil
	}
	podFilter := sel(fmt.Sprintf(`namespace=%q, pod=%q, container!="POD"`, namespace, pods[0]), extra)
	nameFilter := sel(fmt.Sprintf(`namespace=%q, pod=%q`, namespace, pods[0]), extra)
	return []metricQuery{
		{name: "container_memory_working_set_bytes", query: fmt.Sprintf(`container_memory_working_set_bytes{%s}`, podFilter), description: "Working set memory", unit: "bytes"},
		{name: "container_memory_limit_bytes", query: fmt.Sprintf(`container_memory_limit_bytes{%s}`, podFilter), description: "Memory limit", unit: "bytes"},
		{name: "container_cpu_usage_rate", query: fmt.Sprintf(`rate(container_cpu_usage_seconds_total{%s}[5m])`, podFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "container_restarts_total", query: fmt.Sprintf(`container_restarts_total{%s}`, nameFilter), description: "Container restarts", unit: "count"},
		{name: "container_network_receive_errors_rate", query: fmt.Sprintf(`rate(container_network_receive_errors_total{%s}[5m])`, nameFilter), description: "Network receive errors rate", unit: "count"},
		{name: "container_network_transmit_errors_rate", query: fmt.Sprintf(`rate(container_network_transmit_errors_total{%s}[5m])`, nameFilter), description: "Network transmit errors rate", unit: "count"},
	}
}

func deploymentQueries(namespace string, pods []string, extra string) []metricQuery {
	if len(pods) == 0 {
		return nil
	}
	podRegex := strings.Join(pods, "|")
	podFilter := sel(fmt.Sprintf(`namespace=%q, pod=~%q, container!="POD"`, namespace, podRegex), extra)
	nameFilter := sel(fmt.Sprintf(`namespace=%q, pod=~%q`, namespace, podRegex), extra)
	nsFilter := sel(fmt.Sprintf(`namespace=%q`, namespace), extra)
	return []metricQuery{
		{name: "container_memory_working_set_bytes", query: fmt.Sprintf(`container_memory_working_set_bytes{%s}`, podFilter), description: "Working set memory", unit: "bytes"},
		{name: "container_memory_limit_bytes", query: fmt.Sprintf(`container_memory_limit_bytes{%s}`, podFilter), description: "Memory limit", unit: "bytes"},
		{name: "container_cpu_usage_rate", query: fmt.Sprintf(`rate(container_cpu_usage_seconds_total{%s}[5m])`, podFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "container_restarts_total", query: fmt.Sprintf(`container_restarts_total{%s}`, nameFilter), description: "Container restarts", unit: "count"},
		{name: "container_network_receive_errors_rate", query: fmt.Sprintf(`rate(container_network_receive_errors_total{%s}[5m])`, nameFilter), description: "Network receive errors rate", unit: "count"},
		{name: "container_network_transmit_errors_rate", query: fmt.Sprintf(`rate(container_network_transmit_errors_total{%s}[5m])`, nameFilter), description: "Network transmit errors rate", unit: "count"},
		{name: "kube_deployment_status_replicas_available", query: fmt.Sprintf(`kube_deployment_status_replicas_available{%s}`, nsFilter), description: "Available replicas", unit: "count"},
		{name: "kube_deployment_status_replicas_unavailable", query: fmt.Sprintf(`kube_deployment_status_replicas_unavailable{%s}`, nsFilter), description: "Unavailable replicas", unit: "count"},
	}
}

func nodeQueries(node, extra string) []metricQuery {
	nodeFilter := sel(fmt.Sprintf(`instance=~"%s.*"`, node), extra)
	return []metricQuery{
		{name: "node_memory_MemAvailable_bytes", query: fmt.Sprintf(`node_memory_MemAvailable_bytes{%s}`, nodeFilter), description: "Available memory", unit: "bytes"},
		{name: "node_memory_MemTotal_bytes", query: fmt.Sprintf(`node_memory_MemTotal_bytes{%s}`, nodeFilter), description: "Total memory", unit: "bytes"},
		{name: "node_cpu_usage_rate", query: fmt.Sprintf(`rate(node_cpu_seconds_total{%s, mode!="idle"}[5m])`, nodeFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "node_filesystem_avail_bytes", query: fmt.Sprintf(`node_filesystem_avail_bytes{%s, mountpoint="/"}`, nodeFilter), description: "Available filesystem", unit: "bytes"},
		{name: "node_filesystem_size_bytes", query: fmt.Sprintf(`node_filesystem_size_bytes{%s, mountpoint="/"}`, nodeFilter), description: "Total filesystem", unit: "bytes"},
		{name: "node_load1", query: fmt.Sprintf(`node_load1{%s}`, nodeFilter), description: "1-minute load average", unit: "count"},
	}
}

func pvcQueries(namespace, extra string) []metricQuery {
	nsFilter := sel(fmt.Sprintf(`namespace=%q`, namespace), extra)
	return []metricQuery{
		{name: "kubelet_volume_stats_used_bytes", query: fmt.Sprintf(`kubelet_volume_stats_used_bytes{%s}`, nsFilter), description: "PVC used bytes", unit: "bytes"},
		{name: "kubelet_volume_stats_capacity_bytes", query: fmt.Sprintf(`kubelet_volume_stats_capacity_bytes{%s}`, nsFilter), description: "PVC capacity bytes", unit: "bytes"},
	}
}

func (c *Client) queryRange(ctx context.Context, q metricQuery) (*pb.MetricSeries, error) {
	now := time.Now()
	start := now.Add(-time.Duration(c.lookbackMin) * time.Minute)

	params := url.Values{}
	params.Set("query", q.query)
	params.Set("start", fmt.Sprintf("%f", float64(start.Unix())))
	params.Set("end", fmt.Sprintf("%f", float64(now.Unix())))
	params.Set("step", "60s")

	reqURL := fmt.Sprintf("%s/api/v1/query_range?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", c.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s returned %d: %s", c.name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var promResp promResponse
	if err := json.NewDecoder(resp.Body).Decode(&promResp); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", c.name, err)
	}

	if promResp.Status != "success" {
		return nil, fmt.Errorf("%s status: %s", c.name, promResp.Status)
	}

	series := &pb.MetricSeries{
		MetricName:  q.name,
		Description: q.description,
		Unit:        q.unit,
	}

	for _, raw := range promResp.Data.Result {
		var result matrixResult
		if err := json.Unmarshal(raw, &result); err != nil {
			continue
		}
		for _, v := range result.Values {
			if len(v) < 2 {
				continue
			}
			ts, ok := v[0].(float64)
			if !ok {
				continue
			}
			valStr, ok := v[1].(string)
			if !ok {
				continue
			}
			val, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			series.Points = append(series.Points, &pb.DataPoint{
				Timestamp: int64(ts),
				Value:     val,
			})
		}
		break // take first result only
	}

	return series, nil
}
