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

type Client struct {
	baseURL     string
	lookbackMin int
	enabled     bool
	httpClient  *http.Client
	logger      *zap.Logger
}

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

func NewClient(baseURL string, lookbackMin int, enabled bool, logger *zap.Logger) *Client {
	return &Client{
		baseURL:     baseURL,
		lookbackMin: lookbackMin,
		enabled:     enabled,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		logger:      logger,
	}
}

func (c *Client) FetchMetrics(ctx context.Context, targetType, namespace string, pods []string, node string) ([]*pb.MetricSeries, error) {
	if !c.enabled {
		return nil, nil
	}

	var queries []metricQuery

	switch targetType {
	case "pod":
		queries = podQueries(namespace, pods)
	case "deployment":
		queries = deploymentQueries(namespace, pods)
	case "node":
		queries = nodeQueries(node)
	case "pvc":
		queries = pvcQueries(namespace)
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

func podQueries(namespace string, pods []string) []metricQuery {
	if len(pods) == 0 {
		return nil
	}
	podFilter := fmt.Sprintf(`namespace=%q, pod=%q, container!="POD"`, namespace, pods[0])
	return []metricQuery{
		{name: "container_memory_working_set_bytes", query: fmt.Sprintf(`container_memory_working_set_bytes{%s}`, podFilter), description: "Working set memory", unit: "bytes"},
		{name: "container_memory_limit_bytes", query: fmt.Sprintf(`container_memory_limit_bytes{%s}`, podFilter), description: "Memory limit", unit: "bytes"},
		{name: "container_cpu_usage_rate", query: fmt.Sprintf(`rate(container_cpu_usage_seconds_total{%s}[5m])`, podFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "container_restarts_total", query: fmt.Sprintf(`container_restarts_total{namespace=%q, pod=%q}`, namespace, pods[0]), description: "Container restarts", unit: "count"},
		{name: "container_network_receive_errors_rate", query: fmt.Sprintf(`rate(container_network_receive_errors_total{namespace=%q, pod=%q}[5m])`, namespace, pods[0]), description: "Network receive errors rate", unit: "count"},
		{name: "container_network_transmit_errors_rate", query: fmt.Sprintf(`rate(container_network_transmit_errors_total{namespace=%q, pod=%q}[5m])`, namespace, pods[0]), description: "Network transmit errors rate", unit: "count"},
	}
}

func deploymentQueries(namespace string, pods []string) []metricQuery {
	if len(pods) == 0 {
		return nil
	}
	podRegex := strings.Join(pods, "|")
	podFilter := fmt.Sprintf(`namespace=%q, pod=~%q, container!="POD"`, namespace, podRegex)
	return []metricQuery{
		{name: "container_memory_working_set_bytes", query: fmt.Sprintf(`container_memory_working_set_bytes{%s}`, podFilter), description: "Working set memory", unit: "bytes"},
		{name: "container_memory_limit_bytes", query: fmt.Sprintf(`container_memory_limit_bytes{%s}`, podFilter), description: "Memory limit", unit: "bytes"},
		{name: "container_cpu_usage_rate", query: fmt.Sprintf(`rate(container_cpu_usage_seconds_total{%s}[5m])`, podFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "container_restarts_total", query: fmt.Sprintf(`container_restarts_total{namespace=%q, pod=~%q}`, namespace, podRegex), description: "Container restarts", unit: "count"},
		{name: "container_network_receive_errors_rate", query: fmt.Sprintf(`rate(container_network_receive_errors_total{namespace=%q, pod=~%q}[5m])`, namespace, podRegex), description: "Network receive errors rate", unit: "count"},
		{name: "container_network_transmit_errors_rate", query: fmt.Sprintf(`rate(container_network_transmit_errors_total{namespace=%q, pod=~%q}[5m])`, namespace, podRegex), description: "Network transmit errors rate", unit: "count"},
		{name: "kube_deployment_status_replicas_available", query: fmt.Sprintf(`kube_deployment_status_replicas_available{namespace=%q}`, namespace), description: "Available replicas", unit: "count"},
		{name: "kube_deployment_status_replicas_unavailable", query: fmt.Sprintf(`kube_deployment_status_replicas_unavailable{namespace=%q}`, namespace), description: "Unavailable replicas", unit: "count"},
	}
}

func nodeQueries(node string) []metricQuery {
	nodeFilter := fmt.Sprintf(`instance=~"%s.*"`, node)
	return []metricQuery{
		{name: "node_memory_MemAvailable_bytes", query: fmt.Sprintf(`node_memory_MemAvailable_bytes{%s}`, nodeFilter), description: "Available memory", unit: "bytes"},
		{name: "node_memory_MemTotal_bytes", query: fmt.Sprintf(`node_memory_MemTotal_bytes{%s}`, nodeFilter), description: "Total memory", unit: "bytes"},
		{name: "node_cpu_usage_rate", query: fmt.Sprintf(`rate(node_cpu_seconds_total{%s, mode!="idle"}[5m])`, nodeFilter), description: "CPU usage rate", unit: "seconds"},
		{name: "node_filesystem_avail_bytes", query: fmt.Sprintf(`node_filesystem_avail_bytes{%s, mountpoint="/"}`, nodeFilter), description: "Available filesystem", unit: "bytes"},
		{name: "node_filesystem_size_bytes", query: fmt.Sprintf(`node_filesystem_size_bytes{%s, mountpoint="/"}`, nodeFilter), description: "Total filesystem", unit: "bytes"},
		{name: "node_load1", query: fmt.Sprintf(`node_load1{%s}`, nodeFilter), description: "1-minute load average", unit: "count"},
	}
}

func pvcQueries(namespace string) []metricQuery {
	return []metricQuery{
		{name: "kubelet_volume_stats_used_bytes", query: fmt.Sprintf(`kubelet_volume_stats_used_bytes{namespace=%q}`, namespace), description: "PVC used bytes", unit: "bytes"},
		{name: "kubelet_volume_stats_capacity_bytes", query: fmt.Sprintf(`kubelet_volume_stats_capacity_bytes{namespace=%q}`, namespace), description: "PVC capacity bytes", unit: "bytes"},
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("prometheus returned %d: %s", resp.StatusCode, string(body))
	}

	var promResp promResponse
	if err := json.NewDecoder(resp.Body).Decode(&promResp); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}

	if promResp.Status != "success" {
		return nil, fmt.Errorf("prometheus status: %s", promResp.Status)
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
