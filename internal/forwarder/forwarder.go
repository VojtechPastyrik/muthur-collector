package forwarder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

type Forwarder struct {
	url    string
	token  string
	client *http.Client
	logger *zap.Logger
}

func New(url, token string, logger *zap.Logger) *Forwarder {
	return &Forwarder{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
		logger: logger,
	}
}

func (f *Forwarder) Forward(ctx context.Context, payload *pb.AlertPayload) error {
	data, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal protobuf: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			f.logger.Warn("retrying forward",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			time.Sleep(backoff)
		}

		err := f.send(ctx, data)
		if err == nil {
			return nil
		}
		lastErr = err
		f.logger.Error("forward failed",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
	}

	return fmt.Errorf("forward failed after 3 attempts: %w", lastErr)
}

func (f *Forwarder) send(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Collector-Token", f.token)

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("client error: %d (not retryable)", resp.StatusCode)
	}

	return nil
}
