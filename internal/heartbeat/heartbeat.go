// Package heartbeat reports collector liveness to the brain.
//
// Without it, a collector that dies takes its own alarm with it: the alerts it
// would have forwarded simply never arrive, and silence is indistinguishable
// from a quiet cluster. The brain cannot tell "nothing is wrong" from "nothing
// is reporting" unless something keeps saying "I am here".
package heartbeat

import (
	"context"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// Sender is the transport the beat goes out on, implemented by the forwarder.
type Sender interface {
	Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) error
}

// Counter reports how many alerts this process has forwarded. Implemented by
// the pipeline; carried in the beat so the brain can show per-cluster
// throughput without the collector exposing a separate API.
type Counter interface {
	AlertsForwarded() int64
}

// PipelineProbe reports when the cluster's alerting pipeline last proved
// itself. Implemented by Probe; nil when the operator has not routed Watchdog.
type PipelineProbe interface {
	LastSeen() int64
}

// Config tunes the beat.
type Config struct {
	Enabled   bool
	ClusterID string
	Version   string
	// Interval is the beat period. The brain multiplies it to derive its
	// staleness threshold, so a longer interval here directly means a slower
	// outage detection — not a missed one.
	Interval time.Duration
	// Timeout bounds a single beat. Kept well under Interval so a hung brain
	// cannot stack goroutines.
	Timeout time.Duration
}

// Beater sends periodic heartbeats until Stop.
type Beater struct {
	sender    Sender
	counter   Counter
	probe     PipelineProbe
	cfg       Config
	startedAt time.Time
	logger    *zap.Logger

	stopCh chan struct{}
	doneCh chan struct{}
}

// New returns a Beater. A zero or negative Interval falls back to 60s, which
// pairs with the brain's default 3x multiplier for a 3-minute detection floor.
func New(sender Sender, counter Counter, probe PipelineProbe, cfg Config, logger *zap.Logger) *Beater {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Timeout <= 0 || cfg.Timeout >= cfg.Interval {
		cfg.Timeout = cfg.Interval / 3
	}
	return &Beater{
		sender:    sender,
		counter:   counter,
		probe:     probe,
		cfg:       cfg,
		startedAt: time.Now(),
		logger:    logger,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start begins beating. The first beat is sent immediately so a restarted
// collector re-registers without waiting a full interval — that window is
// exactly when an operator is watching to see whether the restart worked.
func (b *Beater) Start() {
	if !b.cfg.Enabled {
		b.logger.Info("heartbeat disabled; the brain cannot detect this collector going down")
		close(b.doneCh)
		return
	}
	b.logger.Info("heartbeat started",
		zap.Duration("interval", b.cfg.Interval),
		zap.String("cluster_id", b.cfg.ClusterID),
	)
	go b.loop()
}

// Stop halts the loop and sends a final beat marked shutting_down, retiring
// the cluster from the brain's watchdog. This is what separates a planned
// teardown (helm uninstall, node drain, rollout) from a crash: without it,
// every deliberate shutdown would page somebody.
func (b *Beater) Stop(ctx context.Context) {
	if !b.cfg.Enabled {
		return
	}
	close(b.stopCh)
	<-b.doneCh
	b.send(ctx, true)
}

func (b *Beater) loop() {
	defer close(b.doneCh)
	b.send(context.Background(), false)

	ticker := time.NewTicker(b.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.send(context.Background(), false)
		}
	}
}

func (b *Beater) send(ctx context.Context, shuttingDown bool) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()

	req := &pb.HeartbeatRequest{
		ClusterId:        b.cfg.ClusterID,
		CollectorVersion: b.cfg.Version,
		StartedAt:        b.startedAt.Unix(),
		IntervalSeconds:  int32(b.cfg.Interval.Seconds()),
		ShuttingDown:     shuttingDown,
	}
	if b.counter != nil {
		req.AlertsForwarded = b.counter.AlertsForwarded()
	}
	// Zero means "Watchdog was never routed here", which the brain reads as
	// "not configured" and never alerts on. Only a once-seen-then-stale probe
	// is evidence of a broken pipeline.
	if b.probe != nil {
		req.PipelineLastSeen = b.probe.LastSeen()
	}

	if err := b.sender.Heartbeat(cctx, req); err != nil {
		// Warn, never fail: a collector that cannot reach the brain must keep
		// doing its real job. The brain's watchdog notices the silence anyway,
		// which is the whole point of the mechanism.
		b.logger.Warn("heartbeat failed",
			zap.Bool("shutting_down", shuttingDown),
			zap.Error(err),
		)
		return
	}
	if shuttingDown {
		b.logger.Info("final heartbeat sent; cluster retired from the brain's watchdog")
	}
}
