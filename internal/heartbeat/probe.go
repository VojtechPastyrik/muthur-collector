package heartbeat

import (
	"sync/atomic"
	"time"
)

// Probe records the last time the cluster's own alerting pipeline proved it
// works, by delivering a Watchdog alert all the way to the collector.
//
// The distinction it buys is the whole point of routing Watchdog here. A
// heartbeat says "this process is running" — which stays true while Prometheus
// is crashlooping, while AlertManager drops everything on the floor, and while
// a bad route sends every alert to a receiver that does not exist. In each of
// those cases the collector is healthy, no alert ever arrives, and without
// this probe the brain has no way to tell that from a quiet night.
//
// Watchdog is the right signal because it fires continuously by design and
// travels the same path a real alert would: rules evaluate it, AlertManager
// groups and routes it, and the webhook delivers it. Its arrival proves every
// link; its absence condemns the chain without having to name which link broke.
type Probe struct {
	// lastSeen holds a unix timestamp. Atomic because the webhook handler
	// writes it on an arbitrary request goroutine while the beater reads it
	// on its ticker.
	lastSeen atomic.Int64
}

// NewProbe returns a probe that has not yet seen the pipeline work. It starts
// at zero deliberately: an operator who never routed Watchdog must not have
// the brain page them about a pipeline they did not opt into, and zero is the
// value the brain treats as "not configured".
func NewProbe() *Probe { return &Probe{} }

// Touch records that a Watchdog alert arrived.
func (p *Probe) Touch(now time.Time) { p.lastSeen.Store(now.Unix()) }

// LastSeen returns the unix timestamp of the last Watchdog arrival, or 0 when
// none has ever arrived.
func (p *Probe) LastSeen() int64 { return p.lastSeen.Load() }
