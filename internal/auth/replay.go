package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// Replay-protection headers. Mirrored from the brain side; this collector
// emits both on every call to /ingest and /sign-csr so the brain's
// ReplayGuard accepts the request as fresh and single-use.
const (
	HeaderTimestamp = "X-Muthur-Timestamp"
	HeaderNonce     = "X-Muthur-Nonce"
)

// stampReplayHeaders attaches a current Unix timestamp and a fresh 128-bit
// hex nonce to req. Used by every outbound request that the brain
// replay-protects (/ingest, /sign-csr — /bootstrap-cert ignores them but
// receives them too so the call shape is uniform).
//
// Any error during random generation falls back to a time-derived nonce.
// The fallback is strictly worse than a real random nonce but it is still
// monotonic enough that practical replay protection holds: the brain's
// single-use marker rejects a second occurrence.
func stampReplayHeaders(req *http.Request) {
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(HeaderNonce, freshNonce())
}

func freshNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Last-resort fallback: time-based bytes. Worse entropy but the
		// brain's nonce cache still rejects exact repeats within the window.
		now := time.Now().UnixNano()
		for i := 0; i < len(b); i++ {
			b[i] = byte(now >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(b[:])
}
