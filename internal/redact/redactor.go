package redact

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/metrics"
)

// Default size guards. Redaction is a security boundary feeding untrusted log
// text to an LLM, so these fail CLOSED: content that cannot be safely bounded
// is dropped, never forwarded raw.
const (
	defaultMaxLineBytes  = 8 * 1024   // 8 KiB per line
	defaultMaxTotalBytes = 256 * 1024 // 256 KiB per payload
)

// droppedLineMarker replaces a line that is dropped by a size guard. It is a
// constant containing no log-derived bytes, so it is always safe to forward.
const droppedLineMarker = "[redacted: line dropped by size guard]"

type Stats struct {
	TotalLines    int
	RedactedLines int
	DroppedLines  int
	Replacements  int
	ByCategory    map[string]int
}

type Redactor struct {
	patterns      []pattern
	maxLineBytes  int
	maxTotalBytes int
	logStats      bool
	logger        *zap.Logger
}

// New builds a Redactor. maxLineBytes caps an individual log line; maxTotalBytes
// caps the cumulative redacted payload. A non-positive value falls back to the
// safe default — the guards can be tuned but never disabled, because forwarding
// an unbounded line means trusting regex coverage on text we cannot inspect.
func New(extraPatterns string, logStats bool, maxLineBytes, maxTotalBytes int, logger *zap.Logger) *Redactor {
	patterns := make([]pattern, len(builtinPatterns))
	copy(patterns, builtinPatterns)

	extra := parseExtraPatterns(extraPatterns, logger)
	patterns = append(patterns, extra...)

	if maxLineBytes <= 0 {
		maxLineBytes = defaultMaxLineBytes
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = defaultMaxTotalBytes
	}

	logger.Info("initialized redactor",
		zap.Int("builtin_patterns", len(builtinPatterns)),
		zap.Int("custom_patterns", len(extra)),
		zap.Int("max_line_bytes", maxLineBytes),
		zap.Int("max_total_bytes", maxTotalBytes),
	)

	return &Redactor{
		patterns:      patterns,
		maxLineBytes:  maxLineBytes,
		maxTotalBytes: maxTotalBytes,
		logStats:      logStats,
		logger:        logger,
	}
}

func (r *Redactor) Redact(lines []string) ([]string, *Stats) {
	stats := &Stats{
		TotalLines: len(lines),
		ByCategory: make(map[string]int),
	}

	result := make([]string, 0, len(lines))
	totalBytes := 0
	for _, line := range lines {
		// Fail closed: a line longer than the per-line cap cannot be trusted to
		// have been fully redacted (a secret could hide past the region our
		// line-oriented patterns reason about), so drop its content entirely.
		if len(line) > r.maxLineBytes {
			result = append(result, droppedLineMarker)
			stats.DroppedLines++
			metrics.LinesDropped.WithLabelValues("oversize").Inc()
			continue
		}

		redacted, lineReplacements := r.redactLine(line, stats)

		// Fail closed on the cumulative budget: once the payload is full, drop
		// the rest rather than ship an unbounded blob (which would also inflate
		// the downstream LLM token bill).
		if totalBytes+len(redacted) > r.maxTotalBytes {
			stats.DroppedLines += stats.TotalLines - len(result)
			metrics.LinesDropped.WithLabelValues("budget").Inc()
			result = append(result, fmt.Sprintf("[redacted: %d further lines dropped — payload byte budget reached]", stats.TotalLines-len(result)))
			break
		}
		totalBytes += len(redacted)

		result = append(result, redacted)
		if lineReplacements > 0 {
			stats.RedactedLines++
		}
	}

	if r.logStats {
		r.logger.Info("redaction stats",
			zap.Int("total_lines", stats.TotalLines),
			zap.Int("redacted_lines", stats.RedactedLines),
			zap.Int("dropped_lines", stats.DroppedLines),
			zap.Int("total_replacements", stats.Replacements),
			zap.Any("by_category", stats.ByCategory),
		)
	}

	return result, stats
}

func (r *Redactor) redactLine(line string, stats *Stats) (string, int) {
	replacements := 0
	for _, p := range r.patterns {
		matches := p.regex.FindAllStringIndex(line, -1)
		if len(matches) > 0 {
			line = p.regex.ReplaceAllString(line, p.replacement)
			replacements += len(matches)
			stats.Replacements += len(matches)
			stats.ByCategory[p.category] += len(matches)
		}
	}
	return line, replacements
}
