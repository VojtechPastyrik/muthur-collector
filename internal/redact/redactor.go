package redact

import (
	"go.uber.org/zap"
)

type Stats struct {
	TotalLines     int
	RedactedLines  int
	Replacements   int
	ByCategory     map[string]int
}

type Redactor struct {
	patterns []pattern
	logStats bool
	logger   *zap.Logger
}

func New(extraPatterns string, logStats bool, logger *zap.Logger) *Redactor {
	patterns := make([]pattern, len(builtinPatterns))
	copy(patterns, builtinPatterns)

	extra := parseExtraPatterns(extraPatterns, logger)
	patterns = append(patterns, extra...)

	logger.Info("initialized redactor",
		zap.Int("builtin_patterns", len(builtinPatterns)),
		zap.Int("custom_patterns", len(extra)),
	)

	return &Redactor{
		patterns: patterns,
		logStats: logStats,
		logger:   logger,
	}
}

func (r *Redactor) Redact(lines []string) ([]string, *Stats) {
	stats := &Stats{
		TotalLines: len(lines),
		ByCategory: make(map[string]int),
	}

	result := make([]string, len(lines))
	for i, line := range lines {
		redacted, lineReplacements := r.redactLine(line, stats)
		result[i] = redacted
		if lineReplacements > 0 {
			stats.RedactedLines++
		}
	}

	if r.logStats {
		r.logger.Info("redaction stats",
			zap.Int("total_lines", stats.TotalLines),
			zap.Int("redacted_lines", stats.RedactedLines),
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
