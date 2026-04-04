package redact

import (
	"regexp"
	"strings"

	"go.uber.org/zap"
)

func parseExtraPatterns(raw string, logger *zap.Logger) []pattern {
	if raw == "" {
		return nil
	}

	var extra []pattern
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("invalid custom redact pattern, skipping",
				zap.String("pattern", p), zap.Error(err))
			continue
		}
		extra = append(extra, pattern{
			category:    "custom",
			name:        p,
			regex:       re,
			replacement: "[redacted]",
		})
	}
	return extra
}
