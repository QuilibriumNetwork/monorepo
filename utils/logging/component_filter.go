package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap/zapcore"
)

// componentFilterCore wraps a zapcore.Core and applies per-component log level
// filtering based on the logger name (set via .Named() calls).
type componentFilterCore struct {
	zapcore.Core
	filters   map[string]zapcore.Level
	baseLevel zapcore.Level
}

// NewComponentFilterCore wraps base with per-component level filtering.
// If filters is empty, returns base unchanged (zero overhead).
func NewComponentFilterCore(
	base zapcore.Core,
	baseLevel zapcore.Level,
	filters map[string]zapcore.Level,
) zapcore.Core {
	if len(filters) == 0 {
		return base
	}
	return &componentFilterCore{
		Core:      base,
		filters:   filters,
		baseLevel: baseLevel,
	}
}

func (c *componentFilterCore) Enabled(level zapcore.Level) bool {
	return c.Core.Enabled(level)
}

func (c *componentFilterCore) Check(
	entry zapcore.Entry,
	ce *zapcore.CheckedEntry,
) *zapcore.CheckedEntry {
	effectiveLevel := c.baseLevel
	if lvl, ok := c.matchLevel(entry.LoggerName); ok {
		effectiveLevel = lvl
	}
	if entry.Level < effectiveLevel {
		return ce
	}
	return c.Core.Check(entry, ce)
}

func (c *componentFilterCore) With(fields []zapcore.Field) zapcore.Core {
	return &componentFilterCore{
		Core:      c.Core.With(fields),
		filters:   c.filters,
		baseLevel: c.baseLevel,
	}
}

// matchLevel finds the effective level for a logger name.
// Exact match takes priority, then longest prefix match (prefix + ".").
func (c *componentFilterCore) matchLevel(
	name string,
) (zapcore.Level, bool) {
	if lvl, ok := c.filters[name]; ok {
		return lvl, true
	}
	best := ""
	for prefix := range c.filters {
		if strings.HasPrefix(name, prefix+".") && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best != "" {
		return c.filters[best], true
	}
	return zapcore.DebugLevel, false
}

// ParseLogFilters converts a map of component name → level string into
// a map of component name → zapcore.Level. Invalid level strings are
// reported to stderr and skipped.
func ParseLogFilters(raw map[string]string) map[string]zapcore.Level {
	if len(raw) == 0 {
		return nil
	}
	result := make(map[string]zapcore.Level, len(raw))
	for name, levelStr := range raw {
		var lvl zapcore.Level
		if err := lvl.UnmarshalText([]byte(levelStr)); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: ignoring invalid log filter level %q for component %q\n",
				levelStr, name,
			)
			continue
		}
		result[name] = lvl
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
