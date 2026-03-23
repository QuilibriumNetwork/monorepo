package logging

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func buildFilteredLogger(
	baseLevel zapcore.Level,
	filters map[string]zapcore.Level,
) (*zap.Logger, *observer.ObservedLogs) {
	// Compute the minimum level across base and all filters.
	coreLevel := baseLevel
	for _, lvl := range filters {
		if lvl < coreLevel {
			coreLevel = lvl
		}
	}

	obs, logs := observer.New(coreLevel)
	core := NewComponentFilterCore(obs, baseLevel, filters)
	return zap.New(core), logs
}

func TestNoFilters_PassthroughAtBaseLevel(t *testing.T) {
	obs, logs := observer.New(zapcore.InfoLevel)
	// With empty filters, NewComponentFilterCore returns the base core unchanged.
	core := NewComponentFilterCore(obs, zapcore.InfoLevel, nil)
	logger := zap.New(core).Named("anything")

	logger.Debug("should be filtered")
	logger.Info("should appear")

	if logs.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", logs.Len())
	}
	if logs.All()[0].Message != "should appear" {
		t.Fatalf("unexpected message: %s", logs.All()[0].Message)
	}
}

func TestExactMatch_ComponentAtDebug(t *testing.T) {
	logger, logs := buildFilteredLogger(zapcore.InfoLevel, map[string]zapcore.Level{
		"bootstrap": zapcore.DebugLevel,
	})

	logger.Named("bootstrap").Debug("boot debug")
	logger.Named("bootstrap").Info("boot info")
	logger.Named("other").Debug("other debug")
	logger.Named("other").Info("other info")

	entries := logs.All()
	if len(entries) != 3 {
		t.Fatalf("expected 3 log entries, got %d", len(entries))
	}

	// bootstrap debug should appear
	if entries[0].Message != "boot debug" {
		t.Errorf("expected 'boot debug', got %q", entries[0].Message)
	}
	// bootstrap info should appear
	if entries[1].Message != "boot info" {
		t.Errorf("expected 'boot info', got %q", entries[1].Message)
	}
	// other info should appear (base level is Info)
	if entries[2].Message != "other info" {
		t.Errorf("expected 'other info', got %q", entries[2].Message)
	}
}

func TestExactMatch_ComponentAtWarn(t *testing.T) {
	logger, logs := buildFilteredLogger(zapcore.InfoLevel, map[string]zapcore.Level{
		"noisy": zapcore.WarnLevel,
	})

	logger.Named("noisy").Info("noisy info")
	logger.Named("noisy").Warn("noisy warn")
	logger.Named("other").Info("other info")

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(entries))
	}
	if entries[0].Message != "noisy warn" {
		t.Errorf("expected 'noisy warn', got %q", entries[0].Message)
	}
	if entries[1].Message != "other info" {
		t.Errorf("expected 'other info', got %q", entries[1].Message)
	}
}

func TestPrefixMatch(t *testing.T) {
	logger, logs := buildFilteredLogger(zapcore.InfoLevel, map[string]zapcore.Level{
		"p2p": zapcore.DebugLevel,
	})

	// "p2p.bootstrap" should match the "p2p" prefix filter
	logger.Named("p2p").Named("bootstrap").Debug("p2p.bootstrap debug")
	logger.Named("p2p").Named("bootstrap").Info("p2p.bootstrap info")
	logger.Named("consensus").Debug("consensus debug")
	logger.Named("consensus").Info("consensus info")

	entries := logs.All()
	if len(entries) != 3 {
		t.Fatalf("expected 3 log entries, got %d", len(entries))
	}
	if entries[0].Message != "p2p.bootstrap debug" {
		t.Errorf("expected 'p2p.bootstrap debug', got %q", entries[0].Message)
	}
	if entries[1].Message != "p2p.bootstrap info" {
		t.Errorf("expected 'p2p.bootstrap info', got %q", entries[1].Message)
	}
	if entries[2].Message != "consensus info" {
		t.Errorf("expected 'consensus info', got %q", entries[2].Message)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	logger, logs := buildFilteredLogger(zapcore.InfoLevel, map[string]zapcore.Level{
		"p2p":           zapcore.WarnLevel,  // broad: suppress p2p to warn
		"p2p.bootstrap": zapcore.DebugLevel, // narrow: but let bootstrap be debug
	})

	logger.Named("p2p").Named("bootstrap").Debug("bootstrap debug")
	logger.Named("p2p").Named("discovery").Info("discovery info")
	logger.Named("p2p").Named("discovery").Warn("discovery warn")

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(entries))
	}
	if entries[0].Message != "bootstrap debug" {
		t.Errorf("expected 'bootstrap debug', got %q", entries[0].Message)
	}
	if entries[1].Message != "discovery warn" {
		t.Errorf("expected 'discovery warn', got %q", entries[1].Message)
	}
}

func TestWithPreservesFilters(t *testing.T) {
	logger, logs := buildFilteredLogger(zapcore.InfoLevel, map[string]zapcore.Level{
		"bootstrap": zapcore.DebugLevel,
	})

	// .With() creates a new core via With(); filters should still apply.
	child := logger.Named("bootstrap").With(zap.String("key", "val"))
	child.Debug("with debug")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	if entries[0].Message != "with debug" {
		t.Errorf("expected 'with debug', got %q", entries[0].Message)
	}
}

func TestParseLogFilters(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]zapcore.Level
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty input",
			input:    map[string]string{},
			expected: nil,
		},
		{
			name:  "valid levels",
			input: map[string]string{"bootstrap": "debug", "noisy": "warn"},
			expected: map[string]zapcore.Level{
				"bootstrap": zapcore.DebugLevel,
				"noisy":     zapcore.WarnLevel,
			},
		},
		{
			name:     "invalid level skipped",
			input:    map[string]string{"bad": "notavalidlevel"},
			expected: nil,
		},
		{
			name:  "mixed valid and invalid",
			input: map[string]string{"good": "error", "bad": "xyz"},
			expected: map[string]zapcore.Level{
				"good": zapcore.ErrorLevel,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLogFilters(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d entries, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("for key %q: expected %v, got %v", k, v, result[k])
				}
			}
		})
	}
}
