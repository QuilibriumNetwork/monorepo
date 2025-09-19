package config

import (
	"testing"
)

func TestDBConfigWithDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    DBConfig
		expected DBConfig
	}{
		{
			name:  "Empty config with no path",
			input: DBConfig{},
			expected: DBConfig{
				WorkerPathPrefix:    "worker-store/%d",
				NoticePercentage:    70,
				WarnPercentage:      90,
				TerminatePercentage: 95,
			},
		},
		{
			name: "Config with custom path",
			input: DBConfig{
				Path: "/custom/path/store",
			},
			expected: DBConfig{
				Path:                "/custom/path/store",
				WorkerPathPrefix:    "/custom/path/worker-store/%d",
				NoticePercentage:    70,
				WarnPercentage:      90,
				TerminatePercentage: 95,
			},
		},
		{
			name: "Config with .config path",
			input: DBConfig{
				Path: ".config/store",
			},
			expected: DBConfig{
				Path:                ".config/store",
				WorkerPathPrefix:    ".config/worker-store/%d",
				NoticePercentage:    70,
				WarnPercentage:      90,
				TerminatePercentage: 95,
			},
		},
		{
			name: "Config with explicit worker path prefix",
			input: DBConfig{
				Path:             "/custom/path/store",
				WorkerPathPrefix: "/different/worker/%d",
			},
			expected: DBConfig{
				Path:                "/custom/path/store",
				WorkerPathPrefix:    "/different/worker/%d",
				NoticePercentage:    70,
				WarnPercentage:      90,
				TerminatePercentage: 95,
			},
		},
		{
			name: "Config with path not ending in /store",
			input: DBConfig{
				Path: "/custom/path",
			},
			expected: DBConfig{
				Path:                "/custom/path",
				WorkerPathPrefix:    "worker-store/%d",
				NoticePercentage:    70,
				WarnPercentage:      90,
				TerminatePercentage: 95,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.WithDefaults()
			
			if result.Path != tt.expected.Path {
				t.Errorf("Path mismatch: got %v, want %v", result.Path, tt.expected.Path)
			}
			if result.WorkerPathPrefix != tt.expected.WorkerPathPrefix {
				t.Errorf("WorkerPathPrefix mismatch: got %v, want %v", result.WorkerPathPrefix, tt.expected.WorkerPathPrefix)
			}
			if result.NoticePercentage != tt.expected.NoticePercentage {
				t.Errorf("NoticePercentage mismatch: got %v, want %v", result.NoticePercentage, tt.expected.NoticePercentage)
			}
			if result.WarnPercentage != tt.expected.WarnPercentage {
				t.Errorf("WarnPercentage mismatch: got %v, want %v", result.WarnPercentage, tt.expected.WarnPercentage)
			}
			if result.TerminatePercentage != tt.expected.TerminatePercentage {
				t.Errorf("TerminatePercentage mismatch: got %v, want %v", result.TerminatePercentage, tt.expected.TerminatePercentage)
			}
		})
	}
}