package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

func TestNewDiskMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errCh := make(chan error, 1)

	cfg := config.DBConfig{
		Path:                "/tmp",
		NoticePercentage:    70,
		WarnPercentage:      90,
		TerminatePercentage: 95,
	}

	monitor := NewDiskMonitor(0, cfg, logger, errCh)

	assert.Equal(t, "/tmp", monitor.path)
	assert.Equal(t, 70, monitor.noticePercentage)
	assert.Equal(t, 90, monitor.warnPercentage)
	assert.Equal(t, 95, monitor.terminatePercentage)
	assert.Equal(t, time.Minute, monitor.checkInterval)
}

func TestNewDiskMonitorWorkerPathPrefix(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errCh := make(chan error, 1)

	os.MkdirAll("/tmp/1", 0777)

	cfg := config.DBConfig{
		WorkerPathPrefix:    "/tmp/%d",
		NoticePercentage:    70,
		WarnPercentage:      90,
		TerminatePercentage: 95,
	}

	monitor := NewDiskMonitor(1, cfg, logger, errCh)

	assert.Equal(t, "/tmp/1", monitor.path)
	assert.Equal(t, 70, monitor.noticePercentage)
	assert.Equal(t, 90, monitor.warnPercentage)
	assert.Equal(t, 95, monitor.terminatePercentage)
	assert.Equal(t, time.Minute, monitor.checkInterval)
}

func TestNewDiskMonitorWorkerPath(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errCh := make(chan error, 1)

	os.MkdirAll("/tmp/1", 0777)

	cfg := config.DBConfig{
		WorkerPaths:         []string{"/tmp/1"},
		NoticePercentage:    70,
		WarnPercentage:      90,
		TerminatePercentage: 95,
	}

	monitor := NewDiskMonitor(1, cfg, logger, errCh)

	assert.Equal(t, "/tmp/1", monitor.path)
	assert.Equal(t, 70, monitor.noticePercentage)
	assert.Equal(t, 90, monitor.warnPercentage)
	assert.Equal(t, 95, monitor.terminatePercentage)
	assert.Equal(t, time.Minute, monitor.checkInterval)
}

func TestWithCheckInterval(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errCh := make(chan error, 1)

	cfg := config.DBConfig{
		Path:                "/tmp",
		NoticePercentage:    70,
		WarnPercentage:      90,
		TerminatePercentage: 95,
	}

	monitor := NewDiskMonitor(0, cfg, logger, errCh)
	monitor = monitor.WithCheckInterval(5 * time.Second)

	assert.Equal(t, 5*time.Second, monitor.checkInterval)
}

func TestGetDiskStats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	errCh := make(chan error, 1)

	// Use current directory as it definitely exists
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	cfg := config.DBConfig{
		Path:                cwd,
		NoticePercentage:    70,
		WarnPercentage:      90,
		TerminatePercentage: 95,
	}

	monitor := NewDiskMonitor(0, cfg, logger, errCh)
	percentage, _, _, _, err := monitor.getDiskStats()

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, percentage, 0)
	assert.LessOrEqual(t, percentage, 100)
}

func TestCheckDiskUsage(t *testing.T) {
	// Create a logger that records logs for inspection
	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	errCh := make(chan error, 1)

	// Use current directory
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	cfg := config.DBConfig{
		Path: cwd,
		// Set all thresholds to 0 to ensure logging happens
		NoticePercentage:    0,
		WarnPercentage:      0,
		TerminatePercentage: 0,
	}

	monitor := NewDiskMonitor(0, cfg, logger, errCh)
	monitor.checkDiskUsage()

	// Verify at least one log entry was created
	assert.GreaterOrEqual(t, recorded.Len(), 1)

	// Check that an error was sent to the channel
	select {
	case err := <-errCh:
		assert.Contains(t, err.Error(), "critical threshold")
	default:
		t.Fatal("Expected an error to be sent to the channel")
	}
}

func TestMonitorStart(t *testing.T) {
	// Create a logger that records logs for inspection
	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	errCh := make(chan error, 1)

	// Use current directory
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	cfg := config.DBConfig{
		Path: cwd,
		// Set all thresholds to 0 to ensure logging happens
		NoticePercentage:    0,
		WarnPercentage:      0,
		TerminatePercentage: 0,
	}

	monitor := NewDiskMonitor(0, cfg, logger, errCh)
	monitor = monitor.WithCheckInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	monitor.Start(ctx)

	// Wait for context to be done
	<-ctx.Done()

	// Verify at least one log entry was created
	assert.GreaterOrEqual(t, recorded.Len(), 1)

	// Check that an error was sent to the channel
	select {
	case err := <-errCh:
		assert.Contains(t, err.Error(), "critical threshold")
	default:
		t.Fatal("Expected an error to be sent to the channel")
	}
}
