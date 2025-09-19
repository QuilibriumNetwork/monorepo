package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

func TestNewPebbleDB_ExistingDirectory(t *testing.T) {
	testDir, err := os.MkdirTemp("", "pebble-test-existing-*")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	core, logs := observer.New(zap.InfoLevel)
	testLogger := zap.New(core)

	cfg := &config.DBConfig{
		Path: testDir,
	}

	db := NewPebbleDB(testLogger, cfg, 0)
	require.NotNil(t, db)
	defer db.Close()

	foundInfoLog := false
	for _, log := range logs.All() {
		if log.Message == "store found" {
			foundInfoLog = true
			assert.Equal(t, testDir, log.ContextMap()["path"])
			break
		}
	}
	assert.True(t, foundInfoLog, "Expected 'store found' info log")
}

func TestNewPebbleDB_ExistingDirectoryWorker(t *testing.T) {
	testDir, err := os.MkdirTemp("", "pebble-test-existing-worker-*")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	core, logs := observer.New(zap.InfoLevel)
	testLogger := zap.New(core)

	cfg := &config.DBConfig{
		WorkerPaths: []string{testDir},
	}

	db := NewPebbleDB(testLogger, cfg, 1)
	require.NotNil(t, db)
	defer db.Close()

	foundInfoLog := false
	for _, log := range logs.All() {
		if log.Message == "worker store found" {
			foundInfoLog = true
			assert.Equal(t, testDir, log.ContextMap()["path"])
			assert.Equal(t, uint64(1), log.ContextMap()["core_id"])
			break
		}
	}
	assert.True(t, foundInfoLog, "Expected 'worker store found' info log")
}

func TestNewPebbleDB_NonExistingDirectory(t *testing.T) {
	baseDir, err := os.MkdirTemp("", "pebble-test-nonexisting-*")
	require.NoError(t, err)
	defer os.RemoveAll(baseDir)

	testDir := filepath.Join(baseDir, "nonexisting")

	core, logs := observer.New(zap.WarnLevel)
	testLogger := zap.New(core)

	cfg := &config.DBConfig{
		Path: testDir,
	}

	db := NewPebbleDB(testLogger, cfg, 0)
	require.NotNil(t, db)
	defer db.Close()

	_, err = os.Stat(testDir)
	assert.NoError(t, err, "Directory should have been created")

	foundWarnLog := false
	for _, log := range logs.All() {
		if log.Message == "store not found, creating" {
			foundWarnLog = true
			assert.Equal(t, testDir, log.ContextMap()["path"])
			break
		}
	}
	assert.True(t, foundWarnLog, "Expected 'store not found, creating' warning log")
}

func TestNewPebbleDB_NonExistingDirectoryWorker(t *testing.T) {
	baseDir, err := os.MkdirTemp("", "pebble-test-nonexisting-worker-*")
	require.NoError(t, err)
	defer os.RemoveAll(baseDir)

	testDir := filepath.Join(baseDir, "nonexisting-worker")

	core, logs := observer.New(zap.WarnLevel)
	testLogger := zap.New(core)

	cfg := &config.DBConfig{
		WorkerPaths: []string{testDir},
	}

	db := NewPebbleDB(testLogger, cfg, 1)
	require.NotNil(t, db)
	defer db.Close()

	_, err = os.Stat(testDir)
	assert.NoError(t, err, "Directory should have been created")

	foundWarnLog := false
	for _, log := range logs.All() {
		if log.Message == "worker store not found, creating" {
			foundWarnLog = true
			assert.Equal(t, testDir, log.ContextMap()["path"])
			assert.Equal(t, uint64(1), log.ContextMap()["core_id"])
			break
		}
	}
	assert.True(t, foundWarnLog, "Expected 'worker store not found, creating' warning log")
}

func TestNewPebbleDB_WorkerPathPrefix(t *testing.T) {
	baseDir, err := os.MkdirTemp("", "pebble-test-prefix-*")
	require.NoError(t, err)
	defer os.RemoveAll(baseDir)

	core, logs := observer.New(zap.WarnLevel)
	testLogger := zap.New(core)

	pathFormat := filepath.Join(baseDir, "worker-%d")
	cfg := &config.DBConfig{
		WorkerPathPrefix: pathFormat,
	}

	db := NewPebbleDB(testLogger, cfg, 2)
	require.NotNil(t, db)
	defer db.Close()

	expectedPath := filepath.Join(baseDir, "worker-2")

	_, err = os.Stat(expectedPath)
	assert.NoError(t, err, "Directory should have been created")

	foundWarnLog := false
	for _, log := range logs.All() {
		if log.Message == "worker store not found, creating" {
			foundWarnLog = true
			assert.Equal(t, expectedPath, log.ContextMap()["path"])
			assert.Equal(t, uint64(2), log.ContextMap()["core_id"])
			break
		}
	}
	assert.True(t, foundWarnLog, "Expected 'worker store not found, creating' warning log")
}
