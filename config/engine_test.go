package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEngineConfigWithDefaults(t *testing.T) {
	// Test case 1: Empty config should be populated with all defaults
	emptyConfig := EngineConfig{}
	withDefaults := emptyConfig.WithDefaults()

	// Verify all default values
	assert.Equal(t, defaultMinimumPeersRequired, withDefaults.MinimumPeersRequired, "MinimumPeersRequired should be set to default")
	assert.Equal(t, defaultDataWorkerBaseListenMultiaddr, withDefaults.DataWorkerBaseListenMultiaddr, "DataWorkerBaseListenMultiaddr should be set to default")
	assert.Equal(t, defaultDataWorkerBaseP2PPort, withDefaults.DataWorkerBaseP2PPort, "DataWorkerBaseP2PPort should be set to default")
	assert.Equal(t, defaultDataWorkerBaseStreamPort, withDefaults.DataWorkerBaseStreamPort, "DataWorkerBaseStreamPort should be set to default")
	assert.Equal(t, defaultDataWorkerMemoryLimit, withDefaults.DataWorkerMemoryLimit, "DataWorkerMemoryLimit should be set to default")
	assert.Equal(t, defaultSyncTimeout, withDefaults.SyncTimeout, "SyncTimeout should be set to default")
	assert.Equal(t, defaultSyncCandidates, withDefaults.SyncCandidates, "SyncCandidates should be set to default")
	assert.Equal(t, defaultRewardStrategy, withDefaults.RewardStrategy, "RewardStrategy should be set to default")

	// Test message limits defaults
	assert.Equal(t, defaultSyncMessageReceiveLimit, withDefaults.SyncMessageLimits.MaxRecvMsgSize, "SyncMessageLimits.MaxRecvMsgSize should be set to default")
	assert.Equal(t, defaultSyncMessageSendLimit, withDefaults.SyncMessageLimits.MaxSendMsgSize, "SyncMessageLimits.MaxSendMsgSize should be set to default")

	// Test frame publish defaults
	assert.Equal(t, "full", withDefaults.FramePublish.Mode, "FramePublish.Mode should be set to default")
	assert.Equal(t, 1*1024*1024, withDefaults.FramePublish.Threshold, "FramePublish.Threshold should be set to default")
	assert.Equal(t, "reed-solomon", withDefaults.FramePublish.Fragmentation.Algorithm, "FramePublish.Fragmentation.Algorithm should be set to default")
	assert.Equal(t, 224, withDefaults.FramePublish.Fragmentation.ReedSolomon.DataShards, "FramePublish.Fragmentation.ReedSolomon.DataShards should be set to default")
	assert.Equal(t, 32, withDefaults.FramePublish.Fragmentation.ReedSolomon.ParityShards, "FramePublish.Fragmentation.ReedSolomon.ParityShards should be set to default")

	// Test case 2: Config with prior default DataWorkerBaseListenMultiaddr should be updated to new default
	priorDefaultConfig := EngineConfig{
		DataWorkerBaseListenMultiaddr: priorDefaultDataWorkerBaseListenMultiaddr,
	}
	updatedConfig := priorDefaultConfig.WithDefaults()

	// Verify the specific field is updated to the new default
	assert.Equal(t, defaultDataWorkerBaseListenMultiaddr, updatedConfig.DataWorkerBaseListenMultiaddr,
		"DataWorkerBaseListenMultiaddr should be updated from prior default to new default")

	// Test case 3: Config with custom values should keep them after WithDefaults
	customConfig := EngineConfig{
		MinimumPeersRequired:          10,
		DataWorkerBaseListenMultiaddr: "/ip4/192.168.1.1/tcp/%d", // Custom value (not prior default)
		DataWorkerBaseP2PPort:         55000,
		DataWorkerBaseStreamPort:      65000,
		DataWorkerMemoryLimit:         2000 * 1024 * 1024,
		SyncTimeout:                   10 * time.Second,
		SyncCandidates:                16,
		RewardStrategy:                "data-greedy",
	}
	preserved := customConfig.WithDefaults()

	// Verify custom values are preserved
	assert.Equal(t, 10, preserved.MinimumPeersRequired, "MinimumPeersRequired custom value should be preserved")
	assert.Equal(t, "/ip4/192.168.1.1/tcp/%d", preserved.DataWorkerBaseListenMultiaddr, "DataWorkerBaseListenMultiaddr custom value should be preserved")
	assert.Equal(t, uint16(55000), preserved.DataWorkerBaseP2PPort, "DataWorkerBaseP2PPort custom value should be preserved")
	assert.Equal(t, uint16(65000), preserved.DataWorkerBaseStreamPort, "DataWorkerBaseStreamPort custom value should be preserved")
	assert.Equal(t, int64(2000*1024*1024), preserved.DataWorkerMemoryLimit, "DataWorkerMemoryLimit custom value should be preserved")
	assert.Equal(t, 10*time.Second, preserved.SyncTimeout, "SyncTimeout custom value should be preserved")
	assert.Equal(t, 16, preserved.SyncCandidates, "SyncCandidates custom value should be preserved")
	assert.Equal(t, "data-greedy", preserved.RewardStrategy, "RewardStrategy custom value should be preserved")
}
