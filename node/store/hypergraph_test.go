package store

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func setupTestHypergraphStore(t *testing.T) *PebbleHypergraphStore {
	logger := zap.NewNop()
	cfg := &config.Config{DB: &config.DBConfig{
		InMemoryDONOTUSE: true,
		Path:             ".test/hypergraph",
	}}
	db := NewPebbleDB(logger, cfg, 0)
	require.NotNil(t, db)
	t.Cleanup(func() { db.Close() })
	return NewPebbleHypergraphStore(cfg.DB, db, logger, nil, nil)
}

func TestGetRootCommits_IncludesAllCommitTypes(t *testing.T) {
	hgStore := setupTestHypergraphStore(t)

	// Create a test shard address
	shardAddress := bytes.Repeat([]byte{0x42}, 32)
	frameNumber := uint64(100)

	// Create test commits (64 bytes each)
	vertexAddsCommit := bytes.Repeat([]byte{0xAA}, 64)
	vertexRemovesCommit := bytes.Repeat([]byte{0xBB}, 64)
	hyperedgeAddsCommit := bytes.Repeat([]byte{0xCC}, 64)
	hyperedgeRemovesCommit := bytes.Repeat([]byte{0xDD}, 64)

	// Start a transaction and write all four commit types
	txn, err := hgStore.NewTransaction(false)
	require.NoError(t, err)

	err = hgStore.SetShardCommit(txn, frameNumber, "adds", "vertex", shardAddress, vertexAddsCommit)
	require.NoError(t, err)

	err = hgStore.SetShardCommit(txn, frameNumber, "removes", "vertex", shardAddress, vertexRemovesCommit)
	require.NoError(t, err)

	err = hgStore.SetShardCommit(txn, frameNumber, "adds", "hyperedge", shardAddress, hyperedgeAddsCommit)
	require.NoError(t, err)

	err = hgStore.SetShardCommit(txn, frameNumber, "removes", "hyperedge", shardAddress, hyperedgeRemovesCommit)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Now retrieve all commits using GetRootCommits
	commits, err := hgStore.GetRootCommits(frameNumber)
	require.NoError(t, err)

	// Find the shard key for our test address
	var foundShardKey *tries.ShardKey
	for sk := range commits {
		if bytes.Equal(sk.L2[:], shardAddress) {
			foundShardKey = &sk
			break
		}
	}

	require.NotNil(t, foundShardKey, "Should find the shard in commits")

	shardCommits := commits[*foundShardKey]
	require.Len(t, shardCommits, 4, "Should have 4 commit slots")

	// Verify each commit type was retrieved
	assert.Equal(t, vertexAddsCommit, shardCommits[0], "Vertex adds commit should match")
	assert.Equal(t, vertexRemovesCommit, shardCommits[1], "Vertex removes commit should match")
	assert.Equal(t, hyperedgeAddsCommit, shardCommits[2], "Hyperedge adds commit should match")
	assert.Equal(t, hyperedgeRemovesCommit, shardCommits[3], "Hyperedge removes commit should match")
}

func TestGetRootCommits_HyperedgeRemovesOnly(t *testing.T) {
	// This test specifically checks if hyperedge removes are retrieved
	// when they are the only commit type for a shard
	hgStore := setupTestHypergraphStore(t)

	// Create a test shard address
	shardAddress := bytes.Repeat([]byte{0x99}, 32)
	frameNumber := uint64(200)

	// Only write hyperedge removes commit
	hyperedgeRemovesCommit := bytes.Repeat([]byte{0xEE}, 64)

	txn, err := hgStore.NewTransaction(false)
	require.NoError(t, err)

	err = hgStore.SetShardCommit(txn, frameNumber, "removes", "hyperedge", shardAddress, hyperedgeRemovesCommit)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Now retrieve all commits using GetRootCommits
	commits, err := hgStore.GetRootCommits(frameNumber)
	require.NoError(t, err)

	// Find the shard key for our test address
	var foundShardKey *tries.ShardKey
	for sk := range commits {
		if bytes.Equal(sk.L2[:], shardAddress) {
			foundShardKey = &sk
			break
		}
	}

	// This assertion will fail if hyperedge removes are not included in the range scan
	require.NotNil(t, foundShardKey, "Should find the shard with only hyperedge removes in commits")

	shardCommits := commits[*foundShardKey]
	require.Len(t, shardCommits, 4, "Should have 4 commit slots")

	// The hyperedge removes should be at index 3
	assert.Equal(t, hyperedgeRemovesCommit, shardCommits[3], "Hyperedge removes commit should match")
}
