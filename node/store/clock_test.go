package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func setupTestClockStore(t *testing.T) *PebbleClockStore {
	logger, _ := zap.NewDevelopment()
	tempDB := NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	return NewPebbleClockStore(tempDB, logger)
}

func createTestGlobalFrame(frameNumber uint64) *protobufs.GlobalFrame {
	return &protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber:          frameNumber,
			Timestamp:            time.Now().UnixMilli(),
			Difficulty:           1000,
			Output:               bytes.Repeat([]byte{0x01}, 516),
			ParentSelector:       bytes.Repeat([]byte{0x02}, 32),
			GlobalCommitments:    [][]byte{bytes.Repeat([]byte{0x03}, 64)},
			ProverTreeCommitment: bytes.Repeat([]byte{0x04}, 64),
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: bytes.Repeat([]byte{0x07}, 192),
			},
		},
		Requests: []*protobufs.MessageBundle{
			{
				Requests: []*protobufs.MessageRequest{{
					Request: &protobufs.MessageRequest_Join{
						Join: &protobufs.ProverJoin{
							Filters:     [][]byte{bytes.Repeat([]byte{0x08}, 32)},
							FrameNumber: frameNumber,
						},
					},
				}},
				Timestamp: time.Now().UnixMilli(),
			},
			{
				Requests: []*protobufs.MessageRequest{{
					Request: &protobufs.MessageRequest_Leave{
						Leave: &protobufs.ProverLeave{
							Filters:     [][]byte{bytes.Repeat([]byte{0x09}, 32)},
							FrameNumber: frameNumber,
						},
					},
				}},
				Timestamp: time.Now().UnixMilli(),
			},
		},
	}
}

func createTestAppShardFrame(frameNumber uint64, address []byte) *protobufs.AppShardFrame {
	return &protobufs.AppShardFrame{
		Header: &protobufs.FrameHeader{
			Address:           address,
			FrameNumber:       frameNumber,
			Timestamp:         time.Now().UnixMilli(),
			Difficulty:        1000,
			Output:            bytes.Repeat([]byte{0x01}, 516),
			ParentSelector:    bytes.Repeat([]byte{0x02}, 32),
			RequestsRoot:      bytes.Repeat([]byte{0x03}, 64),
			StateRoots:        [][]byte{bytes.Repeat([]byte{0x04}, 64)},
			Prover:            bytes.Repeat([]byte{0x05}, 32),
			FeeMultiplierVote: 100,
			PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
				Signature: bytes.Repeat([]byte{0x06}, 74),
			},
		},
		Requests: []*protobufs.MessageBundle{
			{
				Requests: []*protobufs.MessageRequest{{
					Request: &protobufs.MessageRequest_Transaction{
						Transaction: &protobufs.Transaction{
							Domain: token.QUIL_TOKEN_ADDRESS,
							Inputs: []*protobufs.TransactionInput{
								{
									Commitment: []byte{0x04},
									Signature:  []byte{0x05},
									Proofs:     [][]byte{{0x06}},
								},
							},
							Outputs: []*protobufs.TransactionOutput{
								{
									FrameNumber: []byte{0x07},
									Commitment:  []byte{0x08},
									RecipientOutput: &protobufs.RecipientBundle{
										OneTimeKey:      []byte{0x09},
										VerificationKey: []byte{0x0a},
										CoinBalance:     []byte{0x0b},
										Mask:            []byte{0x0c},
									},
								},
							},
							Fees:       [][]byte{{0x01}},
							RangeProof: []byte{0x02},
						},
					},
				}},
				Timestamp: time.Now().UnixMilli(),
			},
			{
				Requests: []*protobufs.MessageRequest{{
					Request: &protobufs.MessageRequest_Leave{
						Leave: &protobufs.ProverLeave{
							Filters:     [][]byte{bytes.Repeat([]byte{0x09}, 32)},
							FrameNumber: frameNumber,
						},
					},
				}},
				Timestamp: time.Now().UnixMilli(),
			},
		},
	}
}

func TestGlobalClockFrameOperations(t *testing.T) {
	cs := setupTestClockStore(t)

	t.Run("PutAndGetGlobalClockFrame", func(t *testing.T) {
		frame := createTestGlobalFrame(1)

		// Put frame
		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutGlobalClockFrame(frame, txn)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		// Get frame
		retrieved, err := cs.GetGlobalClockFrame(1)
		require.NoError(t, err)
		require.NotNil(t, retrieved)

		// Verify header
		assert.Equal(t, frame.Header.FrameNumber, retrieved.Header.FrameNumber)
		assert.Equal(t, frame.Header.Timestamp, retrieved.Header.Timestamp)
		assert.Equal(t, frame.Header.Difficulty, retrieved.Header.Difficulty)
		assert.Equal(t, frame.Header.Output, retrieved.Header.Output)
		assert.Equal(t, frame.Header.ParentSelector, retrieved.Header.ParentSelector)

		// Verify requests
		assert.Equal(t, len(frame.Requests), len(retrieved.Requests))
		for i, req := range frame.Requests {
			assert.Equal(t, req.Timestamp, retrieved.Requests[i].Timestamp)
		}
	})

	t.Run("GetLatestGlobalClockFrame", func(t *testing.T) {
		// Put multiple frames
		for i := uint64(2); i <= 5; i++ {
			frame := createTestGlobalFrame(i)
			txn, err := cs.NewTransaction(false)
			require.NoError(t, err)

			err = cs.PutGlobalClockFrame(frame, txn)
			require.NoError(t, err)

			err = txn.Commit()
			require.NoError(t, err)
		}

		// Get latest
		latest, err := cs.GetLatestGlobalClockFrame()
		require.NoError(t, err)
		assert.Equal(t, uint64(5), latest.Header.FrameNumber)
	})

	t.Run("GetEarliestGlobalClockFrame", func(t *testing.T) {
		earliest, err := cs.GetEarliestGlobalClockFrame()
		require.NoError(t, err)
		assert.Equal(t, uint64(1), earliest.Header.FrameNumber)
	})

	t.Run("RangeGlobalClockFrames", func(t *testing.T) {
		iter, err := cs.RangeGlobalClockFrames(2, 4)
		require.NoError(t, err)
		defer iter.Close()

		count := 0
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			require.NoError(t, err)
			assert.GreaterOrEqual(t, frame.Header.FrameNumber, uint64(2))
			assert.LessOrEqual(t, frame.Header.FrameNumber, uint64(4))
			count++
		}
		assert.Equal(t, 3, count)
	})

	t.Run("GlobalFrameWithNoRequests", func(t *testing.T) {
		frame := createTestGlobalFrame(10)
		frame.Requests = nil

		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutGlobalClockFrame(frame, txn)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		retrieved, err := cs.GetGlobalClockFrame(10)
		require.NoError(t, err)
		assert.Empty(t, retrieved.Requests)
	})

	t.Run("GlobalFrameWithManyRequests", func(t *testing.T) {
		frame := createTestGlobalFrame(20)
		// Add many requests
		frame.Requests = make([]*protobufs.MessageBundle, 100)
		for i := 0; i < 100; i++ {
			frame.Requests[i] = &protobufs.MessageBundle{
				Requests: []*protobufs.MessageRequest{{
					Request: &protobufs.MessageRequest_Join{
						Join: &protobufs.ProverJoin{
							Filters:     [][]byte{bytes.Repeat([]byte{byte(i)}, 32)},
							FrameNumber: 20,
						},
					},
				}},
				Timestamp: time.Now().UnixMilli() + int64(i),
			}
		}

		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutGlobalClockFrame(frame, txn)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		retrieved, err := cs.GetGlobalClockFrame(20)
		require.NoError(t, err)
		assert.Equal(t, 100, len(retrieved.Requests))
	})

	t.Run("ResetGlobalClockFrames", func(t *testing.T) {
		err := cs.ResetGlobalClockFrames()
		require.NoError(t, err)

		// Verify frames are gone
		_, err = cs.GetLatestGlobalClockFrame()
		assert.ErrorIs(t, err, store.ErrNotFound)

		_, err = cs.GetEarliestGlobalClockFrame()
		assert.ErrorIs(t, err, store.ErrNotFound)

		_, err = cs.GetGlobalClockFrame(1)
		assert.ErrorIs(t, err, store.ErrNotFound)
	})
}

func TestAppShardFrameOperations(t *testing.T) {
	cs := setupTestClockStore(t)
	address := bytes.Repeat([]byte{0xAA}, 32)

	t.Run("StageAndCommitShardClockFrame", func(t *testing.T) {
		frame := createTestAppShardFrame(1, address)
		selector := bytes.Repeat([]byte{0xBB}, 32)

		// Stage frame
		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.StageShardClockFrame(selector, frame, txn)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		// Get staged frame
		staged, err := cs.GetStagedShardClockFrame(address, 1, selector, false)
		require.NoError(t, err)
		assert.Equal(t, frame.Header.FrameNumber, staged.Header.FrameNumber)

		// Commit frame
		txn2, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.CommitShardClockFrame(address, 1, selector, nil, txn2, false)
		require.NoError(t, err)

		err = txn2.Commit()
		require.NoError(t, err)

		// Get committed frame
		committed, _, err := cs.GetShardClockFrame(address, 1, false)
		require.NoError(t, err)
		assert.Equal(t, frame.Header.FrameNumber, committed.Header.FrameNumber)
	})

	t.Run("GetLatestShardClockFrame", func(t *testing.T) {
		// Stage and commit multiple frames
		for i := uint64(2); i <= 5; i++ {
			frame := createTestAppShardFrame(i, address)
			selector := bytes.Repeat([]byte{byte(i)}, 32)

			txn, err := cs.NewTransaction(false)
			require.NoError(t, err)

			err = cs.StageShardClockFrame(selector, frame, txn)
			require.NoError(t, err)

			err = cs.CommitShardClockFrame(address, i, selector, nil, txn, false)
			require.NoError(t, err)

			err = txn.Commit()
			require.NoError(t, err)
		}

		latest, _, err := cs.GetLatestShardClockFrame(address)
		require.NoError(t, err)
		assert.Equal(t, uint64(5), latest.Header.FrameNumber)
	})

	t.Run("GetEarliestShardClockFrame", func(t *testing.T) {
		earliest, err := cs.GetEarliestShardClockFrame(address)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), earliest.Header.FrameNumber)
	})

	t.Run("RangeShardClockFrames", func(t *testing.T) {
		iter, err := cs.RangeShardClockFrames(address, 2, 4)
		require.NoError(t, err)
		defer iter.Close()

		count := 0
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			require.NoError(t, err)
			assert.GreaterOrEqual(t, frame.Header.FrameNumber, uint64(2))
			assert.LessOrEqual(t, frame.Header.FrameNumber, uint64(4))
			count++
		}
		assert.Equal(t, 3, count)
	})

	t.Run("GetStagedShardClockFramesForFrameNumber", func(t *testing.T) {
		// Stage multiple frames with different selectors for the same frame number
		frameNumber := uint64(10)
		for i := 0; i < 3; i++ {
			frame := createTestAppShardFrame(frameNumber, address)
			selector := bytes.Repeat([]byte{byte(0xCC + i)}, 32)

			txn, err := cs.NewTransaction(false)
			require.NoError(t, err)

			err = cs.StageShardClockFrame(selector, frame, txn)
			require.NoError(t, err)

			err = txn.Commit()
			require.NoError(t, err)
		}

		staged, err := cs.GetStagedShardClockFramesForFrameNumber(address, frameNumber)
		require.NoError(t, err)
		assert.Equal(t, 3, len(staged))
	})

	t.Run("ResetShardClockFrames", func(t *testing.T) {
		err := cs.ResetShardClockFrames(address)
		require.NoError(t, err)

		// Verify frames are gone
		_, _, err = cs.GetLatestShardClockFrame(address)
		assert.ErrorIs(t, err, store.ErrNotFound)

		_, err = cs.GetEarliestShardClockFrame(address)
		assert.ErrorIs(t, err, store.ErrNotFound)

		_, _, err = cs.GetShardClockFrame(address, 1, false)
		assert.ErrorIs(t, err, store.ErrNotFound)
	})
}

func TestProverTriesOperations(t *testing.T) {
	cs := setupTestClockStore(t)

	t.Run("SetProverTriesForGlobalFrame", func(t *testing.T) {
		frame := createTestGlobalFrame(1)

		// Create test tries
		testTries := make([]*tries.RollingFrecencyCritbitTrie, 3)
		for i := 0; i < 3; i++ {
			trie := &tries.RollingFrecencyCritbitTrie{}
			testTries[i] = trie
		}

		err := cs.SetProverTriesForGlobalFrame(frame, testTries)
		require.NoError(t, err)
	})

	t.Run("SetProverTriesForShardFrame", func(t *testing.T) {
		address := bytes.Repeat([]byte{0xDD}, 32)
		frame := createTestAppShardFrame(1, address)

		// Create test tries
		testTries := make([]*tries.RollingFrecencyCritbitTrie, 3)
		for i := 0; i < 3; i++ {
			trie := &tries.RollingFrecencyCritbitTrie{}
			testTries[i] = trie
		}

		err := cs.SetProverTriesForShardFrame(frame, testTries)
		require.NoError(t, err)
	})
}

func TestPeerSeniorityMapOperations(t *testing.T) {
	cs := setupTestClockStore(t)
	filter := bytes.Repeat([]byte{0xEE}, 32)

	t.Run("PutAndGetPeerSeniorityMap", func(t *testing.T) {
		seniorityMap := map[string]uint64{
			"peer1": 100,
			"peer2": 200,
			"peer3": 300,
		}

		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutPeerSeniorityMap(txn, filter, seniorityMap)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		retrieved, err := cs.GetPeerSeniorityMap(filter)
		require.NoError(t, err)
		assert.Equal(t, seniorityMap, retrieved)
	})
}

func TestShardStateTreeOperations(t *testing.T) {
	cs := setupTestClockStore(t)
	filter := bytes.Repeat([]byte{0xFF}, 32)

	t.Run("GetShardStateTree", func(t *testing.T) {
		// Note: PutShardStateTree doesn't exist in the interface
		// This test just verifies GetShardStateTree handles missing data correctly
		_, err := cs.GetShardStateTree(filter)
		// Should return error for non-existent tree
		assert.Error(t, err)
	})
}

func TestIteratorEdgeCases(t *testing.T) {
	cs := setupTestClockStore(t)

	t.Run("IteratorOnEmptyStore", func(t *testing.T) {
		iter, err := cs.RangeGlobalClockFrames(1, 10)
		require.NoError(t, err)
		defer iter.Close()

		assert.False(t, iter.First())
		assert.False(t, iter.Valid())
	})

	t.Run("IteratorTruncatedValue", func(t *testing.T) {
		// Put a frame
		frame := createTestGlobalFrame(1)
		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutGlobalClockFrame(frame, txn)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)

		// Test truncated value
		iter, err := cs.RangeGlobalClockFrames(1, 1)
		require.NoError(t, err)
		defer iter.Close()

		assert.True(t, iter.First())

		truncated, err := iter.TruncatedValue()
		require.NoError(t, err)
		assert.NotNil(t, truncated.Header)
		assert.Empty(t, truncated.Requests) // TruncatedValue doesn't include requests
	})
}

func TestTransactionRollback(t *testing.T) {
	cs := setupTestClockStore(t)

	frame := createTestGlobalFrame(100)

	// Start transaction
	txn, err := cs.NewTransaction(false)
	require.NoError(t, err)

	// Put frame in transaction
	err = cs.PutGlobalClockFrame(frame, txn)
	require.NoError(t, err)

	// Rollback transaction
	err = txn.Abort()
	require.NoError(t, err)

	// Verify frame was not persisted
	_, err = cs.GetGlobalClockFrame(100)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestNilHeaderHandling(t *testing.T) {
	cs := setupTestClockStore(t)

	t.Run("PutGlobalFrameWithNilHeader", func(t *testing.T) {
		frame := &protobufs.GlobalFrame{
			Header: nil,
		}

		txn, err := cs.NewTransaction(false)
		require.NoError(t, err)

		err = cs.PutGlobalClockFrame(frame, txn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "frame header is required")
	})
}
