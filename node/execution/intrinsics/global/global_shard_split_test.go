package global_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

func TestShardSplitOp_Prove(t *testing.T) {
	mockKeyManager := new(mocks.MockKeyManager)
	mockSigner := new(mocks.MockBLSSigner)

	shardAddress := make([]byte, 33)
	for i := range shardAddress {
		shardAddress[i] = byte(i % 256)
	}
	proposedShards := [][]byte{
		append(slices.Clone(shardAddress), 0x00),
		append(slices.Clone(shardAddress), 0x01),
	}
	frameNumber := uint64(12345)
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	// Derive expected 32-byte address from pubKey
	addressBI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	expectedAddress := addressBI.FillBytes(make([]byte, 32))

	splitDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_SPLIT"),
	)
	splitDomain, err := poseidon.HashBytes(splitDomainPreimage)
	require.NoError(t, err)

	expectedMessage := slices.Concat(
		big.NewInt(int64(frameNumber)).FillBytes(make([]byte, 8)),
		shardAddress,
	)

	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage, splitDomain.Bytes()).
		Return([]byte("signature"), nil)

	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	op := global.NewShardSplitOp(
		shardAddress,
		proposedShards,
		mockKeyManager,
		nil,
		nil,
	)

	err = op.Prove(frameNumber)
	require.NoError(t, err)

	assert.Equal(t, expectedAddress, op.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, []byte("signature"), op.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, frameNumber, op.FrameNumber)

	mockSigner.AssertExpectations(t)
	mockKeyManager.AssertExpectations(t)
}

func TestShardSplitOp_Verify(t *testing.T) {
	t.Run("prover registry required", func(t *testing.T) {
		op := global.NewShardSplitOp(
			make([]byte, 33),
			[][]byte{make([]byte, 34), make([]byte, 34)},
			nil,
			nil,
			nil, // no registry
		)

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "prover registry not initialized")
	})

	t.Run("shard address too short", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		op := global.NewShardSplitOp(
			make([]byte, 31), // too short
			[][]byte{make([]byte, 33), make([]byte, 33)},
			nil,
			nil,
			mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address: make([]byte, 32),
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "32-63 bytes")
	})

	t.Run("shard address too long", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		op := global.NewShardSplitOp(
			make([]byte, 64), // too long
			[][]byte{make([]byte, 65), make([]byte, 65)},
			nil,
			nil,
			mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address: make([]byte, 32),
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "32-63 bytes")
	})

	t.Run("too few proposed shards", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		shardAddress := make([]byte, 33)
		op := global.NewShardSplitOp(
			shardAddress,
			[][]byte{append(slices.Clone(shardAddress), 0x00)}, // only 1
			nil,
			nil,
			mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address: make([]byte, 32),
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "2-8")
	})

	t.Run("proposed shard wrong prefix", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		shardAddress := make([]byte, 33)
		badShard := make([]byte, 34)
		badShard[0] = 0xFF // does not match parent prefix
		op := global.NewShardSplitOp(
			shardAddress,
			[][]byte{
				append(slices.Clone(shardAddress), 0x00),
				badShard,
			},
			nil,
			nil,
			mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address: make([]byte, 32),
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "prefix")
	})

	t.Run("invalid address length", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		shardAddress := make([]byte, 33)
		op := global.NewShardSplitOp(
			shardAddress,
			[][]byte{
				append(slices.Clone(shardAddress), 0x00),
				append(slices.Clone(shardAddress), 0x01),
			},
			nil,
			nil,
			mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address: make([]byte, 585), // wrong length
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "invalid address length")
	})

	t.Run("signer not a registered prover", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)

		shardAddress := make([]byte, 33)
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(nil, nil)

		op := global.NewShardSplitOp(
			shardAddress, proposedShards, nil, nil, mockRegistry,
		)
		op.FrameNumber = 100
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		}

		valid, err := op.Verify(100)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "not a registered prover")
	})

	t.Run("signer not a global prover", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)

		shardAddress := make([]byte, 33)
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(&consensus.ProverInfo{
			Allocations: []consensus.ProverAllocationInfo{
				{
					ConfirmationFilter: []byte("some-app-shard"),
					Status:             consensus.ProverStatusActive,
				},
			},
		}, nil)

		op := global.NewShardSplitOp(
			shardAddress, proposedShards, nil, nil, mockRegistry,
		)
		op.FrameNumber = 100
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		}

		valid, err := op.Verify(100)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "not an active global prover")
	})

	t.Run("invalid signature fails", func(t *testing.T) {
		mockKeyManager := new(mocks.MockKeyManager)
		mockRegistry := new(mocks.MockProverRegistry)

		shardAddress := make([]byte, 33)
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}
		pubKey := make([]byte, 585)
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(&consensus.ProverInfo{
			PublicKey: pubKey,
			Allocations: []consensus.ProverAllocationInfo{
				{
					ConfirmationFilter: nil,
					Status:             consensus.ProverStatusActive,
				},
			},
		}, nil)

		splitDomainPreimage := slices.Concat(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			[]byte("SHARD_SPLIT"),
		)
		splitDomain, err := poseidon.HashBytes(splitDomainPreimage)
		require.NoError(t, err)

		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubKey,
			mock.Anything,
			[]byte("bad-sig"),
			splitDomain.Bytes(),
		).Return(false, nil)

		op := global.NewShardSplitOp(
			shardAddress, proposedShards, mockKeyManager, nil, mockRegistry,
		)
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: []byte("bad-sig"),
		}

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "invalid BLS signature")
	})

	t.Run("shard prover count below split threshold", func(t *testing.T) {
		mockKeyManager := new(mocks.MockKeyManager)
		mockRegistry := new(mocks.MockProverRegistry)

		shardAddress := make([]byte, 33)
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(&consensus.ProverInfo{
			PublicKey: pubKey,
			Allocations: []consensus.ProverAllocationInfo{
				{
					ConfirmationFilter: nil,
					Status:             consensus.ProverStatusActive,
				},
			},
		}, nil)
		setupSplitSignatureValidation(mockKeyManager, pubKey)
		mockRegistry.On("GetProverCount", shardAddress).Return(30, nil)

		op := global.NewShardSplitOp(
			shardAddress, proposedShards, mockKeyManager, nil, mockRegistry,
		)
		op.FrameNumber = 100
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		}

		valid, err := op.Verify(100)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "split requires")
	})

	t.Run("valid split with eligibility checks", func(t *testing.T) {
		mockKeyManager := new(mocks.MockKeyManager)
		mockRegistry := new(mocks.MockProverRegistry)

		shardAddress := make([]byte, 33)
		for i := range shardAddress {
			shardAddress[i] = byte(i % 256)
		}
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(&consensus.ProverInfo{
			PublicKey: pubKey,
			Allocations: []consensus.ProverAllocationInfo{
				{
					ConfirmationFilter: nil,
					Status:             consensus.ProverStatusActive,
				},
			},
		}, nil)
		setupSplitSignatureValidation(mockKeyManager, pubKey)
		mockRegistry.On("GetProverCount", shardAddress).Return(35, nil)

		op := global.NewShardSplitOp(
			shardAddress, proposedShards, mockKeyManager, nil, mockRegistry,
		)
		op.FrameNumber = 100
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		}

		valid, err := op.Verify(100)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

func TestShardSplitOp_Materialize(t *testing.T) {
	t.Run("registers proposed shards", func(t *testing.T) {
		mockShardsStore := new(mocks.MockShardsStore)

		// 33-byte shard address: 32 bytes L2 + 1 byte path
		shardAddress := make([]byte, 33)
		for i := range shardAddress {
			shardAddress[i] = byte(i % 256)
		}
		proposedShards := [][]byte{
			append(slices.Clone(shardAddress), 0x00),
			append(slices.Clone(shardAddress), 0x01),
		}

		for _, ps := range proposedShards {
			l2 := slices.Clone(ps[:32])
			path := make([]uint32, 0, len(ps)-32)
			for _, b := range ps[32:] {
				path = append(path, uint32(b))
			}
			mockShardsStore.On("PutAppShard",
				mock.Anything, // txn
				store.ShardInfo{L2: l2, Path: path},
			).Return(nil).Once()
		}

		op := global.NewShardSplitOp(
			shardAddress,
			proposedShards,
			nil,
			mockShardsStore,
			nil,
		)

		newState, err := op.Materialize(100, nil)
		require.NoError(t, err)
		assert.Nil(t, newState) // state passthrough (nil in)

		mockShardsStore.AssertExpectations(t)
	})

	t.Run("shardsStore nil returns error", func(t *testing.T) {
		op := global.NewShardSplitOp(
			make([]byte, 33),
			[][]byte{make([]byte, 34), make([]byte, 34)},
			nil,
			nil, // no store
			nil,
		)

		_, err := op.Materialize(100, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shards store not initialized")
	})
}

func TestShardSplitOp_GetCost(t *testing.T) {
	op := global.NewShardSplitOp(nil, nil, nil, nil, nil)
	cost, err := op.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}

func TestShardSplitOp_GetWriteAddresses(t *testing.T) {
	shardAddress := make([]byte, 33)
	proposedShards := [][]byte{
		append(slices.Clone(shardAddress), 0x00),
		append(slices.Clone(shardAddress), 0x01),
	}

	op := global.NewShardSplitOp(shardAddress, proposedShards, nil, nil, nil)

	addrs, err := op.GetWriteAddresses(0)
	require.NoError(t, err)
	require.Len(t, addrs, 2)

	for _, addr := range addrs {
		assert.Len(t, addr, 64)
		assert.Equal(t, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr[:32])
	}
}

func TestShardSplitOp_GetReadAddresses(t *testing.T) {
	op := global.NewShardSplitOp(nil, nil, nil, nil, nil)
	addrs, err := op.GetReadAddresses(0)
	require.NoError(t, err)
	assert.Nil(t, addrs)
}

func TestShardSplitOp_ToRequestBytes(t *testing.T) {
	shardAddress := make([]byte, 33)
	for i := range shardAddress {
		shardAddress[i] = byte(i % 256)
	}
	proposedShards := [][]byte{
		append(slices.Clone(shardAddress), 0x00),
		append(slices.Clone(shardAddress), 0x01),
	}

	op := global.NewShardSplitOp(shardAddress, proposedShards, nil, nil, nil)
	op.FrameNumber = 12345
	op.PublicKeySignatureBLS48581 = MockAddressedSignature()

	data, err := op.ToRequestBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

// setupSplitSignatureValidation sets up mock expectations for BLS signature
// validation on a split operation.
func setupSplitSignatureValidation(
	mockKeyManager *mocks.MockKeyManager,
	pubKey []byte,
) {
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(true, nil)
}
