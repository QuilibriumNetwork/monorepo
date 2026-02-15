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
)

func TestShardMergeOp_Prove(t *testing.T) {
	mockKeyManager := new(mocks.MockKeyManager)
	mockSigner := new(mocks.MockBLSSigner)

	parentAddress := make([]byte, 32)
	for i := range parentAddress {
		parentAddress[i] = byte(i % 256)
	}
	shardAddresses := [][]byte{
		append(slices.Clone(parentAddress), 0x00),
		append(slices.Clone(parentAddress), 0x01),
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

	mergeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_MERGE"),
	)
	mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
	require.NoError(t, err)

	expectedMessage := slices.Concat(
		big.NewInt(int64(frameNumber)).FillBytes(make([]byte, 8)),
		parentAddress,
	)

	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", expectedMessage, mergeDomain.Bytes()).
		Return([]byte("signature"), nil)

	mockKeyManager.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)

	op := global.NewShardMergeOp(
		shardAddresses,
		parentAddress,
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

func TestShardMergeOp_Verify(t *testing.T) {
	t.Run("prover registry required", func(t *testing.T) {
		parentAddress := make([]byte, 32)
		op := global.NewShardMergeOp(
			[][]byte{
				append(slices.Clone(parentAddress), 0x00),
				append(slices.Clone(parentAddress), 0x01),
			},
			parentAddress,
			nil,
			nil,
			nil, // no registry
		)

		valid, err := op.Verify(0)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "prover registry not initialized")
	})

	t.Run("too few shard addresses", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		parentAddress := make([]byte, 32)
		op := global.NewShardMergeOp(
			[][]byte{append(slices.Clone(parentAddress), 0x00)}, // only 1
			parentAddress,
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

	t.Run("parent address wrong length", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		op := global.NewShardMergeOp(
			[][]byte{make([]byte, 34), make([]byte, 34)},
			make([]byte, 31), // wrong length
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
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("base shard cannot be merged", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		parentAddress := make([]byte, 32)
		op := global.NewShardMergeOp(
			[][]byte{
				make([]byte, 32), // exactly 32 bytes = base shard
				append(slices.Clone(parentAddress), 0x01),
			},
			parentAddress,
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
		assert.Contains(t, err.Error(), "base shards")
	})

	t.Run("shard does not share parent prefix", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		parentAddress := make([]byte, 32)
		badShard := make([]byte, 33)
		badShard[0] = 0xFF
		op := global.NewShardMergeOp(
			[][]byte{
				append(slices.Clone(parentAddress), 0x00),
				badShard,
			},
			parentAddress,
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
		assert.Contains(t, err.Error(), "parent address prefix")
	})

	t.Run("invalid address length", func(t *testing.T) {
		mockRegistry := new(mocks.MockProverRegistry)
		parentAddress := make([]byte, 32)
		op := global.NewShardMergeOp(
			[][]byte{
				append(slices.Clone(parentAddress), 0x00),
				append(slices.Clone(parentAddress), 0x01),
			},
			parentAddress,
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

		parentAddress := make([]byte, 32)
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
		}
		address := make([]byte, 32)
		address[0] = 0x42

		mockRegistry.On("GetProverInfo", address).Return(nil, nil)

		op := global.NewShardMergeOp(
			shardAddresses, parentAddress, nil, nil, mockRegistry,
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

		parentAddress := make([]byte, 32)
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
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

		op := global.NewShardMergeOp(
			shardAddresses, parentAddress, nil, nil, mockRegistry,
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

		parentAddress := make([]byte, 32)
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
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

		mergeDomainPreimage := slices.Concat(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			[]byte("SHARD_MERGE"),
		)
		mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
		require.NoError(t, err)

		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeBLS48581G1,
			pubKey,
			mock.Anything,
			[]byte("bad-sig"),
			mergeDomain.Bytes(),
		).Return(false, nil)

		op := global.NewShardMergeOp(
			shardAddresses, parentAddress, mockKeyManager, nil, mockRegistry,
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

	t.Run("shard prover count above merge threshold", func(t *testing.T) {
		mockKeyManager := new(mocks.MockKeyManager)
		mockRegistry := new(mocks.MockProverRegistry)

		parentAddress := make([]byte, 32)
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
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
		setupMergeSignatureValidation(mockKeyManager, pubKey)
		// 10 global provers -> minP = 10*2/3 = 6
		globalProvers := make([]*consensus.ProverInfo, 10)
		mockRegistry.On("GetActiveProvers", []byte(nil)).Return(globalProvers, nil)
		// First shard has 10 provers (>= minP=6), merge not eligible
		mockRegistry.On("GetProverCount", shardAddresses[0]).Return(10, nil)

		op := global.NewShardMergeOp(
			shardAddresses, parentAddress, mockKeyManager, nil, mockRegistry,
		)
		op.FrameNumber = 100
		op.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		}

		valid, err := op.Verify(100)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "merge not eligible")
	})

	t.Run("valid merge with eligibility checks", func(t *testing.T) {
		mockKeyManager := new(mocks.MockKeyManager)
		mockRegistry := new(mocks.MockProverRegistry)

		parentAddress := make([]byte, 32)
		for i := range parentAddress {
			parentAddress[i] = byte(i % 256)
		}
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
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
		setupMergeSignatureValidation(mockKeyManager, pubKey)
		// 10 global provers -> minP = 10*2/3 = 6
		globalProvers := make([]*consensus.ProverInfo, 10)
		mockRegistry.On("GetActiveProvers", []byte(nil)).Return(globalProvers, nil)
		// Both shards have 2 provers (< minP=6), merge eligible
		mockRegistry.On("GetProverCount", shardAddresses[0]).Return(2, nil)
		mockRegistry.On("GetProverCount", shardAddresses[1]).Return(2, nil)

		op := global.NewShardMergeOp(
			shardAddresses, parentAddress, mockKeyManager, nil, mockRegistry,
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

func TestShardMergeOp_Materialize(t *testing.T) {
	t.Run("deletes sub-shards", func(t *testing.T) {
		mockShardsStore := new(mocks.MockShardsStore)

		parentAddress := make([]byte, 32)
		for i := range parentAddress {
			parentAddress[i] = byte(i % 256)
		}
		shardAddresses := [][]byte{
			append(slices.Clone(parentAddress), 0x00),
			append(slices.Clone(parentAddress), 0x01),
		}

		for _, addr := range shardAddresses {
			shardKey := slices.Clone(addr[:32])
			path := make([]uint32, 0, len(addr)-32)
			for _, b := range addr[32:] {
				path = append(path, uint32(b))
			}
			mockShardsStore.On("DeleteAppShard",
				mock.Anything, // txn
				shardKey,
				path,
			).Return(nil).Once()
		}

		op := global.NewShardMergeOp(
			shardAddresses,
			parentAddress,
			nil,
			mockShardsStore,
			nil,
		)

		newState, err := op.Materialize(100, nil)
		require.NoError(t, err)
		assert.Nil(t, newState)

		mockShardsStore.AssertExpectations(t)
	})

	t.Run("shardsStore nil returns error", func(t *testing.T) {
		op := global.NewShardMergeOp(
			[][]byte{make([]byte, 33), make([]byte, 33)},
			make([]byte, 32),
			nil,
			nil, // no store
			nil,
		)

		_, err := op.Materialize(100, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shards store not initialized")
	})
}

func TestShardMergeOp_GetCost(t *testing.T) {
	op := global.NewShardMergeOp(nil, nil, nil, nil, nil)
	cost, err := op.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}

func TestShardMergeOp_GetWriteAddresses(t *testing.T) {
	parentAddress := make([]byte, 32)
	shardAddresses := [][]byte{
		append(slices.Clone(parentAddress), 0x00),
		append(slices.Clone(parentAddress), 0x01),
	}

	op := global.NewShardMergeOp(shardAddresses, parentAddress, nil, nil, nil)

	addrs, err := op.GetWriteAddresses(0)
	require.NoError(t, err)
	require.Len(t, addrs, 2)

	for _, addr := range addrs {
		assert.Len(t, addr, 64)
		assert.Equal(t, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr[:32])
	}
}

func TestShardMergeOp_GetReadAddresses(t *testing.T) {
	op := global.NewShardMergeOp(nil, nil, nil, nil, nil)
	addrs, err := op.GetReadAddresses(0)
	require.NoError(t, err)
	assert.Nil(t, addrs)
}

func TestShardMergeOp_ToRequestBytes(t *testing.T) {
	parentAddress := make([]byte, 32)
	for i := range parentAddress {
		parentAddress[i] = byte(i % 256)
	}
	shardAddresses := [][]byte{
		append(slices.Clone(parentAddress), 0x00),
		append(slices.Clone(parentAddress), 0x01),
	}

	op := global.NewShardMergeOp(shardAddresses, parentAddress, nil, nil, nil)
	op.FrameNumber = 12345
	op.PublicKeySignatureBLS48581 = MockAddressedSignature()

	data, err := op.ToRequestBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

// setupMergeSignatureValidation sets up mock expectations for BLS signature
// validation on a merge operation.
func setupMergeSignatureValidation(
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
