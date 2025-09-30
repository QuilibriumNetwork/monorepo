package global_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// MockSignature returns mock data for BLS48581SignatureWithProofOfPossession
func MockSignature() global.BLS48581SignatureWithProofOfPossession {
	return global.BLS48581SignatureWithProofOfPossession{
		PublicKey:    append([]byte("mock-public-key"), bytes.Repeat([]byte{0}, 585-len("mock-public-key"))...),
		Signature:    append([]byte("mock-signature"), bytes.Repeat([]byte{0}, 74-len("mock-signature"))...),
		PopSignature: append([]byte("mock-pop-signature"), bytes.Repeat([]byte{0}, 74-len("mock-pop-signature"))...),
	}
}

// MockAddressedSignature returns mock data for BLS48581AddressedSignature
func MockAddressedSignature() global.BLS48581AddressedSignature {
	return global.BLS48581AddressedSignature{
		Address:   append([]byte("mock-address"), bytes.Repeat([]byte{0}, 32-len("mock-address"))...),
		Signature: append([]byte("mock-signature"), bytes.Repeat([]byte{0}, 74-len("mock-signature"))...),
	}
}

// TestBLS48581SignatureWithProofOfPossessionSerialization tests serialization and deserialization of BLS48581SignatureWithProofOfPossession
func TestBLS48581SignatureWithProofOfPossessionSerialization(t *testing.T) {
	sig := MockSignature()

	// Serialize
	data, err := sig.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	var deserializedSig global.BLS48581SignatureWithProofOfPossession
	err = deserializedSig.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, sig.PublicKey, deserializedSig.PublicKey)
	assert.Equal(t, sig.Signature, deserializedSig.Signature)
	assert.Equal(t, sig.PopSignature, deserializedSig.PopSignature)
}

// TestBLS48581AddressedSignatureSerialization tests serialization and deserialization of BLS48581AddressedSignature
func TestBLS48581AddressedSignatureSerialization(t *testing.T) {
	sig := MockAddressedSignature()

	// Serialize
	data, err := sig.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	var deserializedSig global.BLS48581AddressedSignature
	err = deserializedSig.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, sig.Address, deserializedSig.Address)
	assert.Equal(t, sig.Signature, deserializedSig.Signature)
}

// TestProverJoinSerialization tests serialization and deserialization of ProverJoin
func TestProverJoinSerialization(t *testing.T) {
	proverJoin := global.ProverJoin{
		Filters:                    [][]byte{[]byte("filter-data1"), []byte("filter-data2")},
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockSignature(),
	}

	// Serialize
	data, err := proverJoin.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x01}, typePrefix) // ProverJoinType

	// Deserialize
	var deserializedProverJoin global.ProverJoin
	err = deserializedProverJoin.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverJoin.Filters, deserializedProverJoin.Filters)
	assert.Equal(t, proverJoin.FrameNumber, deserializedProverJoin.FrameNumber)
	assert.Equal(t, proverJoin.PublicKeySignatureBLS48581.PublicKey, deserializedProverJoin.PublicKeySignatureBLS48581.PublicKey)
	assert.Equal(t, proverJoin.PublicKeySignatureBLS48581.Signature, deserializedProverJoin.PublicKeySignatureBLS48581.Signature)
	assert.Equal(t, proverJoin.PublicKeySignatureBLS48581.PopSignature, deserializedProverJoin.PublicKeySignatureBLS48581.PopSignature)
}

// TestProverLeaveSerialization tests serialization and deserialization of ProverLeave
func TestProverLeaveSerialization(t *testing.T) {
	proverLeave := global.ProverLeave{
		Filters:                    [][]byte{[]byte("filter-data1"), []byte("filter-data2")},
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	// Serialize
	data, err := proverLeave.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x02}, typePrefix) // ProverLeaveType

	// Deserialize
	var deserializedProverLeave global.ProverLeave
	err = deserializedProverLeave.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverLeave.Filters, deserializedProverLeave.Filters)
	assert.Equal(t, proverLeave.FrameNumber, deserializedProverLeave.FrameNumber)
	assert.Equal(t, proverLeave.PublicKeySignatureBLS48581.Address, deserializedProverLeave.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, proverLeave.PublicKeySignatureBLS48581.Signature, deserializedProverLeave.PublicKeySignatureBLS48581.Signature)
}

// TestProverPauseSerialization tests serialization and deserialization of ProverPause
func TestProverPauseSerialization(t *testing.T) {
	proverPause := global.ProverPause{
		Filter:                     []byte("filter-data"),
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	// Serialize
	data, err := proverPause.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x03}, typePrefix) // ProverPauseType

	// Deserialize
	var deserializedProverPause global.ProverPause
	err = deserializedProverPause.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverPause.Filter, deserializedProverPause.Filter)
	assert.Equal(t, proverPause.FrameNumber, deserializedProverPause.FrameNumber)
	assert.Equal(t, proverPause.PublicKeySignatureBLS48581.Address, deserializedProverPause.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, proverPause.PublicKeySignatureBLS48581.Signature, deserializedProverPause.PublicKeySignatureBLS48581.Signature)
}

// TestProverResumeSerialization tests serialization and deserialization of ProverResume
func TestProverResumeSerialization(t *testing.T) {
	proverResume := global.ProverResume{
		Filter:                     []byte("filter-data"),
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	// Serialize
	data, err := proverResume.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x04}, typePrefix) // ProverResumeType

	// Deserialize
	var deserializedProverResume global.ProverResume
	err = deserializedProverResume.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverResume.Filter, deserializedProverResume.Filter)
	assert.Equal(t, proverResume.FrameNumber, deserializedProverResume.FrameNumber)
	assert.Equal(t, proverResume.PublicKeySignatureBLS48581.Address, deserializedProverResume.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, proverResume.PublicKeySignatureBLS48581.Signature, deserializedProverResume.PublicKeySignatureBLS48581.Signature)
}

// TestProverConfirmSerialization tests serialization and deserialization of ProverConfirm
func TestProverConfirmSerialization(t *testing.T) {
	proverConfirm := global.ProverConfirm{
		Filter:                     []byte("filter-data"),
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	// Serialize
	data, err := proverConfirm.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x05}, typePrefix) // ProverConfirmType

	// Deserialize
	var deserializedProverConfirm global.ProverConfirm
	err = deserializedProverConfirm.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverConfirm.Filter, deserializedProverConfirm.Filter)
	assert.Equal(t, proverConfirm.FrameNumber, deserializedProverConfirm.FrameNumber)
	assert.Equal(t, proverConfirm.PublicKeySignatureBLS48581.Address, deserializedProverConfirm.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, proverConfirm.PublicKeySignatureBLS48581.Signature, deserializedProverConfirm.PublicKeySignatureBLS48581.Signature)
}

// TestProverRejectSerialization tests serialization and deserialization of ProverReject
func TestProverRejectSerialization(t *testing.T) {
	proverReject := global.ProverReject{
		Filter:                     []byte("filter-data"),
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	// Serialize
	data, err := proverReject.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x06}, typePrefix) // ProverRejectType

	// Deserialize
	var deserializedProverReject global.ProverReject
	err = deserializedProverReject.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, proverReject.Filter, deserializedProverReject.Filter)
	assert.Equal(t, proverReject.FrameNumber, deserializedProverReject.FrameNumber)
	assert.Equal(t, proverReject.PublicKeySignatureBLS48581.Address, deserializedProverReject.PublicKeySignatureBLS48581.Address)
	assert.Equal(t, proverReject.PublicKeySignatureBLS48581.Signature, deserializedProverReject.PublicKeySignatureBLS48581.Signature)
}

// TestProverKickSerialization tests serialization and deserialization of ProverKick
func TestProverKickSerialization(t *testing.T) {
	// Create a mock inclusion prover that will create mock multiproofs
	mockInclusionProver := &mocks.MockInclusionProver{}

	// Create a mock multiproof for serialization
	mockMultiproof := &mocks.MockMultiproof{}
	mockMultiproof.On("ToBytes").Return([]byte("mock-multiproof-bytes"), nil)
	mockMultiproof.On("GetMulticommitment").Return([]byte("mock-multicommitment"))
	mockMultiproof.On("GetProof").Return([]byte("mock-proof"))

	// Create a mock traversal proof with proper structure
	mockTraversalProof := &tries.TraversalProof{
		Multiproof: mockMultiproof,
		SubProofs: []tries.TraversalSubProof{
			{
				Commits: [][]byte{[]byte("commit1"), []byte("commit2")},
				Ys:      [][]byte{[]byte("y1"), []byte("y2")},
				Paths:   [][]uint64{{1, 2}, {3, 4}},
			},
			{
				Commits: [][]byte{[]byte("commit3")},
				Ys:      [][]byte{[]byte("y3")},
				Paths:   [][]uint64{{5}},
			},
		},
	}

	proverKick := global.ProverKick{
		FrameNumber:           12345,
		KickedProverPublicKey: append([]byte("kicked-prover-key"), bytes.Repeat([]byte{0}, 585-len("kicked-prover-key"))...),
		ConflictingFrame1:     []byte("conflicting-frame-1"),
		ConflictingFrame2:     []byte("conflicting-frame-2"),
		Commitment:            append([]byte("commitment"), bytes.Repeat([]byte{0}, 74-len("commitment"))...),
		Proof:                 []byte("multiproof-data"),
		TraversalProof:        mockTraversalProof,
	}

	// Serialize
	data, err := proverKick.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Check type prefix (protobuf canonical type)
	typePrefix := data[0:4]
	require.Equal(t, []byte{0, 0, 0x03, 0x07}, typePrefix) // ProverKickType

	// Deserialize without dependencies - Multiproof will be nil
	var deserializedProverKick global.ProverKick
	err = deserializedProverKick.FromBytes(data)
	require.NoError(t, err)

	// Verify basic fields
	assert.Equal(t, proverKick.FrameNumber, deserializedProverKick.FrameNumber)
	assert.Equal(t, proverKick.KickedProverPublicKey, deserializedProverKick.KickedProverPublicKey)
	assert.Equal(t, proverKick.ConflictingFrame1, deserializedProverKick.ConflictingFrame1)
	assert.Equal(t, proverKick.ConflictingFrame2, deserializedProverKick.ConflictingFrame2)
	assert.Equal(t, proverKick.Commitment, deserializedProverKick.Commitment)
	assert.Equal(t, proverKick.Proof, deserializedProverKick.Proof)

	// Verify TraversalProof structure
	require.NotNil(t, deserializedProverKick.TraversalProof)
	assert.Equal(t, len(proverKick.TraversalProof.SubProofs), len(deserializedProverKick.TraversalProof.SubProofs))
	
	// Multiproof will be nil when deserialized without inclusionProver
	assert.Nil(t, deserializedProverKick.TraversalProof.Multiproof)

	// Verify SubProofs content
	for i, subProof := range proverKick.TraversalProof.SubProofs {
		assert.Equal(t, subProof.Commits, deserializedProverKick.TraversalProof.SubProofs[i].Commits)
		assert.Equal(t, subProof.Ys, deserializedProverKick.TraversalProof.SubProofs[i].Ys)
		assert.Equal(t, subProof.Paths, deserializedProverKick.TraversalProof.SubProofs[i].Paths)
	}
	
	// Test deserialization with inclusionProver to reconstruct Multiproof
	newMockMultiproof := &mocks.MockMultiproof{}
	// The multiproof bytes are stored as multicommitment + proof concatenated
	multiproofBytes := append([]byte("mock-multicommitment"), []byte("mock-proof")...)
	newMockMultiproof.On("FromBytes", multiproofBytes).Return(nil)
	mockInclusionProver.On("NewMultiproof").Return(newMockMultiproof)
	
	// Deserialize with hypergraph and inclusionProver
	var deserializedWithDeps global.ProverKick
	err = deserializedWithDeps.FromBytesWithHypergraph(data, nil, mockInclusionProver, nil)
	require.NoError(t, err)
	
	// Now Multiproof should be reconstructed
	require.NotNil(t, deserializedWithDeps.TraversalProof)
	assert.NotNil(t, deserializedWithDeps.TraversalProof.Multiproof)
}

// TestProverKickSerializationNilTraversalProof tests ProverKick serialization with nil traversal proof
func TestProverKickSerializationNilTraversalProof(t *testing.T) {
	proverKick := global.ProverKick{
		FrameNumber:           12345,
		KickedProverPublicKey: append([]byte("kicked-prover-key"), bytes.Repeat([]byte{0}, 585-len("kicked-prover-key"))...),
		ConflictingFrame1:     []byte("conflicting-frame-1"),
		ConflictingFrame2:     []byte("conflicting-frame-2"),
		Commitment:            append([]byte("commitment"), bytes.Repeat([]byte{0}, 74-len("commitment"))...),
		Proof:                 []byte("multiproof-data"),
		TraversalProof:        nil, // nil traversal proof
	}

	// Serialize
	data, err := proverKick.ToBytes()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	var deserializedProverKick global.ProverKick
	err = deserializedProverKick.FromBytes(data)
	require.NoError(t, err)

	// Verify
	assert.Nil(t, deserializedProverKick.TraversalProof)
}

// TestInvalidTypePrefixErrors tests that deserializing with an invalid type prefix returns an error
func TestInvalidTypePrefixErrors(t *testing.T) {
	// ProverJoin
	proverJoin := global.ProverJoin{
		Filters:                    [][]byte{[]byte("filter-data")},
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockSignature(),
	}

	joinData, err := proverJoin.ToBytes()
	require.NoError(t, err)

	// Corrupt the type prefix (change from 9 to 99)
	corruptData := bytes.Clone(joinData)
	corruptData[3] = 99

	var deserializedProverJoin global.ProverJoin
	err = deserializedProverJoin.FromBytes(corruptData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")

	// ProverLeave
	proverLeave := global.ProverLeave{
		Filters:                    [][]byte{[]byte("filter-data")},
		FrameNumber:                12345,
		PublicKeySignatureBLS48581: MockAddressedSignature(),
	}

	leaveData, err := proverLeave.ToBytes()
	require.NoError(t, err)

	// Corrupt the type prefix (change from 9 to 99)
	corruptData = bytes.Clone(leaveData)
	corruptData[3] = 99

	var deserializedProverLeave global.ProverLeave
	err = deserializedProverLeave.FromBytes(corruptData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

// TestInvalidLengthErrors tests that deserializing with invalid field lengths returns errors
func TestInvalidLengthErrors(t *testing.T) {
	t.Run("BLS48581SignatureWithProofOfPossession", func(t *testing.T) {
		// Test with completely invalid data
		invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		var deserializedSig global.BLS48581SignatureWithProofOfPossession
		err := deserializedSig.FromBytes(invalidData)
		assert.Error(t, err, "Should error on invalid data")
		
		// Test with empty data
		err = deserializedSig.FromBytes([]byte{})
		assert.Error(t, err, "Should error on empty data")
		
		// Test with truncated data (type prefix only)
		err = deserializedSig.FromBytes([]byte{0x00, 0x00, 0x03, 0x08})
		assert.Error(t, err, "Should error on truncated data")
	})

	t.Run("BLS48581AddressedSignature", func(t *testing.T) {
		// Test with completely invalid data
		invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		var deserializedSig global.BLS48581AddressedSignature
		err := deserializedSig.FromBytes(invalidData)
		assert.Error(t, err, "Should error on invalid data")
		
		// Test with empty data
		err = deserializedSig.FromBytes([]byte{})
		assert.Error(t, err, "Should error on empty data")
		
		// Test with truncated data (type prefix only)
		err = deserializedSig.FromBytes([]byte{0x00, 0x00, 0x03, 0x09})
		assert.Error(t, err, "Should error on truncated data")
	})
}

// TestSerializationRoundTrip tests a complete round trip of serialization and deserialization for all types
func TestSerializationRoundTrip(t *testing.T) {
	testCases := []struct {
		name         string
		getObj       func() interface{}
		serialize    func(interface{}) ([]byte, error)
		deserialize  func([]byte, interface{}) error
		expectedType uint32
	}{
		{
			name: "ProverJoin",
			getObj: func() interface{} {
				return &global.ProverJoin{
					Filters:                    [][]byte{[]byte("filter-data1"), []byte("filter-data2")},
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverJoin).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverJoin).FromBytes(data)
			},
			expectedType: protobufs.ProverJoinType,
		},
		{
			name: "ProverLeave",
			getObj: func() interface{} {
				return &global.ProverLeave{
					Filters:                    [][]byte{[]byte("filter-data1"), []byte("filter-data2")},
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockAddressedSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverLeave).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverLeave).FromBytes(data)
			},
			expectedType: protobufs.ProverLeaveType,
		},
		{
			name: "ProverPause",
			getObj: func() interface{} {
				return &global.ProverPause{
					Filter:                     []byte("filter-data"),
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockAddressedSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverPause).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverPause).FromBytes(data)
			},
			expectedType: protobufs.ProverPauseType,
		},
		{
			name: "ProverResume",
			getObj: func() interface{} {
				return &global.ProverResume{
					Filter:                     []byte("filter-data"),
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockAddressedSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverResume).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverResume).FromBytes(data)
			},
			expectedType: protobufs.ProverResumeType,
		},
		{
			name: "ProverConfirm",
			getObj: func() interface{} {
				return &global.ProverConfirm{
					Filter:                     []byte("filter-data"),
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockAddressedSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverConfirm).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverConfirm).FromBytes(data)
			},
			expectedType: protobufs.ProverConfirmType,
		},
		{
			name: "ProverReject",
			getObj: func() interface{} {
				return &global.ProverReject{
					Filter:                     []byte("filter-data"),
					FrameNumber:                12345,
					PublicKeySignatureBLS48581: MockAddressedSignature(),
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverReject).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverReject).FromBytes(data)
			},
			expectedType: protobufs.ProverRejectType,
		},
		{
			name: "ProverKick",
			getObj: func() interface{} {
				mockMultiproof := &mocks.MockMultiproof{}
				mockMultiproof.On("ToBytes").Return([]byte("mock-multiproof-bytes"), nil)
				mockMultiproof.On("GetMulticommitment").Return([]byte("mock-multicommitment"))
				mockMultiproof.On("GetProof").Return([]byte("mock-proof"))

				// For deserialization - note that FromBytes without dependencies
				// won't be able to reconstruct the Multiproof

				return &global.ProverKick{
					FrameNumber:           12345,
					KickedProverPublicKey: append([]byte("kicked-prover-key"), bytes.Repeat([]byte{0}, 585-len("kicked-prover-key"))...),
					ConflictingFrame1:     []byte("conflicting-frame-1"),
					ConflictingFrame2:     []byte("conflicting-frame-2"),
					Commitment:            append([]byte("commitment"), bytes.Repeat([]byte{0}, 74-len("commitment"))...),
					Proof:                 []byte("multiproof-data"),
					TraversalProof: &tries.TraversalProof{
						Multiproof: mockMultiproof,
						SubProofs: []tries.TraversalSubProof{
							{
								Commits: [][]byte{[]byte("commit1")},
								Ys:      [][]byte{[]byte("y1")},
								Paths:   [][]uint64{{1}},
							},
						},
					},
				}
			},
			serialize: func(obj interface{}) ([]byte, error) {
				return obj.(*global.ProverKick).ToBytes()
			},
			deserialize: func(data []byte, obj interface{}) error {
				return obj.(*global.ProverKick).FromBytes(data)
			},
			expectedType: protobufs.ProverKickType,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the original object
			original := tc.getObj()

			// Serialize
			serialized, err := tc.serialize(original)
			require.NoError(t, err)
			require.NotEmpty(t, serialized)

			// Check type prefix
			typePrefix := serialized[0:4]
			expectedPrefix := []byte{
				byte(tc.expectedType >> 24),
				byte(tc.expectedType >> 16),
				byte(tc.expectedType >> 8),
				byte(tc.expectedType),
			}
			require.Equal(t, expectedPrefix, typePrefix, "Type prefix should match")

			// Create a new instance for deserialization
			deserialized := tc.getObj()

			// Deserialize
			err = tc.deserialize(serialized, deserialized)
			require.NoError(t, err)

			// Compare (using testify/assert deep equality)
			// For ProverKick, we can't directly compare due to mock objects, so we check fields manually
			if tc.name == "ProverKick" {
				origKick := original.(*global.ProverKick)
				deserKick := deserialized.(*global.ProverKick)
				assert.Equal(t, origKick.FrameNumber, deserKick.FrameNumber)
				assert.Equal(t, origKick.KickedProverPublicKey, deserKick.KickedProverPublicKey)
				assert.Equal(t, origKick.ConflictingFrame1, deserKick.ConflictingFrame1)
				assert.Equal(t, origKick.ConflictingFrame2, deserKick.ConflictingFrame2)
				assert.Equal(t, origKick.Commitment, deserKick.Commitment)
				assert.Equal(t, origKick.Proof, deserKick.Proof)
				require.NotNil(t, deserKick.TraversalProof)
				assert.Equal(t, len(origKick.TraversalProof.SubProofs), len(deserKick.TraversalProof.SubProofs))
				// Multiproof is nil when deserialized without dependencies
				assert.Nil(t, deserKick.TraversalProof.Multiproof)
			} else {
				assert.Equal(t, original, deserialized, "Original and deserialized objects should be equal")
			}
		})
	}
}
