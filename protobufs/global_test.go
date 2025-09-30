package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeniorityMerge_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		merge *SeniorityMerge
	}{
		{
			name: "complete seniority merge",
			merge: &SeniorityMerge{
				Signature:       make([]byte, 114), // Ed448 signature
				KeyType:         0,
				ProverPublicKey: make([]byte, 57), // Ed448 public key
			},
		},
		{
			name: "different key type",
			merge: &SeniorityMerge{
				Signature:       append([]byte{0xFF}, make([]byte, 113)...),
				KeyType:         1,
				ProverPublicKey: append([]byte{0xAA}, make([]byte, 56)...),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.merge.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			merge2 := &SeniorityMerge{}
			err = merge2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.merge.Signature, merge2.Signature)
			assert.Equal(t, tt.merge.KeyType, merge2.KeyType)
			assert.Equal(t, tt.merge.ProverPublicKey, merge2.ProverPublicKey)
		})
	}
}

func TestLegacyProverRequest_Serialization(t *testing.T) {
	tests := []struct {
		name string
		req  *LegacyProverRequest
	}{
		{
			name: "complete legacy prover request",
			req: &LegacyProverRequest{
				PublicKeySignaturesEd448: []*Ed448Signature{
					{
						PublicKey: &Ed448PublicKey{
							KeyValue: make([]byte, 57),
						},
						Signature: make([]byte, 114),
					},
					{
						PublicKey: &Ed448PublicKey{
							KeyValue: append([]byte{0xAA}, make([]byte, 56)...),
						},
						Signature: append([]byte{0xBB}, make([]byte, 113)...),
					},
				},
			},
		},
		{
			name: "empty legacy prover request",
			req: &LegacyProverRequest{
				PublicKeySignaturesEd448: []*Ed448Signature{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.req.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			req2 := &LegacyProverRequest{}
			err = req2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, len(tt.req.PublicKeySignaturesEd448), len(req2.PublicKeySignaturesEd448))
			for i := range tt.req.PublicKeySignaturesEd448 {
				assert.Equal(t, tt.req.PublicKeySignaturesEd448[i].PublicKey.KeyValue, req2.PublicKeySignaturesEd448[i].PublicKey.KeyValue)
				assert.Equal(t, tt.req.PublicKeySignaturesEd448[i].Signature, req2.PublicKeySignaturesEd448[i].Signature)
			}
		})
	}
}

func TestProverJoin_Serialization(t *testing.T) {
	tests := []struct {
		name string
		join *ProverJoin
	}{
		{
			name: "complete prover join",
			join: &ProverJoin{
				Filters:     [][]byte{make([]byte, 32), append([]byte{0xFF}, make([]byte, 31)...)},
				FrameNumber: 12345,
				PublicKeySignatureBls48581: &BLS48581SignatureWithProofOfPossession{
					Signature:    make([]byte, 74), // BLS48-581 signature size
					PopSignature: make([]byte, 74), // BLS48-581 PoP size
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585), // BLS48-581 G2 key size
					},
				},
				DelegateAddress: make([]byte, 32),
				MergeTargets: []*SeniorityMerge{
					{
						Signature:       make([]byte, 114),
						KeyType:         0,
						ProverPublicKey: make([]byte, 57),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.join.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			join2 := &ProverJoin{}
			err = join2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.join.Filters, join2.Filters)
			assert.Equal(t, tt.join.FrameNumber, join2.FrameNumber)
			assert.Equal(t, tt.join.DelegateAddress, join2.DelegateAddress)
			assert.Equal(t, len(tt.join.MergeTargets), len(join2.MergeTargets))

			if tt.join.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, join2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.join.PublicKeySignatureBls48581.Signature, join2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.join.PublicKeySignatureBls48581.PopSignature, join2.PublicKeySignatureBls48581.PopSignature)
				if tt.join.PublicKeySignatureBls48581.PublicKey != nil {
					assert.NotNil(t, join2.PublicKeySignatureBls48581.PublicKey)
					assert.Equal(t, tt.join.PublicKeySignatureBls48581.PublicKey.KeyValue, join2.PublicKeySignatureBls48581.PublicKey.KeyValue)
				}
			} else {
				assert.Nil(t, join2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestFrameHeader_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		header *FrameHeader
	}{
		{
			name: "complete frame header",
			header: &FrameHeader{
				Address:           make([]byte, 32),
				FrameNumber:       99999,
				Timestamp:         1234567890123,
				Difficulty:        1000000,
				Output:            make([]byte, 516), // VDF output: 258 + 258 bytes
				ParentSelector:    make([]byte, 32),
				RequestsRoot:      make([]byte, 32),
				StateRoots:        [][]byte{make([]byte, 32), make([]byte, 32)},
				Prover:            make([]byte, 32),
				FeeMultiplierVote: 500,
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					Signature: make([]byte, 74),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
					Bitmask: make([]byte, 32),
				},
			},
		},
		{
			name: "minimal frame header",
			header: &FrameHeader{
				Address:                    []byte{},
				FrameNumber:                0,
				Timestamp:                  0,
				Difficulty:                 0,
				Output:                     []byte{},
				ParentSelector:             []byte{},
				RequestsRoot:               []byte{},
				StateRoots:                 [][]byte{},
				Prover:                     []byte{},
				FeeMultiplierVote:          0,
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.header.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			header2 := &FrameHeader{}
			err = header2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.header.Address, header2.Address)
			assert.Equal(t, tt.header.FrameNumber, header2.FrameNumber)
			assert.Equal(t, tt.header.Timestamp, header2.Timestamp)
			assert.Equal(t, tt.header.Difficulty, header2.Difficulty)
			assert.Equal(t, tt.header.Output, header2.Output)
			assert.Equal(t, tt.header.ParentSelector, header2.ParentSelector)
			assert.Equal(t, tt.header.RequestsRoot, header2.RequestsRoot)
			assert.Equal(t, tt.header.StateRoots, header2.StateRoots)
			assert.Equal(t, tt.header.Prover, header2.Prover)
			assert.Equal(t, tt.header.FeeMultiplierVote, header2.FeeMultiplierVote)

			if tt.header.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, header2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.header.PublicKeySignatureBls48581.Signature, header2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.header.PublicKeySignatureBls48581.Bitmask, header2.PublicKeySignatureBls48581.Bitmask)
				if tt.header.PublicKeySignatureBls48581.PublicKey != nil {
					assert.NotNil(t, header2.PublicKeySignatureBls48581.PublicKey)
					assert.Equal(t, tt.header.PublicKeySignatureBls48581.PublicKey.KeyValue, header2.PublicKeySignatureBls48581.PublicKey.KeyValue)
				}
			} else {
				assert.Nil(t, header2.PublicKeySignatureBls48581)
			}
		})
	}
}

// Note: MessageRequest is a complex union type that requires special handling
// The actual implementation would need to test each specific request type
func TestMessageRequest_Serialization(t *testing.T) {
	tests := []struct {
		name string
		req  *MessageRequest
	}{
		{
			name: "message request with join",
			req: &MessageRequest{
				Request: &MessageRequest_Join{
					Join: &ProverJoin{
						Filters:     [][]byte{make([]byte, 32)},
						FrameNumber: 12345,
						PublicKeySignatureBls48581: &BLS48581SignatureWithProofOfPossession{
							Signature:    make([]byte, 74),
							PopSignature: make([]byte, 74),
							PublicKey: &BLS48581G2PublicKey{
								KeyValue: make([]byte, 585),
							},
						},
						DelegateAddress: make([]byte, 32),
						MergeTargets:    []*SeniorityMerge{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.req.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			req2 := &MessageRequest{}
			err = req2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Verify the union type was preserved
			assert.NotNil(t, req2.Request)

			// Type assertion to verify specific request type
			if joinReq, ok := tt.req.Request.(*MessageRequest_Join); ok {
				join2, ok2 := req2.Request.(*MessageRequest_Join)
				assert.True(t, ok2)
				if ok2 {
					assert.Equal(t, joinReq.Join.FrameNumber, join2.Join.FrameNumber)
					assert.Equal(t, joinReq.Join.Filters, join2.Join.Filters)
				}
			}
		})
	}
}

// Simplified tests for the remaining types - many follow similar patterns
func TestProverUpdate_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		update *ProverUpdate
	}{
		{
			name: "complete prover update",
			update: &ProverUpdate{
				DelegateAddress: make([]byte, 32),
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "minimal prover update",
			update: &ProverUpdate{
				DelegateAddress:            []byte{},
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.update.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			update2 := &ProverUpdate{}
			err = update2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.update.DelegateAddress, update2.DelegateAddress)
			if tt.update.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, update2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Signature, update2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Address, update2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, update2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestGlobalAlert_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		alert *GlobalAlert
	}{
		{
			name: "complete global alert",
			alert: &GlobalAlert{
				Message:   "Critical alert: Network maintenance scheduled",
				Signature: make([]byte, 114), // Ed448 signature size
			},
		},
		{
			name: "empty global alert",
			alert: &GlobalAlert{
				Message:   "",
				Signature: []byte{},
			},
		},
		{
			name: "alert with short message",
			alert: &GlobalAlert{
				Message:   "Alert",
				Signature: append([]byte{0xAA}, make([]byte, 113)...),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.alert.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			alert2 := &GlobalAlert{}
			err = alert2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.alert.Message, alert2.Message)
			assert.Equal(t, tt.alert.Signature, alert2.Signature)
		})
	}
}

func TestProverLeave_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		leave *ProverLeave
	}{
		{
			name: "complete prover leave",
			leave: &ProverLeave{
				Filters:     [][]byte{make([]byte, 32), append([]byte{0xAA}, make([]byte, 31)...)},
				FrameNumber: 54321,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "minimal prover leave",
			leave: &ProverLeave{
				Filters:                    [][]byte{},
				FrameNumber:                0,
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.leave.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			leave2 := &ProverLeave{}
			err = leave2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.leave.Filters, leave2.Filters)
			assert.Equal(t, tt.leave.FrameNumber, leave2.FrameNumber)

			if tt.leave.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, leave2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.leave.PublicKeySignatureBls48581.Signature, leave2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.leave.PublicKeySignatureBls48581.Address, leave2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, leave2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestProverPause_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		pause *ProverPause
	}{
		{
			name: "complete prover pause",
			pause: &ProverPause{
				Filter:      make([]byte, 32),
				FrameNumber: 99999,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.pause.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			pause2 := &ProverPause{}
			err = pause2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.pause.Filter, pause2.Filter)
			assert.Equal(t, tt.pause.FrameNumber, pause2.FrameNumber)
			assert.NotNil(t, pause2.PublicKeySignatureBls48581)
			assert.Equal(t, tt.pause.PublicKeySignatureBls48581.Signature, pause2.PublicKeySignatureBls48581.Signature)
		})
	}
}

func TestProverResume_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		resume *ProverResume
	}{
		{
			name: "complete prover resume",
			resume: &ProverResume{
				Filter:      make([]byte, 32),
				FrameNumber: 77777,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "minimal prover resume",
			resume: &ProverResume{
				Filter:                     []byte{},
				FrameNumber:                0,
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.resume.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			resume2 := &ProverResume{}
			err = resume2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.resume.Filter, resume2.Filter)
			assert.Equal(t, tt.resume.FrameNumber, resume2.FrameNumber)
			if tt.resume.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, resume2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.resume.PublicKeySignatureBls48581.Signature, resume2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.resume.PublicKeySignatureBls48581.Address, resume2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, resume2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestProverConfirm_Serialization(t *testing.T) {
	tests := []struct {
		name    string
		confirm *ProverConfirm
	}{
		{
			name: "complete prover confirm",
			confirm: &ProverConfirm{
				Filter:      make([]byte, 32),
				FrameNumber: 33333,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "minimal prover confirm",
			confirm: &ProverConfirm{
				Filter:                     []byte{},
				FrameNumber:                0,
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.confirm.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			confirm2 := &ProverConfirm{}
			err = confirm2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.confirm.Filter, confirm2.Filter)
			assert.Equal(t, tt.confirm.FrameNumber, confirm2.FrameNumber)
			if tt.confirm.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, confirm2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.confirm.PublicKeySignatureBls48581.Signature, confirm2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.confirm.PublicKeySignatureBls48581.Address, confirm2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, confirm2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestProverReject_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		reject *ProverReject
	}{
		{
			name: "complete prover reject",
			reject: &ProverReject{
				Filter:      make([]byte, 32),
				FrameNumber: 44444,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "minimal prover reject",
			reject: &ProverReject{
				Filter:                     []byte{},
				FrameNumber:                0,
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.reject.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			reject2 := &ProverReject{}
			err = reject2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.reject.Filter, reject2.Filter)
			assert.Equal(t, tt.reject.FrameNumber, reject2.FrameNumber)
			if tt.reject.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, reject2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.reject.PublicKeySignatureBls48581.Signature, reject2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.reject.PublicKeySignatureBls48581.Address, reject2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, reject2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestProverKick_Serialization(t *testing.T) {
	tests := []struct {
		name string
		kick *ProverKick
	}{
		{
			name: "complete prover kick",
			kick: &ProverKick{
				FrameNumber:           66666,
				KickedProverPublicKey: make([]byte, 57), // Ed448 public key
				ConflictingFrame_1:    make([]byte, 32),
				ConflictingFrame_2:    make([]byte, 32),
				Commitment:            make([]byte, 32),
				Proof:                 make([]byte, 128),
				TraversalProof: &TraversalProof{
					Multiproof: &Multiproof{
						Multicommitment: make([]byte, 32),
						Proof:           make([]byte, 64),
					},
					SubProofs: []*TraversalSubProof{
						{
							Commits: [][]byte{make([]byte, 32)},
							Ys:      [][]byte{make([]byte, 48)},
							Paths:   []*Path{{Indices: []uint64{1, 2}}},
						},
					},
				},
			},
		},
		{
			name: "minimal prover kick",
			kick: &ProverKick{
				FrameNumber:           0,
				KickedProverPublicKey: []byte{},
				ConflictingFrame_1:    []byte{},
				ConflictingFrame_2:    []byte{},
				Commitment:            []byte{},
				Proof:                 []byte{},
				TraversalProof:        nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.kick.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			kick2 := &ProverKick{}
			err = kick2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.kick.FrameNumber, kick2.FrameNumber)
			assert.Equal(t, tt.kick.KickedProverPublicKey, kick2.KickedProverPublicKey)
			assert.Equal(t, tt.kick.ConflictingFrame_1, kick2.ConflictingFrame_1)
			assert.Equal(t, tt.kick.ConflictingFrame_2, kick2.ConflictingFrame_2)
			assert.Equal(t, tt.kick.Commitment, kick2.Commitment)
			assert.Equal(t, tt.kick.Proof, kick2.Proof)
			if tt.kick.TraversalProof != nil {
				assert.NotNil(t, kick2.TraversalProof)
				assert.NotNil(t, kick2.TraversalProof.Multiproof)
				assert.Equal(t, len(tt.kick.TraversalProof.SubProofs), len(kick2.TraversalProof.SubProofs))
			} else {
				assert.Nil(t, kick2.TraversalProof)
			}
		})
	}
}

func TestProverLivenessCheck_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		check *ProverLivenessCheck
	}{
		{
			name: "complete liveness check",
			check: &ProverLivenessCheck{
				Filter:         make([]byte, 32),
				FrameNumber:    88888,
				Timestamp:      1234567890123,
				CommitmentHash: make([]byte, 32),
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.check.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			check2 := &ProverLivenessCheck{}
			err = check2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.check.Filter, check2.Filter)
			assert.Equal(t, tt.check.FrameNumber, check2.FrameNumber)
			assert.Equal(t, tt.check.Timestamp, check2.Timestamp)
			assert.Equal(t, tt.check.CommitmentHash, check2.CommitmentHash)
			if tt.check.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, check2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.check.PublicKeySignatureBls48581.Signature, check2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.check.PublicKeySignatureBls48581.Address, check2.PublicKeySignatureBls48581.Address)
			} else {
				assert.Nil(t, check2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestFrameVote_Serialization(t *testing.T) {
	tests := []struct {
		name string
		vote *FrameVote
	}{
		{
			name: "complete frame vote approve",
			vote: &FrameVote{
				FrameNumber: 77777,
				Proposer:    make([]byte, 32),
				Approve:     true,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: make([]byte, 74),
					Address:   make([]byte, 32),
				},
			},
		},
		{
			name: "frame vote reject",
			vote: &FrameVote{
				FrameNumber: 88888,
				Proposer:    append([]byte{0xFF}, make([]byte, 31)...),
				Approve:     false,
				PublicKeySignatureBls48581: &BLS48581AddressedSignature{
					Signature: append([]byte{0xAA}, make([]byte, 73)...),
					Address:   append([]byte{0xCC}, make([]byte, 31)...),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.vote.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			vote2 := &FrameVote{}
			err = vote2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.vote.FrameNumber, vote2.FrameNumber)
			assert.Equal(t, tt.vote.Proposer, vote2.Proposer)
			assert.Equal(t, tt.vote.Approve, vote2.Approve)
			assert.NotNil(t, vote2.PublicKeySignatureBls48581)
			assert.Equal(t, tt.vote.PublicKeySignatureBls48581.Signature, vote2.PublicKeySignatureBls48581.Signature)
			assert.Equal(t, tt.vote.PublicKeySignatureBls48581.Address, vote2.PublicKeySignatureBls48581.Address)
		})
	}
}

func TestFrameConfirmation_Serialization(t *testing.T) {
	tests := []struct {
		name string
		conf *FrameConfirmation
	}{
		{
			name: "complete frame confirmation",
			conf: &FrameConfirmation{
				FrameNumber: 12345,
				Selector:    make([]byte, 32),
				AggregateSignature: &BLS48581AggregateSignature{
					Signature: make([]byte, 74),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
					Bitmask: make([]byte, 32),
				},
			},
		},
		{
			name: "minimal frame confirmation",
			conf: &FrameConfirmation{
				FrameNumber:        0,
				Selector:           []byte{},
				AggregateSignature: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.conf.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			conf2 := &FrameConfirmation{}
			err = conf2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.conf.FrameNumber, conf2.FrameNumber)
			assert.Equal(t, tt.conf.Selector, conf2.Selector)
			if tt.conf.AggregateSignature != nil {
				assert.NotNil(t, conf2.AggregateSignature)
				assert.Equal(t, tt.conf.AggregateSignature.Signature, conf2.AggregateSignature.Signature)
				assert.Equal(t, tt.conf.AggregateSignature.Bitmask, conf2.AggregateSignature.Bitmask)
				if tt.conf.AggregateSignature.PublicKey != nil {
					assert.NotNil(t, conf2.AggregateSignature.PublicKey)
					assert.Equal(t, tt.conf.AggregateSignature.PublicKey.KeyValue, conf2.AggregateSignature.PublicKey.KeyValue)
				}
			} else {
				assert.Nil(t, conf2.AggregateSignature)
			}
		})
	}
}

func TestGlobalFrameHeader_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		header *GlobalFrameHeader
	}{
		{
			name: "complete global frame header",
			header: &GlobalFrameHeader{
				FrameNumber:    54321,
				Timestamp:      9876543210123,
				Difficulty:     2000000,
				Output:         make([]byte, 516),
				ParentSelector: make([]byte, 32),
				GlobalCommitments: [][]byte{
					make([]byte, 32),
					make([]byte, 32),
					make([]byte, 32),
				},
				ProverTreeCommitment: make([]byte, 32),
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					Signature: make([]byte, 74),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
					Bitmask: make([]byte, 32),
				},
			},
		},
		{
			name: "minimal global frame header",
			header: &GlobalFrameHeader{
				FrameNumber:                0,
				Timestamp:                  0,
				Difficulty:                 0,
				Output:                     []byte{},
				ParentSelector:             []byte{},
				GlobalCommitments:          [][]byte{},
				ProverTreeCommitment:       []byte{},
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.header.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			header2 := &GlobalFrameHeader{}
			err = header2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.header.FrameNumber, header2.FrameNumber)
			assert.Equal(t, tt.header.Timestamp, header2.Timestamp)
			assert.Equal(t, tt.header.Difficulty, header2.Difficulty)
			assert.Equal(t, tt.header.Output, header2.Output)
			assert.Equal(t, tt.header.ParentSelector, header2.ParentSelector)
			assert.Equal(t, tt.header.GlobalCommitments, header2.GlobalCommitments)
			assert.Equal(t, tt.header.ProverTreeCommitment, header2.ProverTreeCommitment)
			if tt.header.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, header2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.header.PublicKeySignatureBls48581.Signature, header2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.header.PublicKeySignatureBls48581.Bitmask, header2.PublicKeySignatureBls48581.Bitmask)
				if tt.header.PublicKeySignatureBls48581.PublicKey != nil {
					assert.NotNil(t, header2.PublicKeySignatureBls48581.PublicKey)
					assert.Equal(t, tt.header.PublicKeySignatureBls48581.PublicKey.KeyValue, header2.PublicKeySignatureBls48581.PublicKey.KeyValue)
				}
			} else {
				assert.Nil(t, header2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestGlobalFrame_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		frame *GlobalFrame
	}{
		{
			name: "complete global frame",
			frame: &GlobalFrame{
				Header: &GlobalFrameHeader{
					FrameNumber:    11111,
					Timestamp:      1111111111111,
					Difficulty:     1500000,
					Output:         make([]byte, 516),
					ParentSelector: make([]byte, 32),
					GlobalCommitments: [][]byte{
						make([]byte, 32),
						make([]byte, 32),
					},
					ProverTreeCommitment: make([]byte, 32),
					PublicKeySignatureBls48581: &BLS48581AggregateSignature{
						Signature: make([]byte, 74),
						PublicKey: &BLS48581G2PublicKey{
							KeyValue: make([]byte, 585),
						},
						Bitmask: make([]byte, 32),
					},
				},
				Requests: []*MessageBundle{
					{
						Requests:  []*MessageRequest{},
						Timestamp: 1234567890123,
					},
					{
						Requests: []*MessageRequest{
							{
								Request: &MessageRequest_Join{
									Join: &ProverJoin{
										Filters:     [][]byte{make([]byte, 32)},
										FrameNumber: 12345,
										PublicKeySignatureBls48581: &BLS48581SignatureWithProofOfPossession{
											Signature:    make([]byte, 74),
											PopSignature: make([]byte, 74),
											PublicKey: &BLS48581G2PublicKey{
												KeyValue: make([]byte, 585),
											},
										},
										DelegateAddress: make([]byte, 32),
										MergeTargets:    []*SeniorityMerge{},
									},
								},
							},
						},
						Timestamp: 1234567890456,
					},
				},
			},
		},
		{
			name: "minimal global frame",
			frame: &GlobalFrame{
				Header:   nil,
				Requests: []*MessageBundle{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.frame.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			frame2 := &GlobalFrame{}
			err = frame2.FromCanonicalBytes(data)
			require.NoError(t, err)

			if tt.frame.Header != nil {
				assert.NotNil(t, frame2.Header)
				assert.Equal(t, tt.frame.Header.FrameNumber, frame2.Header.FrameNumber)
				assert.Equal(t, tt.frame.Header.Timestamp, frame2.Header.Timestamp)
				assert.Equal(t, tt.frame.Header.Difficulty, frame2.Header.Difficulty)
				assert.Equal(t, tt.frame.Header.Output, frame2.Header.Output)
				assert.Equal(t, tt.frame.Header.ParentSelector, frame2.Header.ParentSelector)
				assert.Equal(t, tt.frame.Header.GlobalCommitments, frame2.Header.GlobalCommitments)
				assert.Equal(t, tt.frame.Header.ProverTreeCommitment, frame2.Header.ProverTreeCommitment)
			} else {
				assert.Nil(t, frame2.Header)
			}
			assert.Equal(t, len(tt.frame.Requests), len(frame2.Requests))
			for i := range tt.frame.Requests {
				assert.Equal(t, tt.frame.Requests[i].Timestamp, frame2.Requests[i].Timestamp)
				assert.Equal(t, len(tt.frame.Requests[i].Requests), len(frame2.Requests[i].Requests))
				for j := range tt.frame.Requests[i].Requests {
					assert.NotNil(t, frame2.Requests[i].Requests[j].Request)
					// Verify the union type was preserved (basic check)
					if joinReq, ok := tt.frame.Requests[i].Requests[j].Request.(*MessageRequest_Join); ok {
						join2, ok2 := frame2.Requests[i].Requests[j].Request.(*MessageRequest_Join)
						assert.True(t, ok2)
						if ok2 {
							assert.Equal(t, joinReq.Join.FrameNumber, join2.Join.FrameNumber)
							assert.Equal(t, joinReq.Join.Filters, join2.Join.Filters)
						}
					}
				}
			}
		})
	}
}

func TestAppShardFrame_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		frame *AppShardFrame
	}{
		{
			name: "complete app shard frame",
			frame: &AppShardFrame{
				Header: &FrameHeader{
					Address:           make([]byte, 32),
					FrameNumber:       67890,
					Timestamp:         1234567890123,
					Difficulty:        500000,
					Output:            make([]byte, 516),
					ParentSelector:    make([]byte, 32),
					RequestsRoot:      make([]byte, 32),
					StateRoots:        [][]byte{make([]byte, 32), make([]byte, 32)},
					Prover:            make([]byte, 32),
					FeeMultiplierVote: 250,
					PublicKeySignatureBls48581: &BLS48581AggregateSignature{
						Signature: make([]byte, 74),
						PublicKey: &BLS48581G2PublicKey{
							KeyValue: make([]byte, 585),
						},
						Bitmask: make([]byte, 32),
					},
				},
				Requests: []*MessageBundle{
					{
						Requests:  []*MessageRequest{},
						Timestamp: 1234567890123,
					},
					{
						Requests: []*MessageRequest{
							{
								Request: &MessageRequest_Join{
									Join: &ProverJoin{
										Filters:     [][]byte{make([]byte, 32)},
										FrameNumber: 67890,
										PublicKeySignatureBls48581: &BLS48581SignatureWithProofOfPossession{
											Signature:    make([]byte, 74),
											PopSignature: make([]byte, 74),
											PublicKey: &BLS48581G2PublicKey{
												KeyValue: make([]byte, 585),
											},
										},
										DelegateAddress: make([]byte, 32),
										MergeTargets:    []*SeniorityMerge{},
									},
								},
							},
						},
						Timestamp: 1234567890456,
					},
				},
			},
		},
		{
			name: "minimal app shard frame",
			frame: &AppShardFrame{
				Header:   nil,
				Requests: []*MessageBundle{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.frame.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			frame2 := &AppShardFrame{}
			err = frame2.FromCanonicalBytes(data)
			require.NoError(t, err)

			if tt.frame.Header != nil {
				assert.NotNil(t, frame2.Header)
				assert.Equal(t, tt.frame.Header.Address, frame2.Header.Address)
				assert.Equal(t, tt.frame.Header.FrameNumber, frame2.Header.FrameNumber)
				assert.Equal(t, tt.frame.Header.Timestamp, frame2.Header.Timestamp)
				assert.Equal(t, tt.frame.Header.Difficulty, frame2.Header.Difficulty)
				assert.Equal(t, tt.frame.Header.Output, frame2.Header.Output)
				assert.Equal(t, tt.frame.Header.ParentSelector, frame2.Header.ParentSelector)
				assert.Equal(t, tt.frame.Header.RequestsRoot, frame2.Header.RequestsRoot)
				assert.Equal(t, tt.frame.Header.StateRoots, frame2.Header.StateRoots)
				assert.Equal(t, tt.frame.Header.Prover, frame2.Header.Prover)
				assert.Equal(t, tt.frame.Header.FeeMultiplierVote, frame2.Header.FeeMultiplierVote)
				if tt.frame.Header.PublicKeySignatureBls48581 != nil {
					assert.NotNil(t, frame2.Header.PublicKeySignatureBls48581)
					assert.Equal(t, tt.frame.Header.PublicKeySignatureBls48581.Signature, frame2.Header.PublicKeySignatureBls48581.Signature)
					assert.Equal(t, tt.frame.Header.PublicKeySignatureBls48581.Bitmask, frame2.Header.PublicKeySignatureBls48581.Bitmask)
				}
			} else {
				assert.Nil(t, frame2.Header)
			}
			assert.Equal(t, len(tt.frame.Requests), len(frame2.Requests))
			for i := range tt.frame.Requests {
				assert.Equal(t, tt.frame.Requests[i].Timestamp, frame2.Requests[i].Timestamp)
				assert.Equal(t, len(tt.frame.Requests[i].Requests), len(frame2.Requests[i].Requests))
				for j := range tt.frame.Requests[i].Requests {
					assert.NotNil(t, frame2.Requests[i].Requests[j].Request)
				}
			}
		})
	}
}

func TestMessageBundle_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		bundle *MessageBundle
	}{
		{
			name: "complete message bundle",
			bundle: &MessageBundle{
				Requests: []*MessageRequest{
					{
						Request: &MessageRequest_Join{
							Join: &ProverJoin{
								Filters:     [][]byte{make([]byte, 32)},
								FrameNumber: 12345,
								PublicKeySignatureBls48581: &BLS48581SignatureWithProofOfPossession{
									Signature:    make([]byte, 74),
									PopSignature: make([]byte, 74),
									PublicKey: &BLS48581G2PublicKey{
										KeyValue: make([]byte, 585),
									},
								},
								DelegateAddress: make([]byte, 32),
								MergeTargets:    []*SeniorityMerge{},
							},
						},
					},
					{
						Request: &MessageRequest_Leave{
							Leave: &ProverLeave{
								Filters:     [][]byte{append([]byte{0xFF}, make([]byte, 31)...)},
								FrameNumber: 67890,
								PublicKeySignatureBls48581: &BLS48581AddressedSignature{
									Signature: make([]byte, 74),
									Address:   make([]byte, 32),
								},
							},
						},
					},
				},
				Timestamp: 1234567890123,
			},
		},
		{
			name: "empty message bundle",
			bundle: &MessageBundle{
				Requests:  []*MessageRequest{},
				Timestamp: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.bundle.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			bundle2 := &MessageBundle{}
			err = bundle2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.bundle.Timestamp, bundle2.Timestamp)
			assert.Equal(t, len(tt.bundle.Requests), len(bundle2.Requests))
			for i := range tt.bundle.Requests {
				assert.NotNil(t, bundle2.Requests[i].Request)
				// Verify the union type was preserved (basic check)
				if joinReq, ok := tt.bundle.Requests[i].Request.(*MessageRequest_Join); ok {
					join2, ok2 := bundle2.Requests[i].Request.(*MessageRequest_Join)
					assert.True(t, ok2)
					if ok2 {
						assert.Equal(t, joinReq.Join.FrameNumber, join2.Join.FrameNumber)
						assert.Equal(t, joinReq.Join.Filters, join2.Join.Filters)
					}
				} else if leaveReq, ok := tt.bundle.Requests[i].Request.(*MessageRequest_Leave); ok {
					leave2, ok2 := bundle2.Requests[i].Request.(*MessageRequest_Leave)
					assert.True(t, ok2)
					if ok2 {
						assert.Equal(t, leaveReq.Leave.FrameNumber, leave2.Leave.FrameNumber)
						assert.Equal(t, leaveReq.Leave.Filters, leave2.Leave.Filters)
					}
				}
			}
		})
	}
}

func TestMultiproof_Serialization(t *testing.T) {
	tests := []struct {
		name       string
		multiproof *Multiproof
	}{
		{
			name: "complete multiproof",
			multiproof: &Multiproof{
				Multicommitment: make([]byte, 32),
				Proof:           make([]byte, 256),
			},
		},
		{
			name: "multiproof with different sizes",
			multiproof: &Multiproof{
				Multicommitment: append([]byte{0xAA}, make([]byte, 31)...),
				Proof:           append([]byte{0xBB}, make([]byte, 255)...),
			},
		},
		{
			name: "minimal multiproof",
			multiproof: &Multiproof{
				Multicommitment: []byte{},
				Proof:           []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.multiproof.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			multiproof2 := &Multiproof{}
			err = multiproof2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.multiproof.Multicommitment, multiproof2.Multicommitment)
			assert.Equal(t, tt.multiproof.Proof, multiproof2.Proof)
		})
	}
}

func TestPath_Serialization(t *testing.T) {
	tests := []struct {
		name string
		path *Path
	}{
		{
			name: "complete path",
			path: &Path{
				Indices: []uint64{1, 2, 3, 4, 5},
			},
		},
		{
			name: "single index path",
			path: &Path{
				Indices: []uint64{42},
			},
		},
		{
			name: "empty path",
			path: &Path{
				Indices: []uint64{},
			},
		},
		{
			name: "path with large indices",
			path: &Path{
				Indices: []uint64{1<<63 - 1, 1<<32 - 1, 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.path.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			path2 := &Path{}
			err = path2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.path.Indices, path2.Indices)
		})
	}
}

func TestTraversalSubProof_Serialization(t *testing.T) {
	tests := []struct {
		name     string
		subProof *TraversalSubProof
	}{
		{
			name: "complete traversal sub proof",
			subProof: &TraversalSubProof{
				Commits: [][]byte{
					make([]byte, 32),
					make([]byte, 32),
				},
				Ys: [][]byte{
					make([]byte, 48),
					make([]byte, 48),
				},
				Paths: []*Path{
					{Indices: []uint64{1, 2, 3}},
					{Indices: []uint64{4, 5}},
				},
			},
		},
		{
			name: "minimal traversal sub proof",
			subProof: &TraversalSubProof{
				Commits: [][]byte{},
				Ys:      [][]byte{},
				Paths:   []*Path{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.subProof.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			subProof2 := &TraversalSubProof{}
			err = subProof2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.subProof.Commits, subProof2.Commits)
			assert.Equal(t, tt.subProof.Ys, subProof2.Ys)
			assert.Equal(t, len(tt.subProof.Paths), len(subProof2.Paths))
			for i := range tt.subProof.Paths {
				assert.Equal(t, tt.subProof.Paths[i].Indices, subProof2.Paths[i].Indices)
			}
		})
	}
}

func TestTraversalProof_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		proof *TraversalProof
	}{
		{
			name: "complete traversal proof",
			proof: &TraversalProof{
				Multiproof: &Multiproof{
					Multicommitment: make([]byte, 32),
					Proof:           make([]byte, 128),
				},
				SubProofs: []*TraversalSubProof{
					{
						Commits: [][]byte{make([]byte, 32)},
						Ys:      [][]byte{make([]byte, 48)},
						Paths:   []*Path{{Indices: []uint64{1, 2}}},
					},
					{
						Commits: [][]byte{make([]byte, 32), make([]byte, 32)},
						Ys:      [][]byte{make([]byte, 48), make([]byte, 48)},
						Paths:   []*Path{{Indices: []uint64{3, 4, 5}}},
					},
				},
			},
		},
		{
			name: "minimal traversal proof",
			proof: &TraversalProof{
				Multiproof: &Multiproof{
					Multicommitment: []byte{},
					Proof:           []byte{},
				},
				SubProofs: []*TraversalSubProof{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.proof.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			proof2 := &TraversalProof{}
			err = proof2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.NotNil(t, proof2.Multiproof)
			assert.Equal(t, tt.proof.Multiproof.Multicommitment, proof2.Multiproof.Multicommitment)
			assert.Equal(t, tt.proof.Multiproof.Proof, proof2.Multiproof.Proof)
			assert.Equal(t, len(tt.proof.SubProofs), len(proof2.SubProofs))
			for i := range tt.proof.SubProofs {
				assert.Equal(t, tt.proof.SubProofs[i].Commits, proof2.SubProofs[i].Commits)
				assert.Equal(t, tt.proof.SubProofs[i].Ys, proof2.SubProofs[i].Ys)
				assert.Equal(t, len(tt.proof.SubProofs[i].Paths), len(proof2.SubProofs[i].Paths))
			}
		})
	}
}
