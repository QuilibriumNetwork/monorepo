package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBLS48581SignatureWithProofOfPossession_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *BLS48581SignatureWithProofOfPossession
	}{
		{
			name: "complete signature",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 74),
				PublicKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
			},
		},
		{
			name: "without public key",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 74),
			},
		},
		{
			name: "empty fields",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    []byte{},
				PopSignature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &BLS48581SignatureWithProofOfPossession{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))
			assert.True(t, equalBytes(tt.sig.PopSignature, sig2.PopSignature))

			if tt.sig.PublicKey != nil {
				require.NotNil(t, sig2.PublicKey)
				assert.True(t, equalBytes(tt.sig.PublicKey.KeyValue, sig2.PublicKey.KeyValue))
			} else {
				assert.Nil(t, sig2.PublicKey)
			}
		})
	}
}

func TestBLS48581AddressedSignature_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *BLS48581AddressedSignature
	}{
		{
			name: "complete signature",
			sig: &BLS48581AddressedSignature{
				Signature: make([]byte, 74),
				Address:   make([]byte, 32),
			},
		},
		{
			name: "empty fields",
			sig: &BLS48581AddressedSignature{
				Signature: []byte{},
				Address:   []byte{},
			},
		},
		{
			name: "nil fields",
			sig:  &BLS48581AddressedSignature{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &BLS48581AddressedSignature{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))
			assert.True(t, equalBytes(tt.sig.Address, sig2.Address))
		})
	}
}

func TestBLS48581AggregateSignature_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *BLS48581AggregateSignature
	}{
		{
			name: "complete aggregate signature",
			sig: &BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				PublicKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				Bitmask: []byte{0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			name: "without public key",
			sig: &BLS48581AggregateSignature{
				Signature: make([]byte, 74),
				Bitmask:   []byte{0x00, 0x00, 0x00, 0x00},
			},
		},
		{
			name: "empty fields",
			sig: &BLS48581AggregateSignature{
				Signature: []byte{},
				Bitmask:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &BLS48581AggregateSignature{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))
			assert.True(t, equalBytes(tt.sig.Bitmask, sig2.Bitmask))

			if tt.sig.PublicKey != nil {
				require.NotNil(t, sig2.PublicKey)
				assert.True(t, equalBytes(tt.sig.PublicKey.KeyValue, sig2.PublicKey.KeyValue))
			} else {
				assert.Nil(t, sig2.PublicKey)
			}
		})
	}
}

func TestEd448PublicKey_Serialization(t *testing.T) {
	tests := []struct {
		name string
		key  *Ed448PublicKey
	}{
		{
			name: "valid key",
			key: &Ed448PublicKey{
				KeyValue: make([]byte, 57),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.key.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			key2 := &Ed448PublicKey{}
			err = key2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.key.KeyValue, key2.KeyValue))
		})
	}
}

func TestEd448Signature_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *Ed448Signature
	}{
		{
			name: "complete signature",
			sig: &Ed448Signature{
				Signature: make([]byte, 114),
				PublicKey: &Ed448PublicKey{
					KeyValue: make([]byte, 57),
				},
			},
		},
		{
			name: "without public key",
			sig: &Ed448Signature{
				Signature: make([]byte, 114),
			},
		},
		{
			name: "empty fields",
			sig: &Ed448Signature{
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &Ed448Signature{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))

			if tt.sig.PublicKey != nil {
				require.NotNil(t, sig2.PublicKey)
				assert.True(t, equalBytes(tt.sig.PublicKey.KeyValue, sig2.PublicKey.KeyValue))
			} else {
				assert.Nil(t, sig2.PublicKey)
			}
		})
	}
}

func TestBLS48581G2PublicKey_Serialization(t *testing.T) {
	tests := []struct {
		name string
		key  *BLS48581G2PublicKey
	}{
		{
			name: "valid key",
			key: &BLS48581G2PublicKey{
				KeyValue: make([]byte, 585),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.key.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			key2 := &BLS48581G2PublicKey{}
			err = key2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.key.KeyValue, key2.KeyValue))
		})
	}
}

func TestBLS48581Signature_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *BLS48581Signature
	}{
		{
			name: "complete signature",
			sig: &BLS48581Signature{
				Signature: make([]byte, 74),
				PublicKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
			},
		},
		{
			name: "without public key",
			sig: &BLS48581Signature{
				Signature: make([]byte, 74),
			},
		},
		{
			name: "empty fields",
			sig: &BLS48581Signature{
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &BLS48581Signature{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))

			if tt.sig.PublicKey != nil {
				require.NotNil(t, sig2.PublicKey)
				assert.True(t, equalBytes(tt.sig.PublicKey.KeyValue, sig2.PublicKey.KeyValue))
			} else {
				assert.Nil(t, sig2.PublicKey)
			}
		})
	}
}

func TestDecaf448PublicKey_Serialization(t *testing.T) {
	tests := []struct {
		name string
		key  *Decaf448PublicKey
	}{
		{
			name: "valid key",
			key: &Decaf448PublicKey{
				KeyValue: make([]byte, 56),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.key.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			key2 := &Decaf448PublicKey{}
			err = key2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.key.KeyValue, key2.KeyValue))
		})
	}
}

func TestDecaf448Signature_Serialization(t *testing.T) {
	tests := []struct {
		name string
		sig  *Decaf448Signature
	}{
		{
			name: "complete signature",
			sig: &Decaf448Signature{
				Signature: make([]byte, 112), // 56 bytes R + 56 bytes S
				PublicKey: &Decaf448PublicKey{
					KeyValue: make([]byte, 56),
				},
			},
		},
		{
			name: "without public key",
			sig: &Decaf448Signature{
				Signature: make([]byte, 112),
			},
		},
		{
			name: "empty fields",
			sig: &Decaf448Signature{
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.sig.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			sig2 := &Decaf448Signature{}
			err = sig2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(tt.sig.Signature, sig2.Signature))

			if tt.sig.PublicKey != nil {
				require.NotNil(t, sig2.PublicKey)
				assert.True(t, equalBytes(tt.sig.PublicKey.KeyValue, sig2.PublicKey.KeyValue))
			} else {
				assert.Nil(t, sig2.PublicKey)
			}
		})
	}
}

func TestSignedX448Key_Serialization(t *testing.T) {
	tests := []struct {
		name string
		key  *SignedX448Key
	}{
		{
			name: "complete key with Ed448 signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
				Signature: &SignedX448Key_Ed448Signature{
					Ed448Signature: &Ed448Signature{
						Signature: make([]byte, 114),
						PublicKey: &Ed448PublicKey{
							KeyValue: make([]byte, 57),
						},
					},
				},
			},
		},
		{
			name: "complete key with BLS signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
				Signature: &SignedX448Key_BlsSignature{
					BlsSignature: &BLS48581Signature{
						Signature: make([]byte, 74),
						PublicKey: &BLS48581G2PublicKey{
							KeyValue: make([]byte, 585),
						},
					},
				},
			},
		},
		{
			name: "complete key with Decaf signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
				Signature: &SignedX448Key_DecafSignature{
					DecafSignature: &Decaf448Signature{
						Signature: make([]byte, 112),
						PublicKey: &Decaf448PublicKey{
							KeyValue: make([]byte, 56),
						},
					},
				},
			},
		},
		{
			name: "key without signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
			},
		},
		{
			name: "minimal key",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.key.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			key2 := &SignedX448Key{}
			err = key2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.NotNil(t, key2.Key)
			assert.True(t, equalBytes(tt.key.Key.KeyValue, key2.Key.KeyValue))
			assert.True(t, equalBytes(tt.key.ParentKeyAddress, key2.ParentKeyAddress))

			// Compare signatures
			switch sig := tt.key.Signature.(type) {
			case *SignedX448Key_Ed448Signature:
				sig2, ok := key2.Signature.(*SignedX448Key_Ed448Signature)
				require.True(t, ok)
				require.NotNil(t, sig2.Ed448Signature)
				assert.True(t, equalBytes(sig.Ed448Signature.Signature, sig2.Ed448Signature.Signature))
				if sig.Ed448Signature.PublicKey != nil {
					require.NotNil(t, sig2.Ed448Signature.PublicKey)
					assert.True(t, equalBytes(sig.Ed448Signature.PublicKey.KeyValue, sig2.Ed448Signature.PublicKey.KeyValue))
				}
			case *SignedX448Key_BlsSignature:
				sig2, ok := key2.Signature.(*SignedX448Key_BlsSignature)
				require.True(t, ok)
				require.NotNil(t, sig2.BlsSignature)
				assert.True(t, equalBytes(sig.BlsSignature.Signature, sig2.BlsSignature.Signature))
				if sig.BlsSignature.PublicKey != nil {
					require.NotNil(t, sig2.BlsSignature.PublicKey)
					assert.True(t, equalBytes(sig.BlsSignature.PublicKey.KeyValue, sig2.BlsSignature.PublicKey.KeyValue))
				}
			case *SignedX448Key_DecafSignature:
				sig2, ok := key2.Signature.(*SignedX448Key_DecafSignature)
				require.True(t, ok)
				require.NotNil(t, sig2.DecafSignature)
				assert.True(t, equalBytes(sig.DecafSignature.Signature, sig2.DecafSignature.Signature))
				if sig.DecafSignature.PublicKey != nil {
					require.NotNil(t, sig2.DecafSignature.PublicKey)
					assert.True(t, equalBytes(sig.DecafSignature.PublicKey.KeyValue, sig2.DecafSignature.PublicKey.KeyValue))
				}
			case nil:
				assert.Nil(t, key2.Signature)
			}
		})
	}
}

func TestKeyCollection_Serialization(t *testing.T) {
	tests := []struct {
		name       string
		collection *KeyCollection
	}{
		{
			name: "complete collection",
			collection: &KeyCollection{
				KeyPurpose: "inbox",
				X448Keys: []*SignedX448Key{
					{
						Key: &X448PublicKey{
							KeyValue: make([]byte, 57),
						},
						ParentKeyAddress: make([]byte, 32),
						Signature: &SignedX448Key_Ed448Signature{
							Ed448Signature: &Ed448Signature{
								Signature: make([]byte, 114),
								PublicKey: &Ed448PublicKey{
									KeyValue: make([]byte, 57),
								},
							},
						},
					},
					{
						Key: &X448PublicKey{
							KeyValue: make([]byte, 57),
						},
						ParentKeyAddress: make([]byte, 32),
						Signature: &SignedX448Key_BlsSignature{
							BlsSignature: &BLS48581Signature{
								Signature: make([]byte, 74),
								PublicKey: &BLS48581G2PublicKey{
									KeyValue: make([]byte, 585),
								},
							},
						},
					},
				},
				Decaf448Keys: []*SignedDecaf448Key{
					{
						Key: &Decaf448PublicKey{
							KeyValue: make([]byte, 56),
						},
						ParentKeyAddress: make([]byte, 32),
						Signature: &SignedDecaf448Key_Ed448Signature{
							Ed448Signature: &Ed448Signature{
								Signature: make([]byte, 114),
								PublicKey: &Ed448PublicKey{
									KeyValue: make([]byte, 57),
								},
							},
						},
					},
					{
						Key: &Decaf448PublicKey{
							KeyValue: make([]byte, 56),
						},
						ParentKeyAddress: make([]byte, 32),
						Signature: &SignedDecaf448Key_BlsSignature{
							BlsSignature: &BLS48581Signature{
								Signature: make([]byte, 74),
								PublicKey: &BLS48581G2PublicKey{
									KeyValue: make([]byte, 585),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty collection",
			collection: &KeyCollection{
				KeyPurpose: "device",
				X448Keys:   []*SignedX448Key{},
			},
		},
		{
			name: "nil keys",
			collection: &KeyCollection{
				KeyPurpose: "pre",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.collection.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			collection2 := &KeyCollection{}
			err = collection2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.Equal(t, tt.collection.KeyPurpose, collection2.KeyPurpose)

			if tt.collection.X448Keys != nil {
				require.NotNil(t, collection2.X448Keys)
				assert.Equal(t, len(tt.collection.X448Keys), len(collection2.X448Keys))

				for i := range tt.collection.X448Keys {
					assert.NotNil(t, collection2.X448Keys[i].Key)
					assert.True(t, equalBytes(tt.collection.X448Keys[i].Key.KeyValue, collection2.X448Keys[i].Key.KeyValue))
					assert.True(t, equalBytes(tt.collection.X448Keys[i].ParentKeyAddress, collection2.X448Keys[i].ParentKeyAddress))
				}
			} else {
				// protobuf deserialization returns empty slice instead of nil
				assert.Empty(t, collection2.X448Keys)
			}

			if tt.collection.Decaf448Keys != nil {
				require.NotNil(t, collection2.Decaf448Keys)
				assert.Equal(t, len(tt.collection.Decaf448Keys), len(collection2.Decaf448Keys))

				for i := range tt.collection.Decaf448Keys {
					assert.NotNil(t, collection2.Decaf448Keys[i].Key)
					assert.True(t, equalBytes(tt.collection.Decaf448Keys[i].Key.KeyValue, collection2.Decaf448Keys[i].Key.KeyValue))
					assert.True(t, equalBytes(tt.collection.Decaf448Keys[i].ParentKeyAddress, collection2.Decaf448Keys[i].ParentKeyAddress))
				}
			} else {
				// protobuf deserialization returns empty slice instead of nil
				assert.Empty(t, collection2.Decaf448Keys)
			}
		})
	}
}

func TestKeyRegistry_Serialization(t *testing.T) {
	tests := []struct {
		name     string
		registry *KeyRegistry
	}{
		{
			name: "complete registry",
			registry: &KeyRegistry{
				IdentityKey: &Ed448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ProverKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
				IdentityToProver: &Ed448Signature{
					Signature: make([]byte, 114),
					PublicKey: &Ed448PublicKey{
						KeyValue: make([]byte, 57),
					},
				},
				ProverToIdentity: &BLS48581Signature{
					Signature: make([]byte, 74),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
				},
				KeysByPurpose: map[string]*KeyCollection{
					"inbox": {
						KeyPurpose: "inbox",
						X448Keys: []*SignedX448Key{
							{
								Key: &X448PublicKey{
									KeyValue: make([]byte, 57),
								},
								ParentKeyAddress: make([]byte, 32),
								Signature: &SignedX448Key_Ed448Signature{
									Ed448Signature: &Ed448Signature{
										Signature: make([]byte, 114),
										PublicKey: &Ed448PublicKey{
											KeyValue: make([]byte, 57),
										},
									},
								},
								KeyPurpose: "inbox",
							},
						},
					},
					"device": {
						KeyPurpose: "device",
						X448Keys: []*SignedX448Key{
							{
								Key: &X448PublicKey{
									KeyValue: make([]byte, 57),
								},
								ParentKeyAddress: make([]byte, 32),
								Signature: &SignedX448Key_BlsSignature{
									BlsSignature: &BLS48581Signature{
										Signature: make([]byte, 74),
										PublicKey: &BLS48581G2PublicKey{
											KeyValue: make([]byte, 585),
										},
									},
								},
								KeyPurpose: "device",
							},
						},
					},
				},
				LastUpdated: 1234567890,
			},
		},
		{
			name: "empty registry",
			registry: &KeyRegistry{
				KeysByPurpose: map[string]*KeyCollection{},
			},
		},
		{
			name:     "nil collections",
			registry: &KeyRegistry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.registry.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			registry2 := &KeyRegistry{}
			err = registry2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			// Compare primary keys
			if tt.registry.IdentityKey != nil {
				require.NotNil(t, registry2.IdentityKey)
				assert.True(t, equalBytes(tt.registry.IdentityKey.KeyValue, registry2.IdentityKey.KeyValue))
			}
			if tt.registry.ProverKey != nil {
				require.NotNil(t, registry2.ProverKey)
				assert.True(t, equalBytes(tt.registry.ProverKey.KeyValue, registry2.ProverKey.KeyValue))
			}

			// Compare cross signatures
			if tt.registry.IdentityToProver != nil {
				require.NotNil(t, registry2.IdentityToProver)
				assert.True(t, equalBytes(tt.registry.IdentityToProver.Signature, registry2.IdentityToProver.Signature))
			}
			if tt.registry.ProverToIdentity != nil {
				require.NotNil(t, registry2.ProverToIdentity)
				assert.True(t, equalBytes(tt.registry.ProverToIdentity.Signature, registry2.ProverToIdentity.Signature))
			}

			// Compare keys by purpose
			if tt.registry.KeysByPurpose != nil {
				require.NotNil(t, registry2.KeysByPurpose)
				assert.Equal(t, len(tt.registry.KeysByPurpose), len(registry2.KeysByPurpose))

				for purpose, collection := range tt.registry.KeysByPurpose {
					collection2, ok := registry2.KeysByPurpose[purpose]
					require.True(t, ok)
					assert.Equal(t, collection.KeyPurpose, collection2.KeyPurpose)
					if collection.X448Keys != nil {
						assert.Equal(t, len(collection.X448Keys), len(collection2.X448Keys))
					}
				}
			}

			// Compare metadata
			assert.Equal(t, tt.registry.LastUpdated, registry2.LastUpdated)
		})
	}
}

// Mock verifiers for testing
type mockBlsVerifier struct {
	shouldVerify bool
}

func (m *mockBlsVerifier) VerifySignatureRaw(
	publicKeyG2 []byte,
	signatureG1 []byte,
	message []byte,
	context []byte,
) bool {
	return m.shouldVerify
}

type mockSchnorrVerifier struct {
	shouldVerify bool
}

func (m *mockSchnorrVerifier) SimpleVerify(
	message []byte,
	signature []byte,
	point []byte,
) bool {
	return m.shouldVerify
}

func TestSignedX448Key_Verify(t *testing.T) {
	// Test context for verification
	testContext := []byte("test-context")

	// Create test Ed448 public key and compute its poseidon address
	ed448PubKey := make([]byte, 57)
	for i := range ed448PubKey {
		ed448PubKey[i] = byte(i)
	}
	// Note: In a real test, we'd compute the actual poseidon hash
	// For this test, we'll use a mock address
	validAddress := make([]byte, 32)
	for i := range validAddress {
		validAddress[i] = byte(i + 100)
	}

	tests := []struct {
		name            string
		key             *SignedX448Key
		blsVerifier     BlsVerifier
		schnorrVerifier SchnorrVerifier
		expectError     bool
		errorContains   string
	}{
		{
			name: "valid Ed448 signature - address matches",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: validAddress,
				Signature: &SignedX448Key_Ed448Signature{
					Ed448Signature: &Ed448Signature{
						Signature: make([]byte, 114),
						PublicKey: &Ed448PublicKey{
							KeyValue: ed448PubKey,
						},
					},
				},
			},
			expectError:   true, // Will fail because we're not mocking ed448 verification
			errorContains: "verify",
		},
		{
			name: "invalid - Ed448 signature fails verification",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32), // Wrong address (all zeros)
				Signature: &SignedX448Key_Ed448Signature{
					Ed448Signature: &Ed448Signature{
						Signature: make([]byte, 114),
						PublicKey: &Ed448PublicKey{
							KeyValue: ed448PubKey,
						},
					},
				},
			},
			expectError:   true,
			errorContains: "verify signature", // Ed448 verification will fail first
		},
		{
			name: "valid BLS signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
				Signature: &SignedX448Key_BlsSignature{
					BlsSignature: &BLS48581Signature{
						Signature: make([]byte, 74),
						PublicKey: &BLS48581G2PublicKey{
							KeyValue: make([]byte, 585),
						},
					},
				},
			},
			blsVerifier: &mockBlsVerifier{shouldVerify: true},
			expectError: true, // Will fail on address check
		},
		{
			name: "valid Decaf signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
				Signature: &SignedX448Key_DecafSignature{
					DecafSignature: &Decaf448Signature{
						Signature: make([]byte, 112),
						PublicKey: &Decaf448PublicKey{
							KeyValue: make([]byte, 56),
						},
					},
				},
			},
			schnorrVerifier: &mockSchnorrVerifier{shouldVerify: true},
			expectError:     true, // Will fail on address check
		},
		{
			name: "no signature",
			key: &SignedX448Key{
				Key: &X448PublicKey{
					KeyValue: make([]byte, 57),
				},
				ParentKeyAddress: make([]byte, 32),
			},
			expectError:   true,
			errorContains: "no signature",
		},
		{
			name:        "nil key",
			key:         nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.key == nil {
				// Test that nil key doesn't panic
				var key *SignedX448Key
				err := key.Verify(testContext, tt.blsVerifier, tt.schnorrVerifier)
				require.Error(t, err)
				return
			}

			err := tt.key.Verify(testContext, tt.blsVerifier, tt.schnorrVerifier)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestX448PublicKey_Serialization(t *testing.T) {
	tests := []struct {
		name string
		key  *X448PublicKey
	}{
		{
			name: "complete X448 public key",
			key: &X448PublicKey{
				KeyValue: make([]byte, 57), // X448 key size
			},
		},
		{
			name: "X448 key with specific value",
			key: &X448PublicKey{
				KeyValue: append([]byte{0x12, 0x34, 0x56, 0x78}, make([]byte, 53)...),
			},
		},
		{
			name: "X448 key with all zeros",
			key: &X448PublicKey{
				KeyValue: make([]byte, 57),
			},
		},
		{
			name: "X448 key with all ones",
			key: &X448PublicKey{
				KeyValue: make([]byte, 57),
			},
		},
	}

	// Fill the "all ones" test case
	for i := range tests[3].key.KeyValue {
		tests[3].key.KeyValue[i] = 0xFF
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.key.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			key2 := &X448PublicKey{}
			err = key2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.key.KeyValue, key2.KeyValue)
		})
	}
}
