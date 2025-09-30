package protobufs

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthority_Serialization(t *testing.T) {
	tests := []struct {
		name string
		auth *Authority
	}{
		{
			name: "full authority",
			auth: &Authority{
				KeyType:   0, // Ed448
				PublicKey: make([]byte, 57),
				CanBurn:   true,
			},
		},
		{
			name: "authority without burn permission",
			auth: &Authority{
				KeyType:   0,
				PublicKey: make([]byte, 57),
				CanBurn:   false,
			},
		},
		{
			name: "empty authority",
			auth: &Authority{
				KeyType:   0,
				PublicKey: []byte{},
				CanBurn:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.auth.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			auth2 := &Authority{}
			err = auth2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.auth.KeyType, auth2.KeyType)
			assert.Equal(t, tt.auth.PublicKey, auth2.PublicKey)
			assert.Equal(t, tt.auth.CanBurn, auth2.CanBurn)
		})
	}
}

func TestFeeBasis_Serialization(t *testing.T) {
	tests := []struct {
		name     string
		feeBasis *FeeBasis
	}{
		{
			name: "no fee basis",
			feeBasis: &FeeBasis{
				Type:     FeeBasisType_NO_FEE_BASIS,
				Baseline: []byte{},
			},
		},
		{
			name: "per unit fee",
			feeBasis: &FeeBasis{
				Type:     FeeBasisType_PER_UNIT,
				Baseline: []byte{0x01, 0x02, 0x03, 0x04}, // Big.Int
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.feeBasis.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			fb2 := &FeeBasis{}
			err = fb2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.feeBasis.Type, fb2.Type)
			assert.Equal(t, tt.feeBasis.Baseline, fb2.Baseline)
		})
	}
}

func TestTokenMintStrategy_Serialization(t *testing.T) {
	tests := []struct {
		name     string
		strategy *TokenMintStrategy
	}{
		{
			name: "no mint behavior",
			strategy: &TokenMintStrategy{
				MintBehavior: TokenMintBehavior_NO_MINT_BEHAVIOR,
				ProofBasis:   ProofBasisType_NO_PROOF_BASIS,
			},
		},
		{
			name: "mint with authority",
			strategy: &TokenMintStrategy{
				MintBehavior: TokenMintBehavior_MINT_WITH_AUTHORITY,
				ProofBasis:   ProofBasisType_NO_PROOF_BASIS,
				Authority: &Authority{
					KeyType:   0,
					PublicKey: make([]byte, 57),
					CanBurn:   true,
				},
			},
		},
		{
			name: "mint with payment",
			strategy: &TokenMintStrategy{
				MintBehavior:   TokenMintBehavior_MINT_WITH_PAYMENT,
				ProofBasis:     ProofBasisType_NO_PROOF_BASIS,
				PaymentAddress: make([]byte, 32),
				FeeBasis: &FeeBasis{
					Type:     FeeBasisType_PER_UNIT,
					Baseline: []byte{0x01, 0x02},
				},
			},
		},
		{
			name: "verkle proof basis",
			strategy: &TokenMintStrategy{
				MintBehavior: TokenMintBehavior_NO_MINT_BEHAVIOR,
				ProofBasis:   ProofBasisType_VERKLE_MULTIPROOF_WITH_SIGNATURE,
				VerkleRoot:   make([]byte, 74),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.strategy.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			s2 := &TokenMintStrategy{}
			err = s2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.strategy.MintBehavior, s2.MintBehavior)
			assert.Equal(t, tt.strategy.ProofBasis, s2.ProofBasis)
			assert.Equal(t, tt.strategy.VerkleRoot, s2.VerkleRoot)
			assert.Equal(t, tt.strategy.PaymentAddress, s2.PaymentAddress)

			if tt.strategy.Authority != nil {
				require.NotNil(t, s2.Authority)
				assert.Equal(t, tt.strategy.Authority.KeyType, s2.Authority.KeyType)
				assert.Equal(t, tt.strategy.Authority.PublicKey, s2.Authority.PublicKey)
				assert.Equal(t, tt.strategy.Authority.CanBurn, s2.Authority.CanBurn)
			} else {
				assert.Nil(t, s2.Authority)
			}

			if tt.strategy.FeeBasis != nil {
				require.NotNil(t, s2.FeeBasis)
				assert.Equal(t, tt.strategy.FeeBasis.Type, s2.FeeBasis.Type)
				assert.Equal(t, tt.strategy.FeeBasis.Baseline, s2.FeeBasis.Baseline)
			} else {
				assert.Nil(t, s2.FeeBasis)
			}
		})
	}
}

func TestTokenConfiguration_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		config *TokenConfiguration
	}{
		{
			name: "non-mintable token",
			config: &TokenConfiguration{
				Behavior: uint32(TokenIntrinsicBehavior_TOKEN_BEHAVIOR_BURNABLE | TokenIntrinsicBehavior_TOKEN_BEHAVIOR_DIVISIBLE),
				Supply:   []byte{0x01, 0x00, 0x00, 0x00}, // Big.Int
				Units:    []byte{0x12},                   // Big.Int
				Name:     "Test Token",
				Symbol:   "TST",
				AdditionalReference: [][]byte{
					make([]byte, 64),
					make([]byte, 57),
				},
			},
		},
		{
			name: "mintable token",
			config: &TokenConfiguration{
				Behavior: uint32(TokenIntrinsicBehavior_TOKEN_BEHAVIOR_MINTABLE),
				MintStrategy: &TokenMintStrategy{
					MintBehavior: TokenMintBehavior_MINT_WITH_AUTHORITY,
					Authority: &Authority{
						KeyType:   0,
						PublicKey: make([]byte, 57),
					},
				},
				Name:   "Mintable Token",
				Symbol: "MINT",
			},
		},
		{
			name: "empty additional reference",
			config: &TokenConfiguration{
				Behavior: 0,
				Supply:   []byte{0x01},
				Name:     "Simple",
				Symbol:   "SMP",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.config.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			c2 := &TokenConfiguration{}
			err = c2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.config.Behavior, c2.Behavior)
			assert.Equal(t, tt.config.Supply, c2.Supply)
			assert.Equal(t, tt.config.Units, c2.Units)
			assert.Equal(t, tt.config.Name, c2.Name)
			assert.Equal(t, tt.config.Symbol, c2.Symbol)
			assert.Equal(t, tt.config.AdditionalReference, c2.AdditionalReference)

			if tt.config.MintStrategy != nil {
				require.NotNil(t, c2.MintStrategy)
				assert.Equal(t, tt.config.MintStrategy.MintBehavior, c2.MintStrategy.MintBehavior)
			} else {
				assert.Nil(t, c2.MintStrategy)
			}
		})
	}
}

func TestTokenDeploy_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		deploy *TokenDeploy
	}{
		{
			name: "complete deploy",
			deploy: &TokenDeploy{
				Config: &TokenConfiguration{
					Behavior: uint32(TokenIntrinsicBehavior_TOKEN_BEHAVIOR_MINTABLE),
					MintStrategy: &TokenMintStrategy{
						MintBehavior: TokenMintBehavior_MINT_WITH_AUTHORITY,
						Authority: &Authority{
							KeyType:   0,
							PublicKey: make([]byte, 57),
						},
					},
					Name:   "Deploy Token",
					Symbol: "DPL",
				},
			},
		},
		{
			name: "nil config",
			deploy: &TokenDeploy{
				Config: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.deploy.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			d2 := &TokenDeploy{}
			err = d2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			if tt.deploy.Config != nil {
				require.NotNil(t, d2.Config)
				assert.Equal(t, tt.deploy.Config.Name, d2.Config.Name)
				assert.Equal(t, tt.deploy.Config.Symbol, d2.Config.Symbol)
			} else {
				assert.Nil(t, d2.Config)
			}
		})
	}
}

func TestRecipientBundle_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		bundle *RecipientBundle
	}{
		{
			name: "complete bundle",
			bundle: &RecipientBundle{
				OneTimeKey:             make([]byte, 32),
				VerificationKey:        make([]byte, 32),
				CoinBalance:            []byte{0x01, 0x02, 0x03, 0x04},
				Mask:                   make([]byte, 32),
				AdditionalReference:    make([]byte, 64),
				AdditionalReferenceKey: make([]byte, 32),
			},
		},
		{
			name: "minimal bundle",
			bundle: &RecipientBundle{
				OneTimeKey:      make([]byte, 32),
				VerificationKey: make([]byte, 32),
				CoinBalance:     []byte{0x01},
				Mask:            make([]byte, 32),
			},
		},
		{
			name: "empty fields",
			bundle: &RecipientBundle{
				OneTimeKey:      []byte{},
				VerificationKey: []byte{},
				CoinBalance:     []byte{},
				Mask:            []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.bundle.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			b2 := &RecipientBundle{}
			err = b2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.bundle.OneTimeKey, b2.OneTimeKey)
			assert.Equal(t, tt.bundle.VerificationKey, b2.VerificationKey)
			assert.Equal(t, tt.bundle.CoinBalance, b2.CoinBalance)
			assert.Equal(t, tt.bundle.Mask, b2.Mask)
			assert.Equal(t, tt.bundle.AdditionalReference, b2.AdditionalReference)
			assert.Equal(t, tt.bundle.AdditionalReferenceKey, b2.AdditionalReferenceKey)
		})
	}
}

func TestTransaction_Serialization(t *testing.T) {
	tests := []struct {
		name string
		txn  *Transaction
	}{
		{
			name: "complete transaction",
			txn: &Transaction{
				Domain: make([]byte, 32),
				Inputs: []*TransactionInput{
					{
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
						Proofs:     [][]byte{make([]byte, 32), make([]byte, 32)},
					},
				},
				Outputs: []*TransactionOutput{
					{
						FrameNumber: []byte{0x01, 0x02, 0x03, 0x04},
						Commitment:  make([]byte, 32),
						RecipientOutput: &RecipientBundle{
							OneTimeKey:      make([]byte, 32),
							VerificationKey: make([]byte, 32),
							CoinBalance:     []byte{0x01},
							Mask:            make([]byte, 32),
						},
					},
				},
				Fees:           [][]byte{[]byte{0x01}},
				RangeProof:     make([]byte, 64),
				TraversalProof: &TraversalProof{},
			},
		},
		{
			name: "multiple inputs and outputs",
			txn: &Transaction{
				Domain: make([]byte, 32),
				Inputs: []*TransactionInput{
					{
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
					{
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
				},
				Outputs: []*TransactionOutput{
					{
						Commitment: make([]byte, 32),
					},
					{
						Commitment: make([]byte, 32),
					},
				},
				Fees:       [][]byte{[]byte{0x01}, []byte{0x02}},
				RangeProof: make([]byte, 64),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.txn.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			t2 := &Transaction{}
			err = t2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.txn.Domain, t2.Domain)
			assert.Equal(t, len(tt.txn.Inputs), len(t2.Inputs))
			assert.Equal(t, len(tt.txn.Outputs), len(t2.Outputs))
			assert.Equal(t, tt.txn.Fees, t2.Fees)
			assert.Equal(t, tt.txn.RangeProof, t2.RangeProof)
			// Handle nil for TraversalProof
			if tt.txn.TraversalProof == nil && t2.TraversalProof == nil {
				// Both are empty, that's fine
			} else {
				if tt.txn.TraversalProof.Multiproof == nil && t2.TraversalProof.Multiproof == nil {
					// MPs are empty, that's also normal
				} else {
					assert.Equal(t, tt.txn.TraversalProof.Multiproof.Multicommitment, t2.TraversalProof.Multiproof.Multicommitment)
					assert.Equal(t, tt.txn.TraversalProof.Multiproof.Proof, t2.TraversalProof.Multiproof.Proof)
				}
			}

			// Compare inputs
			for i, input := range tt.txn.Inputs {
				assert.Equal(t, input.Commitment, t2.Inputs[i].Commitment)
				assert.Equal(t, input.Signature, t2.Inputs[i].Signature)
				// Handle nil vs empty slice
				if len(input.Proofs) == 0 && len(t2.Inputs[i].Proofs) == 0 {
					// Both are empty, that's fine
				} else {
					assert.Equal(t, input.Proofs, t2.Inputs[i].Proofs)
				}
			}

			// Compare outputs
			for i, output := range tt.txn.Outputs {
				assert.Equal(t, output.FrameNumber, t2.Outputs[i].FrameNumber)
				assert.Equal(t, output.Commitment, t2.Outputs[i].Commitment)
				if output.RecipientOutput != nil {
					require.NotNil(t, t2.Outputs[i].RecipientOutput)
					assert.Equal(t, output.RecipientOutput.OneTimeKey, t2.Outputs[i].RecipientOutput.OneTimeKey)
				} else {
					assert.Nil(t, t2.Outputs[i].RecipientOutput)
				}
			}
		})
	}
}

func TestMintTransaction_Serialization(t *testing.T) {
	tests := []struct {
		name    string
		mintTxn *MintTransaction
	}{
		{
			name: "proof of work mint",
			mintTxn: &MintTransaction{
				Domain: make([]byte, 32),
				Inputs: []*MintTransactionInput{
					{
						Value:      []byte{0x01, 0x02, 0x03},
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
				},
				Outputs: []*MintTransactionOutput{
					{
						FrameNumber: []byte{0x01, 0x02},
						Commitment:  make([]byte, 32),
					},
				},
				Fees:       [][]byte{[]byte{0x01}},
				RangeProof: make([]byte, 64),
			},
		},
		{
			name: "authority mint",
			mintTxn: &MintTransaction{
				Domain: make([]byte, 32),
				Inputs: []*MintTransactionInput{
					{
						Value:      []byte{0x01},
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
				},
				Outputs: []*MintTransactionOutput{
					{
						Commitment: make([]byte, 32),
					},
				},
				Fees:       [][]byte{[]byte{0x01}},
				RangeProof: make([]byte, 64),
			},
		},
		{
			name: "signature mint",
			mintTxn: &MintTransaction{
				Domain: make([]byte, 32),
				Inputs: []*MintTransactionInput{
					{
						Value:      []byte{0x01},
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
				},
				Outputs: []*MintTransactionOutput{
					{
						Commitment: make([]byte, 32),
					},
				},
				Fees:       [][]byte{[]byte{0x01}},
				RangeProof: make([]byte, 64),
			},
		},
		{
			name: "payment mint",
			mintTxn: &MintTransaction{
				Domain: make([]byte, 32),
				Inputs: []*MintTransactionInput{
					{
						Value:      []byte{0x01},
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
					},
				},
				Outputs: []*MintTransactionOutput{
					{
						Commitment: make([]byte, 32),
					},
				},
				Fees:       [][]byte{[]byte{0x01}},
				RangeProof: make([]byte, 64),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.mintTxn.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			m2 := &MintTransaction{}
			err = m2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare basic fields
			assert.Equal(t, tt.mintTxn.Domain, m2.Domain)
			assert.Equal(t, len(tt.mintTxn.Inputs), len(m2.Inputs))
			assert.Equal(t, len(tt.mintTxn.Outputs), len(m2.Outputs))
			assert.Equal(t, tt.mintTxn.Fees, m2.Fees)
			assert.Equal(t, tt.mintTxn.RangeProof, m2.RangeProof)
		})
	}
}

func TestTransaction_ValidationFailures(t *testing.T) {
	t.Run("empty commitment", func(t *testing.T) {
		txn := &Transaction{
			Domain: make([]byte, 32),
			Inputs: []*TransactionInput{
				{
					Commitment: []byte{},
					Signature:  make([]byte, 114),
				},
			},
			Outputs: []*TransactionOutput{
				{
					Commitment: make([]byte, 32),
				},
			},
			Fees:       [][]byte{[]byte{0x01}},
			RangeProof: make([]byte, 64),
		}
		err := txn.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "commitment required")
	})

	t.Run("empty signature", func(t *testing.T) {
		txn := &Transaction{
			Domain: make([]byte, 32),
			Inputs: []*TransactionInput{
				{
					Commitment: make([]byte, 32),
					Signature:  []byte{},
				},
			},
			Outputs: []*TransactionOutput{
				{
					Commitment: make([]byte, 32),
				},
			},
			Fees:       [][]byte{[]byte{0x01}},
			RangeProof: make([]byte, 64),
		}
		err := txn.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature required")
	})

	t.Run("empty range proof", func(t *testing.T) {
		txn := &Transaction{
			Domain: make([]byte, 32),
			Inputs: []*TransactionInput{
				{
					Commitment: make([]byte, 32),
					Signature:  make([]byte, 114),
				},
			},
			Outputs: []*TransactionOutput{
				{
					Commitment: make([]byte, 32),
				},
			},
			Fees:       [][]byte{[]byte{0x01}},
			RangeProof: []byte{},
		}
		err := txn.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "range proof required")
	})

	t.Run("empty output commitment", func(t *testing.T) {
		txn := &Transaction{
			Domain: make([]byte, 32),
			Inputs: []*TransactionInput{
				{
					Commitment: make([]byte, 32),
					Signature:  make([]byte, 114),
				},
			},
			Outputs: []*TransactionOutput{
				{
					Commitment: []byte{},
				},
			},
			Fees:       [][]byte{[]byte{0x01}},
			RangeProof: make([]byte, 64),
		}
		err := txn.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "commitment required")
	})
}

func TestTokenTypes_Validation(t *testing.T) {
	t.Run("Authority validation", func(t *testing.T) {
		// Valid authority
		auth := &Authority{
			KeyType:   0,
			PublicKey: make([]byte, 57),
		}
		assert.NoError(t, auth.Validate())

		// Invalid key length
		auth.PublicKey = make([]byte, 56)
		assert.Error(t, auth.Validate())

		// Nil authority
		var nilAuth *Authority
		assert.Error(t, nilAuth.Validate())
	})

	t.Run("TokenConfiguration validation", func(t *testing.T) {
		// Valid non-mintable token
		config := &TokenConfiguration{
			Behavior: 0,
			Supply:   []byte{0x01},
			Name:     "Test",
			Symbol:   "TST",
		}
		assert.NoError(t, config.Validate())

		// Mintable without strategy
		config.Behavior = uint32(TokenIntrinsicBehavior_TOKEN_BEHAVIOR_MINTABLE)
		config.MintStrategy = nil
		assert.Error(t, config.Validate())

		// Mintable with strategy
		config.MintStrategy = &TokenMintStrategy{
			MintBehavior: TokenMintBehavior_NO_MINT_BEHAVIOR,
		}
		assert.NoError(t, config.Validate())

		// Missing name
		config.Name = ""
		assert.Error(t, config.Validate())
	})

	t.Run("Transaction validation", func(t *testing.T) {
		// Valid transaction
		txn := &Transaction{
			Domain: make([]byte, 32),
			Inputs: []*TransactionInput{{
				Commitment: make([]byte, 32),
				Signature:  make([]byte, 114),
			}},
			Outputs: []*TransactionOutput{{
				Commitment: make([]byte, 32),
			}},
			Fees:       [][]byte{[]byte{0x01}},
			RangeProof: make([]byte, 64),
		}
		assert.NoError(t, txn.Validate())

		// Invalid domain length
		txn.Domain = make([]byte, 31)
		assert.Error(t, txn.Validate())

		// No inputs
		txn.Domain = make([]byte, 32)
		txn.Inputs = []*TransactionInput{}
		assert.Error(t, txn.Validate())

		// Mismatched fees
		txn.Inputs = []*TransactionInput{{
			Commitment: make([]byte, 32),
			Signature:  make([]byte, 114),
		}}
		txn.Fees = [][]byte{}
		assert.Error(t, txn.Validate())
	})
}

func TestTokenUpdate_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		update *TokenUpdate
	}{
		{
			name: "complete token update",
			update: &TokenUpdate{
				Config: &TokenConfiguration{
					Name:   "UpdatedToken",
					Symbol: "UTOK",
					Supply: []byte{0x01, 0x00, 0x00, 0x00}, // Big.Int bytes
					Units:  []byte{0x01},
					MintStrategy: &TokenMintStrategy{
						MintBehavior: TokenMintBehavior_NO_MINT_BEHAVIOR,
						ProofBasis:   ProofBasisType_NO_PROOF_BASIS,
					},
				},
				RdfSchema: []byte("@prefix : <http://example.org/token#> . :UpdatedToken a :Token ; :symbol \"UTOK\" ."),
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
			name: "minimal token update",
			update: &TokenUpdate{
				Config:                     nil,
				RdfSchema:                  []byte{},
				PublicKeySignatureBls48581: nil,
			},
		},
		{
			name: "update with only config",
			update: &TokenUpdate{
				Config: &TokenConfiguration{
					Name:   "SimpleToken",
					Symbol: "STOK",
					Supply: []byte{0xFF, 0xFF},
					Units:  []byte{0x01},
					MintStrategy: &TokenMintStrategy{
						MintBehavior: TokenMintBehavior_MINT_WITH_AUTHORITY,
						ProofBasis:   ProofBasisType_NO_PROOF_BASIS,
					},
				},
				RdfSchema:                  []byte{},
				PublicKeySignatureBls48581: nil,
			},
		},
		{
			name: "update with only rdf schema",
			update: &TokenUpdate{
				Config:                     nil,
				RdfSchema:                  []byte("@prefix : <http://example.org/token#> . :MyToken a :Token ."),
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.update.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			update2 := &TokenUpdate{}
			err = update2.FromCanonicalBytes(data)
			require.NoError(t, err)

			if tt.update.Config != nil {
				assert.NotNil(t, update2.Config)
				assert.Equal(t, tt.update.Config.Name, update2.Config.Name)
				assert.Equal(t, tt.update.Config.Symbol, update2.Config.Symbol)
				assert.Equal(t, tt.update.Config.Supply, update2.Config.Supply)
				assert.Equal(t, tt.update.Config.Units, update2.Config.Units)
			} else {
				assert.Nil(t, update2.Config)
			}

			assert.True(t, bytes.Equal(tt.update.RdfSchema, update2.RdfSchema))

			if tt.update.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, update2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Signature, update2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Bitmask, update2.PublicKeySignatureBls48581.Bitmask)
				if tt.update.PublicKeySignatureBls48581.PublicKey != nil {
					assert.NotNil(t, update2.PublicKeySignatureBls48581.PublicKey)
					assert.Equal(t, tt.update.PublicKeySignatureBls48581.PublicKey.KeyValue, update2.PublicKeySignatureBls48581.PublicKey.KeyValue)
				}
			} else {
				assert.Nil(t, update2.PublicKeySignatureBls48581)
			}
		})
	}
}

func TestTransactionInput_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		input *TransactionInput
	}{
		{
			name: "complete transaction input",
			input: &TransactionInput{
				Commitment: make([]byte, 32),
				Signature:  make([]byte, 114), // Ed448 signature
				Proofs: [][]byte{
					make([]byte, 128), // Proof 1
					make([]byte, 256), // Proof 2
					make([]byte, 64),  // Proof 3
				},
			},
		},
		{
			name: "input with different values",
			input: &TransactionInput{
				Commitment: append([]byte{0xFF}, make([]byte, 31)...),
				Signature:  append([]byte{0xAA}, make([]byte, 113)...),
				Proofs: [][]byte{
					append([]byte{0xBB}, make([]byte, 127)...),
					append([]byte{0xCC}, make([]byte, 63)...),
				},
			},
		},
		{
			name: "minimal input",
			input: &TransactionInput{
				Commitment: []byte{},
				Signature:  []byte{},
				Proofs:     [][]byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			input2 := &TransactionInput{}
			err = input2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.input.Commitment, input2.Commitment)
			assert.Equal(t, tt.input.Signature, input2.Signature)
			assert.Equal(t, len(tt.input.Proofs), len(input2.Proofs))
			for i := range tt.input.Proofs {
				assert.Equal(t, tt.input.Proofs[i], input2.Proofs[i])
			}
		})
	}
}

func TestTransactionOutput_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		output *TransactionOutput
	}{
		{
			name: "complete transaction output",
			output: &TransactionOutput{
				FrameNumber: []byte{0x01, 0x00, 0x00, 0x00}, // Big.Int bytes
				Commitment:  make([]byte, 32),
				RecipientOutput: &RecipientBundle{
					OneTimeKey:             make([]byte, 32),
					VerificationKey:        make([]byte, 32),
					CoinBalance:            []byte{0x01, 0x02, 0x03, 0x04},
					Mask:                   make([]byte, 32),
					AdditionalReference:    make([]byte, 64),
					AdditionalReferenceKey: make([]byte, 32),
				},
			},
		},
		{
			name: "output with different values",
			output: &TransactionOutput{
				FrameNumber: []byte{0xFF, 0xFF, 0xFF, 0xFF},
				Commitment:  append([]byte{0xAA}, make([]byte, 31)...),
				RecipientOutput: &RecipientBundle{
					OneTimeKey:             append([]byte{0xBB}, make([]byte, 31)...),
					VerificationKey:        append([]byte{0xCC}, make([]byte, 31)...),
					CoinBalance:            []byte{0xFF, 0xEE, 0xDD, 0xCC},
					Mask:                   append([]byte{0xDD}, make([]byte, 31)...),
					AdditionalReference:    append([]byte{0xEE}, make([]byte, 63)...),
					AdditionalReferenceKey: append([]byte{0xFF}, make([]byte, 31)...),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.output.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			output2 := &TransactionOutput{}
			err = output2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.output.FrameNumber, output2.FrameNumber)
			assert.Equal(t, tt.output.Commitment, output2.Commitment)
			if tt.output.RecipientOutput != nil {
				assert.NotNil(t, output2.RecipientOutput)
				assert.Equal(t, tt.output.RecipientOutput.OneTimeKey, output2.RecipientOutput.OneTimeKey)
				assert.Equal(t, tt.output.RecipientOutput.VerificationKey, output2.RecipientOutput.VerificationKey)
				assert.Equal(t, tt.output.RecipientOutput.CoinBalance, output2.RecipientOutput.CoinBalance)
				assert.Equal(t, tt.output.RecipientOutput.Mask, output2.RecipientOutput.Mask)
				assert.Equal(t, tt.output.RecipientOutput.AdditionalReference, output2.RecipientOutput.AdditionalReference)
				assert.Equal(t, tt.output.RecipientOutput.AdditionalReferenceKey, output2.RecipientOutput.AdditionalReferenceKey)
			} else {
				assert.Nil(t, output2.RecipientOutput)
			}
		})
	}
}

func TestPendingTransaction_Serialization(t *testing.T) {
	tests := []struct {
		name string
		tx   *PendingTransaction
	}{
		{
			name: "complete pending transaction",
			tx: &PendingTransaction{
				Domain: make([]byte, 32),
				Inputs: []*PendingTransactionInput{
					{
						Commitment: make([]byte, 32),
						Signature:  make([]byte, 114),
						Proofs: [][]byte{
							make([]byte, 128),
							make([]byte, 256),
						},
					},
					{
						Commitment: append([]byte{0xAA}, make([]byte, 31)...),
						Signature:  append([]byte{0xBB}, make([]byte, 113)...),
						Proofs: [][]byte{
							append([]byte{0xCC}, make([]byte, 127)...),
						},
					},
				},
				Outputs: []*PendingTransactionOutput{
					{
						FrameNumber: []byte{0x01, 0x00, 0x00, 0x00},
						Commitment:  make([]byte, 32),
						To: &RecipientBundle{
							OneTimeKey:             make([]byte, 32),
							VerificationKey:        make([]byte, 32),
							CoinBalance:            []byte{0x01, 0x02, 0x03, 0x04},
							Mask:                   make([]byte, 32),
							AdditionalReference:    make([]byte, 64),
							AdditionalReferenceKey: make([]byte, 32),
						},
						Refund: &RecipientBundle{
							OneTimeKey:             append([]byte{0xFF}, make([]byte, 31)...),
							VerificationKey:        append([]byte{0xEE}, make([]byte, 31)...),
							CoinBalance:            []byte{0xFF, 0xEE, 0xDD, 0xCC},
							Mask:                   append([]byte{0xDD}, make([]byte, 31)...),
							AdditionalReference:    append([]byte{0xCC}, make([]byte, 63)...),
							AdditionalReferenceKey: append([]byte{0xBB}, make([]byte, 31)...),
						},
					},
				},
				Fees: [][]byte{
					[]byte{0x01, 0x00, 0x00, 0x00}, // Fee 1
					[]byte{0x02, 0x00, 0x00, 0x00}, // Fee 2
				},
			},
		},
		{
			name: "minimal pending transaction",
			tx: &PendingTransaction{
				Domain:  []byte{},
				Inputs:  []*PendingTransactionInput{},
				Outputs: []*PendingTransactionOutput{},
				Fees:    [][]byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.tx.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			tx2 := &PendingTransaction{}
			err = tx2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.tx.Domain, tx2.Domain)
			assert.Equal(t, len(tt.tx.Inputs), len(tx2.Inputs))
			for i := range tt.tx.Inputs {
				assert.Equal(t, tt.tx.Inputs[i].Commitment, tx2.Inputs[i].Commitment)
				assert.Equal(t, tt.tx.Inputs[i].Signature, tx2.Inputs[i].Signature)
				assert.Equal(t, len(tt.tx.Inputs[i].Proofs), len(tx2.Inputs[i].Proofs))
				for j := range tt.tx.Inputs[i].Proofs {
					assert.Equal(t, tt.tx.Inputs[i].Proofs[j], tx2.Inputs[i].Proofs[j])
				}
			}
			assert.Equal(t, len(tt.tx.Outputs), len(tx2.Outputs))
			for i := range tt.tx.Outputs {
				assert.Equal(t, tt.tx.Outputs[i].FrameNumber, tx2.Outputs[i].FrameNumber)
				assert.Equal(t, tt.tx.Outputs[i].Commitment, tx2.Outputs[i].Commitment)
				if tt.tx.Outputs[i].To != nil {
					assert.NotNil(t, tx2.Outputs[i].To)
					assert.Equal(t, tt.tx.Outputs[i].To.OneTimeKey, tx2.Outputs[i].To.OneTimeKey)
					assert.Equal(t, tt.tx.Outputs[i].To.CoinBalance, tx2.Outputs[i].To.CoinBalance)
				}
				if tt.tx.Outputs[i].Refund != nil {
					assert.NotNil(t, tx2.Outputs[i].Refund)
					assert.Equal(t, tt.tx.Outputs[i].Refund.OneTimeKey, tx2.Outputs[i].Refund.OneTimeKey)
					assert.Equal(t, tt.tx.Outputs[i].Refund.CoinBalance, tx2.Outputs[i].Refund.CoinBalance)
				}
			}
			assert.Equal(t, len(tt.tx.Fees), len(tx2.Fees))
			for i := range tt.tx.Fees {
				assert.Equal(t, tt.tx.Fees[i], tx2.Fees[i])
			}
		})
	}
}

func TestPendingTransactionInput_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		input *PendingTransactionInput
	}{
		{
			name: "complete pending input",
			input: &PendingTransactionInput{
				Commitment: make([]byte, 32),
				Signature:  make([]byte, 114), // Ed448 signature
				Proofs: [][]byte{
					make([]byte, 128), // Proof 1
					make([]byte, 256), // Proof 2
				},
			},
		},
		{
			name: "pending input with different values",
			input: &PendingTransactionInput{
				Commitment: append([]byte{0xEE}, make([]byte, 31)...),
				Signature:  append([]byte{0xFF}, make([]byte, 113)...),
				Proofs: [][]byte{
					append([]byte{0xAB}, make([]byte, 127)...),
					append([]byte{0xCD}, make([]byte, 255)...),
					append([]byte{0xEF}, make([]byte, 63)...),
				},
			},
		},
		{
			name: "minimal pending input",
			input: &PendingTransactionInput{
				Commitment: []byte{},
				Signature:  []byte{},
				Proofs:     [][]byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			input2 := &PendingTransactionInput{}
			err = input2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.input.Commitment, input2.Commitment)
			assert.Equal(t, tt.input.Signature, input2.Signature)
			assert.Equal(t, len(tt.input.Proofs), len(input2.Proofs))
			for i := range tt.input.Proofs {
				assert.Equal(t, tt.input.Proofs[i], input2.Proofs[i])
			}
		})
	}
}

func TestPendingTransactionOutput_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		output *PendingTransactionOutput
	}{
		{
			name: "complete pending output",
			output: &PendingTransactionOutput{
				FrameNumber: []byte{0x20, 0x00, 0x00, 0x00}, // Big.Int bytes
				Commitment:  make([]byte, 32),
				To: &RecipientBundle{
					OneTimeKey:             make([]byte, 32),
					VerificationKey:        make([]byte, 32),
					CoinBalance:            []byte{0x01, 0x02, 0x03, 0x04},
					Mask:                   make([]byte, 32),
					AdditionalReference:    make([]byte, 64),
					AdditionalReferenceKey: make([]byte, 32),
				},
				Refund: &RecipientBundle{
					OneTimeKey:             append([]byte{0xAA}, make([]byte, 31)...),
					VerificationKey:        append([]byte{0xBB}, make([]byte, 31)...),
					CoinBalance:            []byte{0xFF, 0xEE, 0xDD, 0xCC},
					Mask:                   append([]byte{0xCC}, make([]byte, 31)...),
					AdditionalReference:    append([]byte{0xDD}, make([]byte, 63)...),
					AdditionalReferenceKey: append([]byte{0xEE}, make([]byte, 31)...),
				},
			},
		},
		{
			name: "pending output with different values",
			output: &PendingTransactionOutput{
				FrameNumber: []byte{0x12, 0x34, 0x56, 0x78},
				Commitment:  append([]byte{0x77}, make([]byte, 31)...),
				To: &RecipientBundle{
					OneTimeKey:             append([]byte{0x88}, make([]byte, 31)...),
					VerificationKey:        append([]byte{0x99}, make([]byte, 31)...),
					CoinBalance:            []byte{0x11, 0x22, 0x33, 0x44},
					Mask:                   append([]byte{0x55}, make([]byte, 31)...),
					AdditionalReference:    append([]byte{0x66}, make([]byte, 63)...),
					AdditionalReferenceKey: append([]byte{0x77}, make([]byte, 31)...),
				},
				Refund: nil, // No refund in this case
			},
		},
		{
			name: "minimal pending output",
			output: &PendingTransactionOutput{
				FrameNumber: []byte{},
				Commitment:  []byte{},
				To:          nil,
				Refund:      nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.output.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			output2 := &PendingTransactionOutput{}
			err = output2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.True(t, bytes.Equal(tt.output.FrameNumber, output2.FrameNumber))
			assert.True(t, bytes.Equal(tt.output.Commitment, output2.Commitment))
			if tt.output.To != nil {
				assert.NotNil(t, output2.To)
				assert.Equal(t, tt.output.To.OneTimeKey, output2.To.OneTimeKey)
				assert.Equal(t, tt.output.To.VerificationKey, output2.To.VerificationKey)
				assert.Equal(t, tt.output.To.CoinBalance, output2.To.CoinBalance)
				assert.Equal(t, tt.output.To.Mask, output2.To.Mask)
				assert.Equal(t, tt.output.To.AdditionalReference, output2.To.AdditionalReference)
				assert.Equal(t, tt.output.To.AdditionalReferenceKey, output2.To.AdditionalReferenceKey)
			} else {
				assert.Nil(t, output2.To)
			}
			if tt.output.Refund != nil {
				assert.NotNil(t, output2.Refund)
				assert.Equal(t, tt.output.Refund.OneTimeKey, output2.Refund.OneTimeKey)
				assert.Equal(t, tt.output.Refund.VerificationKey, output2.Refund.VerificationKey)
				assert.Equal(t, tt.output.Refund.CoinBalance, output2.Refund.CoinBalance)
				assert.Equal(t, tt.output.Refund.Mask, output2.Refund.Mask)
				assert.Equal(t, tt.output.Refund.AdditionalReference, output2.Refund.AdditionalReference)
				assert.Equal(t, tt.output.Refund.AdditionalReferenceKey, output2.Refund.AdditionalReferenceKey)
			} else {
				assert.Nil(t, output2.Refund)
			}
		})
	}
}

func TestMintTransactionInput_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		input *MintTransactionInput
	}{
		{
			name: "complete mint input",
			input: &MintTransactionInput{
				Value:      []byte{0x05, 0x00, 0x00, 0x00}, // Big.Int serialized mint amount
				Commitment: make([]byte, 32),
				Signature:  make([]byte, 114), // Ed448 signature
			},
		},
		{
			name: "mint input with different values",
			input: &MintTransactionInput{
				Value:      []byte{0xFF, 0xEE, 0xDD}, // Different Big.Int value
				Commitment: append([]byte{0x10}, make([]byte, 31)...),
				Signature:  append([]byte{0x20}, make([]byte, 113)...),
			},
		},
		{
			name: "minimal mint input",
			input: &MintTransactionInput{
				Value:      []byte{},
				Commitment: []byte{},
				Signature:  []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			input2 := &MintTransactionInput{}
			err = input2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.input.Value, input2.Value)
			assert.Equal(t, tt.input.Commitment, input2.Commitment)
			assert.Equal(t, tt.input.Signature, input2.Signature)
		})
	}
}

func TestMintTransactionOutput_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		output *MintTransactionOutput
	}{
		{
			name: "complete mint output",
			output: &MintTransactionOutput{
				FrameNumber: []byte{0x08, 0x00, 0x00, 0x00}, // Big.Int bytes
				Commitment:  make([]byte, 32),
				RecipientOutput: &RecipientBundle{
					OneTimeKey:             make([]byte, 32),
					VerificationKey:        make([]byte, 32),
					CoinBalance:            []byte{0x01, 0x02, 0x03, 0x04},
					Mask:                   make([]byte, 32),
					AdditionalReference:    make([]byte, 64),
					AdditionalReferenceKey: make([]byte, 32),
				},
			},
		},
		{
			name: "mint output with different values",
			output: &MintTransactionOutput{
				FrameNumber: []byte{0x11, 0x22, 0x33, 0x44},
				Commitment:  append([]byte{0x60}, make([]byte, 31)...),
				RecipientOutput: &RecipientBundle{
					OneTimeKey:             append([]byte{0x70}, make([]byte, 31)...),
					VerificationKey:        append([]byte{0x80}, make([]byte, 31)...),
					CoinBalance:            []byte{0x55, 0x66, 0x77, 0x88},
					Mask:                   append([]byte{0x90}, make([]byte, 31)...),
					AdditionalReference:    append([]byte{0xA0}, make([]byte, 63)...),
					AdditionalReferenceKey: append([]byte{0xB0}, make([]byte, 31)...),
				},
			},
		},
		{
			name: "minimal mint output",
			output: &MintTransactionOutput{
				FrameNumber:     []byte{},
				Commitment:      []byte{},
				RecipientOutput: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.output.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			output2 := &MintTransactionOutput{}
			err = output2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.True(t, bytes.Equal(tt.output.FrameNumber, output2.FrameNumber))
			assert.Equal(t, tt.output.Commitment, output2.Commitment)
			if tt.output.RecipientOutput != nil {
				assert.NotNil(t, output2.RecipientOutput)
				assert.Equal(t, tt.output.RecipientOutput.OneTimeKey, output2.RecipientOutput.OneTimeKey)
				assert.Equal(t, tt.output.RecipientOutput.VerificationKey, output2.RecipientOutput.VerificationKey)
				assert.Equal(t, tt.output.RecipientOutput.CoinBalance, output2.RecipientOutput.CoinBalance)
				assert.Equal(t, tt.output.RecipientOutput.Mask, output2.RecipientOutput.Mask)
				assert.Equal(t, tt.output.RecipientOutput.AdditionalReference, output2.RecipientOutput.AdditionalReference)
				assert.Equal(t, tt.output.RecipientOutput.AdditionalReferenceKey, output2.RecipientOutput.AdditionalReferenceKey)
			} else {
				assert.Nil(t, output2.RecipientOutput)
			}
		})
	}
}

// Helper function to generate random bytes
func randomBytes(t *testing.T, size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
