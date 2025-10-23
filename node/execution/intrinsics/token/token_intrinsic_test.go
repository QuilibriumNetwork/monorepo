package token

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	tcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func createNonMintableTestConfig() *TokenIntrinsicConfiguration {
	return &TokenIntrinsicConfiguration{
		Behavior: Burnable | Divisible,
		Units:    big.NewInt(1),
		Supply:   big.NewInt(1000000),
		Name:     "Test Token",
		Symbol:   "TEST",
	}
}

// Creates a mintable token configuration with authority for testing
func createMintableTestConfig() *TokenIntrinsicConfiguration {
	return &TokenIntrinsicConfiguration{
		Behavior: Mintable | Burnable | Divisible,
		MintStrategy: &TokenMintStrategy{
			MintBehavior: MintWithAuthority,
			Authority: &Authority{
				KeyType:   tcrypto.KeyTypeEd448,
				PublicKey: []byte("test-public-key"),
				CanBurn:   true,
			},
		},
		Units:  big.NewInt(100),
		Supply: big.NewInt(1000000),
		Name:   "Mintable Test Token",
		Symbol: "MTEST",
	}
}

func createMintWithPaymentTestConfig() *TokenIntrinsicConfiguration {
	return &TokenIntrinsicConfiguration{
		Behavior: Mintable | Divisible,
		MintStrategy: &TokenMintStrategy{
			MintBehavior:   MintWithPayment,
			PaymentAddress: make([]byte, 32), // 32 byte address
			FeeBasis: &FeeBasis{
				Type:     PerUnit,
				Baseline: big.NewInt(100),
			},
		},
		Units:  big.NewInt(100),
		Supply: big.NewInt(1000000),
		Name:   "Payment Test Token",
		Symbol: "PTEST",
	}
}

func createMockDependencies() (
	*mocks.MockInclusionProver,
	*mocks.MockBulletproofProver,
	*mocks.MockKeyManager,
	*mocks.MockHypergraph,
	*mocks.MockVerifiableEncryptor,
	*mocks.MockDecafConstructor,
) {
	inclusionProver := new(mocks.MockInclusionProver)
	inclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
	bulletproofProver := new(mocks.MockBulletproofProver)
	keyManager := new(mocks.MockKeyManager)
	hypergraph := new(mocks.MockHypergraph)
	decafConstructor := new(mocks.MockDecafConstructor)
	verEnc := new(mocks.MockVerifiableEncryptor)
	hypergraph.On("GetProver").Return(inclusionProver)

	return inclusionProver, bulletproofProver, keyManager, hypergraph, verEnc, decafConstructor
}

func TestNewTokenIntrinsic(t *testing.T) {
	tests := []struct {
		name        string
		config      *TokenIntrinsicConfiguration
		expectError bool
	}{
		{
			name:        "valid non-mintable token",
			config:      createNonMintableTestConfig(),
			expectError: false,
		},
		{
			name:        "valid mintable token with authority",
			config:      createMintableTestConfig(),
			expectError: false,
		},
		{
			name:        "valid mintable token with payment",
			config:      createMintWithPaymentTestConfig(),
			expectError: false,
		},
		{
			name: "invalid - mintable without mint strategy",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				Supply:   big.NewInt(1000000),
				Name:     "Invalid Token",
				Symbol:   "INVLD",
			},
			expectError: true,
		},
		{
			name: "invalid - divisible without units",
			config: &TokenIntrinsicConfiguration{
				Behavior: Divisible,
				Supply:   big.NewInt(1000000),
				Name:     "Invalid Token",
				Symbol:   "INVLD",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inclusionProver, bulletproofProver, keyManager, hypergraph, verEnc, decafConstructor := createMockDependencies()

			intrinsic, err := NewTokenIntrinsic(
				tt.config,
				hypergraph,
				verEnc,
				decafConstructor,
				bulletproofProver,
				inclusionProver,
				keyManager,
			)

			if tt.expectError {
				// We don't expect errors from NewTokenIntrinsic directly,
				// as it just initializes the struct. But we'll check validation
				// by calling validateTokenConfiguration
				err := validateTokenConfiguration(tt.config)
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, intrinsic)
				assert.Equal(t, tt.config, intrinsic.config)
				assert.Equal(t, hypergraph, intrinsic.hypergraph)
				assert.Equal(t, bulletproofProver, intrinsic.bulletproofProver)
				assert.Equal(t, inclusionProver, intrinsic.inclusionProver)
				assert.Equal(t, keyManager, intrinsic.keyManager)
			}
		})
	}
}

func TestDeploy(t *testing.T) {
	inclusionProver, bulletproofProver, keyManager, hypergraph, verEnc, decafConstructor := createMockDependencies()

	// Setup the intrinsic with a valid config
	config := createNonMintableTestConfig()
	intrinsic, err := NewTokenIntrinsic(
		config,
		hypergraph,
		verEnc,
		decafConstructor,
		bulletproofProver,
		inclusionProver,
		keyManager,
	)
	require.NoError(t, err)

	t.Run("creates successful deployment state", func(t *testing.T) {
		domain := TOKEN_BASE_DOMAIN
		provers := [][]byte{}
		creator := []byte("creator")
		fee := big.NewInt(10)

		var st state.State = hgstate.NewHypergraphState(hypergraph)
		st, err = intrinsic.Deploy(domain, provers, creator, fee, []byte{}, 1, st)
		require.NoError(t, err)

		require.Len(t, st.Changeset(), 1)
		initChange := st.Changeset()[0]
		require.Equal(t, initChange.StateChange, state.InitializeStateChangeEvent)
	})
}

func TestLoadTokenIntrinsic(t *testing.T) {
	inclusionProver, bulletproofProver, keyManager, _, verEnc, decafConstructor := createMockDependencies()

	// Setup mocks for the error case
	mockHypergraphErr := new(mocks.MockHypergraph)
	mockHypergraphErr.On("GetVertex", mock.Anything).Return(nil, errors.New("vertex not found"))

	// Setup mocks for the success case
	mockHypergraphSuccess := new(mocks.MockHypergraph)

	// Create test configuration
	config := createMintableTestConfig()

	// Create the metadata tree with valid configuration
	metadataTree := &crypto.VectorCommitmentTree{}
	rdfMultiprover := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, inclusionProver)
	configTree, err := NewTokenConfigurationMetadata(config, rdfMultiprover)
	require.NoError(t, err)

	tokenDomainBI, _ := poseidon.HashBytes(
		slices.Concat(
			TOKEN_PREFIX,
			configTree.Commit(inclusionProver, false),
		),
	)

	appAddress := tokenDomainBI.FillBytes(make([]byte, 32))
	metadataAddress := make([]byte, 64)
	copy(metadataAddress[:32], appAddress)
	mockHypergraphSuccess.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte{}, [32]byte{}, []byte{}, big.NewInt(0)), nil)

	// Store consensus tree
	consensus := &crypto.VectorCommitmentTree{}
	consensusData, _ := crypto.SerializeNonLazyTree(consensus)
	require.NoError(t, metadataTree.Insert([]byte{0 << 2}, consensusData, nil, big.NewInt(int64(len(consensusData)))))

	// Store sumcheck tree
	sumcheck := &crypto.VectorCommitmentTree{}
	sumcheckData, _ := crypto.SerializeNonLazyTree(sumcheck)
	require.NoError(t, metadataTree.Insert([]byte{1 << 2}, sumcheckData, nil, big.NewInt(int64(len(sumcheckData)))))

	// Store RDF schema
	rdfschema, _ := newTokenRDFHypergraphSchema(appAddress, config)
	require.NoError(t, metadataTree.Insert([]byte{2 << 2}, []byte(rdfschema), nil, big.NewInt(int64(len(rdfschema)))))

	// Store config metadata at the right index
	configBytes, err := crypto.SerializeNonLazyTree(configTree)
	require.NoError(t, err)
	require.NoError(t, metadataTree.Insert([]byte{16 << 2}, configBytes, nil, big.NewInt(int64(len(configBytes)))))

	// Mock the GetVertexData to return our tree
	mockHypergraphSuccess.On("GetVertexData", mock.Anything).Return(metadataTree, nil)

	// Setup inclusion prover to validate token domain
	inclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return([]byte("mock-commitment"), nil)

	t.Run("load failure - vertex not found", func(t *testing.T) {
		_, err := LoadTokenIntrinsic(appAddress, mockHypergraphErr, verEnc, decafConstructor, bulletproofProver, inclusionProver, keyManager, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vertex not found")
		mockHypergraphErr.AssertExpectations(t)
	})

	t.Run("load success - valid token intrinsic", func(t *testing.T) {
		inclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return([]byte("commitment"), nil)

		tokenIntrinsic, err := LoadTokenIntrinsic(appAddress, mockHypergraphSuccess, verEnc, decafConstructor, bulletproofProver, inclusionProver, keyManager, nil)

		require.NoError(t, err)
		require.NotNil(t, tokenIntrinsic)

		// Verify the loaded intrinsic has all the required components
		assert.Equal(t, mockHypergraphSuccess, tokenIntrinsic.hypergraph)
		assert.Equal(t, bulletproofProver, tokenIntrinsic.bulletproofProver)
		assert.Equal(t, inclusionProver, tokenIntrinsic.inclusionProver)
		assert.Equal(t, keyManager, tokenIntrinsic.keyManager)

		// Verify RDF schema is loaded
		assert.NotEmpty(t, tokenIntrinsic.rdfHypergraphSchema)

		mockHypergraphSuccess.AssertExpectations(t)
	})
}

func TestTokenConfigurationSerialization(t *testing.T) {
	// Create an inclusion prover mock that can be used by the tree operations
	inclusionProver := new(mocks.MockInclusionProver)
	inclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return([]byte("mock-commitment"), nil)

	tests := []struct {
		name   string
		config *TokenIntrinsicConfiguration
	}{
		{
			name:   "non-mintable token",
			config: createNonMintableTestConfig(),
		},
		{
			name:   "mintable token with authority",
			config: createMintableTestConfig(),
		},
		{
			name:   "mintable token with payment",
			config: createMintWithPaymentTestConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create configuration tree
			rdfMultiprover := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, inclusionProver)
			tree, err := NewTokenConfigurationMetadata(tt.config, rdfMultiprover)
			require.NoError(t, err)

			// Check that it has stored the expected keys
			behaviorBytes, err := tree.Get([]byte{0 << 2})
			require.NoError(t, err)
			assert.Equal(t, uint16(tt.config.Behavior), binary.BigEndian.Uint16(behaviorBytes))

			// Check name and symbol
			nameBytes, err := tree.Get([]byte{4 << 2})
			require.NoError(t, err)
			assert.Equal(t, tt.config.Name, string(nameBytes))

			symbolBytes, err := tree.Get([]byte{5 << 2})
			require.NoError(t, err)
			assert.Equal(t, tt.config.Symbol, string(symbolBytes))

			// Check for MintStrategy if applicable
			if (tt.config.Behavior & Mintable) != 0 {
				mintStrategyBytes, err := tree.Get([]byte{1 << 2})
				require.NoError(t, err)
				assert.NotEmpty(t, mintStrategyBytes)

				// Deserialize and validate all MintStrategy fields by packing and reusing the helper
				metadataTree := &crypto.VectorCommitmentTree{}
				flat, _ := crypto.SerializeNonLazyTree(tree)
				metadataTree.Insert([]byte{16 << 2}, flat, nil, big.NewInt(int64(len(flat))))
				deserializedConfig, err := unpackAndVerifyTokenConfigurationMetadata(inclusionProver, metadataTree)
				require.NoError(t, err)
				require.NotNil(t, deserializedConfig.MintStrategy)

				// Validate MintBehavior
				assert.Equal(t, tt.config.MintStrategy.MintBehavior, deserializedConfig.MintStrategy.MintBehavior)

				// Validate ProofBasis
				assert.Equal(t, tt.config.MintStrategy.ProofBasis, deserializedConfig.MintStrategy.ProofBasis)

				// Validate Authority if present
				if tt.config.MintStrategy.Authority != nil {
					require.NotNil(t, deserializedConfig.MintStrategy.Authority)
					assert.Equal(t, tt.config.MintStrategy.Authority.KeyType, deserializedConfig.MintStrategy.Authority.KeyType)
					assert.Equal(t, tt.config.MintStrategy.Authority.PublicKey, deserializedConfig.MintStrategy.Authority.PublicKey)
					assert.Equal(t, tt.config.MintStrategy.Authority.CanBurn, deserializedConfig.MintStrategy.Authority.CanBurn)
				}

				// Validate PaymentAddress if present
				if tt.config.MintStrategy.PaymentAddress != nil {
					assert.Equal(t, tt.config.MintStrategy.PaymentAddress, deserializedConfig.MintStrategy.PaymentAddress)
				}

				// Validate FeeBasis if present
				if tt.config.MintStrategy.FeeBasis != nil {
					require.NotNil(t, deserializedConfig.MintStrategy.FeeBasis)
					assert.Equal(t, tt.config.MintStrategy.FeeBasis.Type, deserializedConfig.MintStrategy.FeeBasis.Type)
					assert.Equal(t, 0, tt.config.MintStrategy.FeeBasis.Baseline.Cmp(deserializedConfig.MintStrategy.FeeBasis.Baseline))
				}

				// Validate VerkleRoot if present
				if tt.config.MintStrategy.VerkleRoot != nil {
					assert.Equal(t, tt.config.MintStrategy.VerkleRoot, deserializedConfig.MintStrategy.VerkleRoot)
				}
			}

			// Check for Units if applicable
			if (tt.config.Behavior & Divisible) != 0 {
				unitsBytes, err := tree.Get([]byte{2 << 2})
				require.NoError(t, err)
				assert.Equal(t, tt.config.Units.FillBytes(make([]byte, 32)), unitsBytes)
			}

			// Check for Supply
			supplyBytes, err := tree.Get([]byte{3 << 2})
			require.NoError(t, err)
			assert.Equal(t, tt.config.Supply.FillBytes(make([]byte, 32)), supplyBytes)

			// Check for AdditionalReference
			refBytes, err := tree.Get([]byte{6 << 2})
			require.NoError(t, err)
			assert.Equal(t, tt.config.AdditionalReference[:], refBytes)
		})
	}
}

// TestTokenConfigurationSerializationRoundTrip tests full serialization/deserialization cycle
func TestTokenConfigurationSerializationRoundTrip(t *testing.T) {
	inclusionProver := new(mocks.MockInclusionProver)
	inclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return([]byte("mock-commitment"), nil)

	tests := []struct {
		name   string
		config *TokenIntrinsicConfiguration
	}{
		{
			name:   "non-mintable token",
			config: createNonMintableTestConfig(),
		},
		{
			name:   "mintable token with authority",
			config: createMintableTestConfig(),
		},
		{
			name:   "mintable token with payment",
			config: createMintWithPaymentTestConfig(),
		},
		{
			name: "mintable token with proof and verkle root",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable | Divisible,
				MintStrategy: &TokenMintStrategy{
					MintBehavior: MintWithProof,
					ProofBasis:   ProofOfMeaningfulWork,
					VerkleRoot:   []byte("test-verkle-root-hash"),
				},
				Units:  big.NewInt(100),
				Supply: big.NewInt(1000000),
				Name:   "Proof Test Token",
				Symbol: "PROOF",
			},
		},
		{
			name: "complex token with all features",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable | Burnable | Divisible | Acceptable | Expirable | Tenderable,
				MintStrategy: &TokenMintStrategy{
					MintBehavior: MintWithAuthority,
					Authority: &Authority{
						KeyType:   tcrypto.KeyTypeBLS48581G1,
						PublicKey: make([]byte, 585), // Max G2 pubkey size
						CanBurn:   true,
					},
					PaymentAddress: make([]byte, 32),
					FeeBasis: &FeeBasis{
						Type:     PerUnit,
						Baseline: big.NewInt(1000),
					},
				},
				Units:  big.NewInt(10000),
				Supply: big.NewInt(1000000000),
				Name:   "Complex Test Token With Long Name",
				Symbol: "COMPLEX",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create configuration tree
			rdfMultiprover := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, inclusionProver)
			tree, err := NewTokenConfigurationMetadata(tt.config, rdfMultiprover)
			require.NoError(t, err)

			// Deserialize and validate all MintStrategy fields by packing and reusing the helper
			metadataTree := &crypto.VectorCommitmentTree{}
			flat, _ := crypto.SerializeNonLazyTree(tree)
			metadataTree.Insert([]byte{16 << 2}, flat, nil, big.NewInt(int64(len(flat))))
			deserializedConfig, err := unpackAndVerifyTokenConfigurationMetadata(inclusionProver, metadataTree)
			require.NoError(t, err)

			// Validate all fields match
			assert.Equal(t, tt.config.Behavior, deserializedConfig.Behavior)
			assert.Equal(t, tt.config.Name, deserializedConfig.Name)
			assert.Equal(t, tt.config.Symbol, deserializedConfig.Symbol)
			assert.Equal(t, tt.config.AdditionalReference, deserializedConfig.AdditionalReference)

			// Validate Units if present
			if tt.config.Units != nil {
				require.NotNil(t, deserializedConfig.Units)
				assert.Equal(t, 0, tt.config.Units.Cmp(deserializedConfig.Units))
			}

			// Validate Supply if present
			if tt.config.Supply != nil {
				require.NotNil(t, deserializedConfig.Supply)
				assert.Equal(t, 0, tt.config.Supply.Cmp(deserializedConfig.Supply))
			}

			// Validate MintStrategy if present
			if tt.config.MintStrategy != nil {
				require.NotNil(t, deserializedConfig.MintStrategy)
				assert.Equal(t, tt.config.MintStrategy.MintBehavior, deserializedConfig.MintStrategy.MintBehavior)
				assert.Equal(t, tt.config.MintStrategy.ProofBasis, deserializedConfig.MintStrategy.ProofBasis)

				// Validate Authority
				if tt.config.MintStrategy.Authority != nil {
					require.NotNil(t, deserializedConfig.MintStrategy.Authority)
					assert.Equal(t, tt.config.MintStrategy.Authority.KeyType, deserializedConfig.MintStrategy.Authority.KeyType)
					assert.Equal(t, tt.config.MintStrategy.Authority.PublicKey, deserializedConfig.MintStrategy.Authority.PublicKey)
					assert.Equal(t, tt.config.MintStrategy.Authority.CanBurn, deserializedConfig.MintStrategy.Authority.CanBurn)
				} else {
					assert.Nil(t, deserializedConfig.MintStrategy.Authority)
				}

				// Validate PaymentAddress
				if tt.config.MintStrategy.PaymentAddress != nil {
					assert.Equal(t, tt.config.MintStrategy.PaymentAddress, deserializedConfig.MintStrategy.PaymentAddress)
				} else {
					assert.Nil(t, deserializedConfig.MintStrategy.PaymentAddress)
				}

				// Validate FeeBasis
				if tt.config.MintStrategy.FeeBasis != nil {
					require.NotNil(t, deserializedConfig.MintStrategy.FeeBasis)
					assert.Equal(t, tt.config.MintStrategy.FeeBasis.Type, deserializedConfig.MintStrategy.FeeBasis.Type)
					assert.Equal(t, 0, tt.config.MintStrategy.FeeBasis.Baseline.Cmp(deserializedConfig.MintStrategy.FeeBasis.Baseline))
				} else {
					assert.Nil(t, deserializedConfig.MintStrategy.FeeBasis)
				}

				// Validate VerkleRoot
				if tt.config.MintStrategy.VerkleRoot != nil {
					assert.Equal(t, tt.config.MintStrategy.VerkleRoot, deserializedConfig.MintStrategy.VerkleRoot)
				} else {
					assert.Nil(t, deserializedConfig.MintStrategy.VerkleRoot)
				}
			} else {
				assert.Nil(t, deserializedConfig.MintStrategy)
			}
		})
	}
}

// TestTokenConfigurationValidation specifically tests the validation logic
func TestTokenConfigurationValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *TokenIntrinsicConfiguration
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid non-mintable token",
			config:      createNonMintableTestConfig(),
			expectError: false,
		},
		{
			name:        "valid mintable token with authority",
			config:      createMintableTestConfig(),
			expectError: false,
		},
		{
			name: "invalid - mintable without mint strategy",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				Supply:   big.NewInt(1000000),
				Name:     "Invalid Token",
				Symbol:   "INVLD",
			},
			expectError:   true,
			errorContains: "mintable token must have mint strategy defined",
		},
		{
			name: "invalid - divisible without units",
			config: &TokenIntrinsicConfiguration{
				Behavior: Divisible,
				Supply:   big.NewInt(1000000),
				Name:     "Invalid Token",
				Symbol:   "INVLD",
			},
			expectError:   true,
			errorContains: "divisible token must have units defined",
		},
		{
			name: "invalid - expirable but not acceptable",
			config: &TokenIntrinsicConfiguration{
				Behavior: Expirable,
				Supply:   big.NewInt(1000000),
				Name:     "Invalid Token",
				Symbol:   "INVLD",
			},
			expectError:   true,
			errorContains: "expirable token must be acceptable",
		},
		{
			name: "invalid - mint with proof but no proof basis",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				MintStrategy: &TokenMintStrategy{
					MintBehavior: MintWithProof,
					ProofBasis:   NoProofBasis,
				},
				Supply: big.NewInt(1000000),
				Name:   "Invalid Token",
				Symbol: "INVLD",
			},
			expectError:   true,
			errorContains: "mint with proof must define proof basis",
		},
		{
			name: "invalid - mint with authority but no authority",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				MintStrategy: &TokenMintStrategy{
					MintBehavior: MintWithAuthority,
				},
				Supply: big.NewInt(1000000),
				Name:   "Invalid Token",
				Symbol: "INVLD",
			},
			expectError:   true,
			errorContains: "mint with authority/signature must define authority",
		},
		{
			name: "invalid - mint with payment but no payment address",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				MintStrategy: &TokenMintStrategy{
					MintBehavior: MintWithPayment,
					FeeBasis: &FeeBasis{
						Type:     PerUnit,
						Baseline: big.NewInt(100),
					},
				},
				Supply: big.NewInt(1000000),
				Name:   "Invalid Token",
				Symbol: "INVLD",
			},
			expectError:   true,
			errorContains: "mint with payment must define payment address",
		},
		{
			name: "invalid - mint with payment but no fee basis",
			config: &TokenIntrinsicConfiguration{
				Behavior: Mintable,
				MintStrategy: &TokenMintStrategy{
					MintBehavior:   MintWithPayment,
					PaymentAddress: make([]byte, 32),
				},
				Supply: big.NewInt(1000000),
				Name:   "Invalid Token",
				Symbol: "INVLD",
			},
			expectError:   true,
			errorContains: "mint with payment must define fee basis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenConfiguration(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
