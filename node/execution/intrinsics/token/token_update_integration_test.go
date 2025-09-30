package token_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func TestTokenIntrinsicUpdate(t *testing.T) {
	// Setup
	logger, _ := zap.NewProduction()
	db := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	defer db.Close()

	encryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bpProver := &bulletproofs.Decaf448BulletproofProver{}
	prover := bls48581.NewKZGInclusionProver(logger)

	hyperstore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, logger, encryptor, prover)
	hg := hypergraph.NewHypergraph(logger, hyperstore, prover, []int{}, &tests.Nopthenticator{})

	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	// Create owner key for updates
	ownerSigner, _, err := keyManager.CreateSigningKey("owner-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	ownerPublicKey := ownerSigner.Public().([]byte)

	// Create initial token configuration
	initialConfig := &token.TokenIntrinsicConfiguration{
		Name:           "Test Token",
		Symbol:         "TEST",
		Supply:         big.NewInt(100000),
		Units:          big.NewInt(10),
		Behavior:       token.Divisible,
		OwnerPublicKey: ownerPublicKey,
	}

	// Create token intrinsic
	tokenIntrinsic, err := token.NewTokenIntrinsic(
		initialConfig,
		hg,
		encryptor,
		dc,
		bpProver,
		prover,
		keyManager,
	)
	require.NoError(t, err)

	var deployState state.State = hgstate.NewHypergraphState(hg)

	// Initial schema
	initialSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX test: <https://types.quilibrium.com/schema-repository/test/>

test:Token a rdfs:Class.
test:Amount a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 0;
  rdfs:range test:Token.
`

	// Deploy the token
	deployState, err = tokenIntrinsic.Deploy(
		token.TOKEN_BASE_DOMAIN,
		nil,
		[]byte("creator"),
		big.NewInt(0),
		[]byte(initialSchema),
		1,
		deployState,
	)
	require.NoError(t, err)
	require.NotNil(t, deployState)

	// Get the deployed address
	changeset := deployState.(*hgstate.HypergraphState).Changeset()
	require.NotEmpty(t, changeset)
	tokenAddress := changeset[0].Domain

	// Commit the deployment
	err = deployState.Commit()
	require.NoError(t, err)

	t.Run("Update configuration without behavior", func(t *testing.T) {
		// Create updated configuration - only name, symbol, decimals can be updated
		// Behavior is immutable
		updatedConfig := &token.TokenIntrinsicConfiguration{
			Name:           "Updated Token",
			Symbol:         "UPD",
			Supply:         big.NewInt(100000),
			Units:          big.NewInt(10),
			Behavior:       token.Divisible, // Same as initial
			OwnerPublicKey: ownerPublicKey,
		}

		// Create update message
		updateMsg := &protobufs.TokenUpdate{
			Config: &protobufs.TokenConfiguration{
				Name:           updatedConfig.Name,
				Symbol:         updatedConfig.Symbol,
				Supply:         updatedConfig.Supply.FillBytes(make([]byte, 32)),
				Units:          updatedConfig.Units.FillBytes(make([]byte, 32)),
				Behavior:       uint32(updatedConfig.Behavior),
				OwnerPublicKey: updatedConfig.OwnerPublicKey,
			},
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.TokenUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(tokenAddress, []byte("TOKEN_UPDATE")...))
		require.NoError(t, err)

		aggSig := &protobufs.BLS48581AggregateSignature{
			Signature: sig[:],
		}
		updateMsg.PublicKeySignatureBls48581 = aggSig

		// Serialize the update message
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Apply the update
		var domain [32]byte
		copy(domain[:], tokenAddress)

		updateState, err := tokenIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			2,
			deployState,
		)
		require.NoError(t, err)
		require.NotNil(t, updateState)
	})

	t.Run("Update behavior should fail", func(t *testing.T) {
		// Try to change behavior flags - this should fail
		updatedConfig := &token.TokenIntrinsicConfiguration{
			Name:   "Updated Token",
			Symbol: "UPD",
			Supply: big.NewInt(100000),
			Units:  big.NewInt(10),
			// Try to add Acceptable flag - this should fail
			Behavior:       token.Divisible | token.Acceptable,
			OwnerPublicKey: ownerPublicKey,
		}

		// Create update message
		updateMsg := &protobufs.TokenUpdate{
			Config: &protobufs.TokenConfiguration{
				Name:           updatedConfig.Name,
				Symbol:         updatedConfig.Symbol,
				Supply:         updatedConfig.Supply.FillBytes(make([]byte, 32)),
				Units:          updatedConfig.Units.FillBytes(make([]byte, 32)),
				Behavior:       uint32(updatedConfig.Behavior),
				OwnerPublicKey: updatedConfig.OwnerPublicKey,
			},
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.TokenUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(tokenAddress, []byte("TOKEN_UPDATE")...))
		require.NoError(t, err)

		aggSig := &protobufs.BLS48581AggregateSignature{
			Signature: sig[:],
		}
		updateMsg.PublicKeySignatureBls48581 = aggSig

		// Serialize the update message
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Apply the update
		var domain [32]byte
		copy(domain[:], tokenAddress)

		updateState, err := tokenIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			3,
			deployState,
		)

		// This should fail because behavior cannot be changed
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "behavior")
		assert.Nil(t, updateState)
	})

	t.Run("Update without signature should fail", func(t *testing.T) {
		// Create update message without signature
		updateMsg := &protobufs.TokenUpdate{
			Config: &protobufs.TokenConfiguration{
				Name:           "Unauthorized Update",
				Symbol:         "FAIL",
				Supply:         big.NewInt(100000).FillBytes(make([]byte, 32)),
				Units:          big.NewInt(10).FillBytes(make([]byte, 32)),
				Behavior:       uint32(token.Divisible),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Serialize without signing
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Try to apply the update
		var domain [32]byte
		copy(domain[:], tokenAddress)

		updateState, err := tokenIntrinsic.Deploy(
			domain,
			nil,
			[]byte("unauthorized"),
			big.NewInt(0),
			updatePayload,
			4,
			deployState,
		)

		// Should fail due to missing/invalid signature
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})

	t.Run("Update with wrong owner key should fail", func(t *testing.T) {
		// Create a different signer
		wrongSigner, _, err := keyManager.CreateSigningKey("wrong-owner", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)

		// Create update message
		updateMsg := &protobufs.TokenUpdate{
			Config: &protobufs.TokenConfiguration{
				Name:           "Wrong Owner Update",
				Symbol:         "WRONG",
				Supply:         big.NewInt(100000).FillBytes(make([]byte, 32)),
				Units:          big.NewInt(10).FillBytes(make([]byte, 32)),
				Behavior:       uint32(token.Divisible),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Sign with wrong key
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.TokenUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := wrongSigner.SignWithDomain(message, append(tokenAddress, []byte("TOKEN_UPDATE")...))
		require.NoError(t, err)

		aggSig := &protobufs.BLS48581AggregateSignature{
			Signature: sig[:],
		}
		updateMsg.PublicKeySignatureBls48581 = aggSig

		// Serialize the update message
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Try to apply the update
		var domain [32]byte
		copy(domain[:], tokenAddress)

		updateState, err := tokenIntrinsic.Deploy(
			domain,
			nil,
			[]byte("wrong-owner"),
			big.NewInt(0),
			updatePayload,
			5,
			deployState,
		)

		// Should fail due to wrong signature
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})
}
