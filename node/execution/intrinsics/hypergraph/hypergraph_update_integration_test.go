//go:build integrationtest
// +build integrationtest

package hypergraph_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	hgi "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func TestHypergraphIntrinsicUpdate(t *testing.T) {

	// Setup
	logger, _ := zap.NewProduction()
	db := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	defer db.Close()

	encryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bc := &bls48581.Bls48581KeyConstructor{}
	prover := bls48581.NewKZGInclusionProver(logger)

	hyperstore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, logger, encryptor, prover)
	hg := hypergraph.NewHypergraph(logger, hyperstore, prover, []int{}, &tests.Nopthenticator{})

	keyManager := keys.NewInMemoryKeyManager(bc, nil)

	// Create owner key for updates
	ownerSigner, _, err := keyManager.CreateSigningKey("owner-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	ownerPublicKey := ownerSigner.Public().([]byte)

	writerReader, _, err := keyManager.CreateSigningKey("writer-reader", crypto.KeyTypeEd448)

	// Create initial hypergraph configuration
	initialConfig := &hgi.HypergraphIntrinsicConfiguration{
		ReadPublicKey:  writerReader.Public().([]byte),
		WritePublicKey: writerReader.Public().([]byte),
		OwnerPublicKey: ownerPublicKey,
	}

	// Create hypergraph intrinsic
	hypergraphIntrinsic := hgi.NewHypergraphIntrinsic(
		initialConfig,
		hg,
		prover,
		keyManager,
		writerReader,
		verenc.NewMPCitHVerifiableEncryptor(1),
	)

	var deployState state.State = hgstate.NewHypergraphState(hg)

	// Initial schema
	initialSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX test: <https://types.quilibrium.com/schema-repository/test/>

test:Entity a rdfs:Class.
test:Name a rdfs:Property;
  rdfs:domain qcl:String;
  qcl:size 100;
  qcl:order 0;
  rdfs:range test:Entity.
test:Value a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 1;
  rdfs:range test:Entity.
`

	// Deploy the hypergraph
	deployState, err = hypergraphIntrinsic.Deploy(
		hgi.HYPERGRAPH_BASE_DOMAIN,
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
	hypergraphAddress := changeset[0].Domain

	// Commit the deployment
	err = deployState.Commit()
	require.NoError(t, err)

	t.Run("Update configuration and schema successfully", func(t *testing.T) {
		// Create updated configuration
		updatedConfig := &hgi.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  writerReader.Public().([]byte),
			WritePublicKey: writerReader.Public().([]byte),
			OwnerPublicKey: ownerPublicKey,
		}

		// Updated schema (additive only - adds Description property)
		updatedSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX test: <https://types.quilibrium.com/schema-repository/test/>

test:Entity a rdfs:Class.
test:Name a rdfs:Property;
  rdfs:domain qcl:String;
  qcl:size 100;
  qcl:order 0;
  rdfs:range test:Entity.
test:Value a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 1;
  rdfs:range test:Entity.
test:Description a rdfs:Property;
  rdfs:domain qcl:String;
  qcl:size 200;
  qcl:order 2;
  rdfs:range test:Entity.
`

		// Create update message
		updateMsg := &protobufs.HypergraphUpdate{
			Config:    updatedConfig.ToProtobuf(),
			RdfSchema: []byte(updatedSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.HypergraphUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(hypergraphAddress, []byte("HYPERGRAPH_UPDATE")...))
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
		copy(domain[:], hypergraphAddress)

		updateState, err := hypergraphIntrinsic.Deploy(
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

	t.Run("Update removing schema properties should fail", func(t *testing.T) {
		// Try to remove Value property - this should fail
		invalidSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX test: <https://types.quilibrium.com/schema-repository/test/>

test:Entity a rdfs:Class.
test:Name a rdfs:Property;
  rdfs:domain qcl:String;
  qcl:size 100;
  qcl:order 0;
  rdfs:range test:Entity.
`

		// Create update message with invalid schema
		updateMsg := &protobufs.HypergraphUpdate{
			Config: &protobufs.HypergraphConfiguration{
				ReadPublicKey:  writerReader.Public().([]byte),
				WritePublicKey: writerReader.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
			RdfSchema: []byte(invalidSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.HypergraphUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(hypergraphAddress, []byte("HYPERGRAPH_UPDATE")...))
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
		copy(domain[:], hypergraphAddress)

		updateState, err := hypergraphIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			3,
			deployState,
		)

		// Should fail due to removed property
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})

	t.Run("Update modifying schema properties should fail", func(t *testing.T) {
		// Try to change Value property size - this should fail
		modifiedSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX test: <https://types.quilibrium.com/schema-repository/test/>

test:Entity a rdfs:Class.
test:Name a rdfs:Property;
  rdfs:domain qcl:String;
  qcl:size 100;
  qcl:order 0;
  rdfs:range test:Entity.
test:Value a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 16;
  qcl:order 1;
  rdfs:range test:Entity.
`

		// Create update message with modified schema
		updateMsg := &protobufs.HypergraphUpdate{
			Config: &protobufs.HypergraphConfiguration{
				ReadPublicKey:  writerReader.Public().([]byte),
				WritePublicKey: writerReader.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
			RdfSchema: []byte(modifiedSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.HypergraphUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(hypergraphAddress, []byte("HYPERGRAPH_UPDATE")...))
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
		copy(domain[:], hypergraphAddress)

		updateState, err := hypergraphIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			4,
			deployState,
		)

		// Should fail due to modified property
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})

	t.Run("Update without signature should fail", func(t *testing.T) {
		// Create update message without signature
		updateMsg := &protobufs.HypergraphUpdate{
			Config: &protobufs.HypergraphConfiguration{
				ReadPublicKey:  writerReader.Public().([]byte),
				WritePublicKey: writerReader.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Serialize without signing
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Try to apply the update
		var domain [32]byte
		copy(domain[:], hypergraphAddress)

		updateState, err := hypergraphIntrinsic.Deploy(
			domain,
			nil,
			[]byte("unauthorized"),
			big.NewInt(0),
			updatePayload,
			5,
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
		updateMsg := &protobufs.HypergraphUpdate{
			Config: &protobufs.HypergraphConfiguration{
				WritePublicKey: writerReader.Public().([]byte),
				ReadPublicKey:  writerReader.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Sign with wrong key
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.HypergraphUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := wrongSigner.SignWithDomain(message, append(hypergraphAddress, []byte("HYPERGRAPH_UPDATE")...))
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
		copy(domain[:], hypergraphAddress)

		updateState, err := hypergraphIntrinsic.Deploy(
			domain,
			nil,
			[]byte("wrong-owner"),
			big.NewInt(0),
			updatePayload,
			6,
			deployState,
		)

		// Should fail due to wrong signature
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})
}
