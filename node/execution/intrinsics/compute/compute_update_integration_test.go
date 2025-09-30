//go:build integrationtest
// +build integrationtest

package compute_test

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
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func TestComputeIntrinsicUpdate(t *testing.T) {
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
	compiler := compiler.NewBedlamCompiler()

	// Create owner key for updates
	ownerSigner, _, err := keyManager.CreateSigningKey("owner-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	ownerPublicKey := ownerSigner.Public().([]byte)

	// Create read and write keys
	readSigner, _, err := keyManager.CreateSigningKey("compute-read", crypto.KeyTypeEd448)
	require.NoError(t, err)
	writeSigner, _, err := keyManager.CreateSigningKey("compute-write", crypto.KeyTypeEd448)
	require.NoError(t, err)

	// Create initial compute configuration
	initialConfig := &compute.ComputeIntrinsicConfiguration{
		ReadPublicKey:  readSigner.Public().([]byte),
		WritePublicKey: writeSigner.Public().([]byte),
		OwnerPublicKey: ownerPublicKey,
	}

	// Create compute intrinsic
	computeIntrinsic, err := compute.NewComputeIntrinsic(
		initialConfig,
		hg,
		prover,
		bpProver,
		encryptor,
		dc,
		keyManager,
		compiler,
	)
	require.NoError(t, err)

	var deployState state.State = hgstate.NewHypergraphState(hg)

	// Initial RDF schema
	initialSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX compute: <https://types.quilibrium.com/schema-repository/compute/>

compute:Computation a rdfs:Class.
compute:Input a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 0;
  rdfs:range compute:Computation.
compute:Output a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 1;
  rdfs:range compute:Computation.
`

	// Deploy the compute intrinsic
	deployState, err = computeIntrinsic.Deploy(
		compute.COMPUTE_INTRINSIC_DOMAIN,
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
	computeAddress := computeIntrinsic.Address()

	// Commit the deployment
	err = deployState.Commit()
	require.NoError(t, err)

	t.Run("Update configuration", func(t *testing.T) {
		// Create new keys for updated configuration
		newReadSigner, _, err := keyManager.CreateSigningKey("new-compute-read", crypto.KeyTypeEd448)
		require.NoError(t, err)
		newWriteSigner, _, err := keyManager.CreateSigningKey("new-compute-write", crypto.KeyTypeEd448)
		require.NoError(t, err)

		// Create updated configuration
		updatedConfig := &compute.ComputeIntrinsicConfiguration{
			ReadPublicKey:  newReadSigner.Public().([]byte),
			WritePublicKey: newWriteSigner.Public().([]byte),
			OwnerPublicKey: ownerPublicKey,
		}

		// Create update message
		updateMsg := &protobufs.ComputeUpdate{
			Config: &protobufs.ComputeConfiguration{
				ReadPublicKey:  updatedConfig.ReadPublicKey,
				WritePublicKey: updatedConfig.WritePublicKey,
				OwnerPublicKey: updatedConfig.OwnerPublicKey,
			},
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.ComputeUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(computeAddress, []byte("COMPUTE_UPDATE")...))
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
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
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

	t.Run("Update RDF schema - add new class and properties", func(t *testing.T) {
		// Updated schema that adds new classes and properties
		updatedSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX compute: <https://types.quilibrium.com/schema-repository/compute/>

compute:Computation a rdfs:Class.
compute:Input a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 0;
  rdfs:range compute:Computation.
compute:Output a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 1;
  rdfs:range compute:Computation.
compute:Timestamp a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 2;
  rdfs:range compute:Computation.

compute:Result a rdfs:Class.
compute:Value a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 0;
  rdfs:range compute:Result.
`

		// Create update message with new schema
		updateMsg := &protobufs.ComputeUpdate{
			RdfSchema: []byte(updatedSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.ComputeUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(computeAddress, []byte("COMPUTE_UPDATE")...))
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
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			3,
			deployState,
		)
		require.NoError(t, err)
		require.NotNil(t, updateState)
	})

	t.Run("Update RDF schema - removing property should fail", func(t *testing.T) {
		// Schema that removes a property (invalid update)
		invalidSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX compute: <https://types.quilibrium.com/schema-repository/compute/>

compute:Computation a rdfs:Class.
compute:Input a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 0;
  rdfs:range compute:Computation.
`
		// Missing Output property - this should fail validation

		// Create update message with invalid schema
		updateMsg := &protobufs.ComputeUpdate{
			RdfSchema: []byte(invalidSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.ComputeUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(computeAddress, []byte("COMPUTE_UPDATE")...))
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
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			4,
			deployState,
		)

		// Should fail due to schema validation
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})

	t.Run("Update RDF schema - modifying property type should fail", func(t *testing.T) {
		// Schema that modifies a property type (invalid update)
		invalidSchema := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX compute: <https://types.quilibrium.com/schema-repository/compute/>

compute:Computation a rdfs:Class.
compute:Input a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 0;
  rdfs:range compute:Computation.
compute:Output a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 1;
  rdfs:range compute:Computation.
`
		// Changed Input from ByteArray to Uint - this should fail validation

		// Create update message with invalid schema
		updateMsg := &protobufs.ComputeUpdate{
			RdfSchema: []byte(invalidSchema),
		}

		// Sign the update
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.ComputeUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := ownerSigner.SignWithDomain(message, append(computeAddress, []byte("COMPUTE_UPDATE")...))
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
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
			domain,
			nil,
			[]byte("updater"),
			big.NewInt(0),
			updatePayload,
			5,
			deployState,
		)

		// Should fail due to schema validation
		assert.Error(t, err)
		assert.Nil(t, updateState)
	})

	t.Run("Update without signature should fail", func(t *testing.T) {
		// Create new keys for configuration
		newReadSigner, _, err := keyManager.CreateSigningKey("unsigned-read", crypto.KeyTypeEd448)
		require.NoError(t, err)
		newWriteSigner, _, err := keyManager.CreateSigningKey("unsigned-write", crypto.KeyTypeEd448)
		require.NoError(t, err)

		// Create update message without signature
		updateMsg := &protobufs.ComputeUpdate{
			Config: &protobufs.ComputeConfiguration{
				ReadPublicKey:  newReadSigner.Public().([]byte),
				WritePublicKey: newWriteSigner.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Serialize without signing
		updatePayload, err := updateMsg.ToCanonicalBytes()
		require.NoError(t, err)

		// Try to apply the update
		var domain [32]byte
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
			domain,
			nil,
			[]byte("unauthorized"),
			big.NewInt(0),
			updatePayload,
			6,
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

		// Create new keys for configuration
		newReadSigner, _, err := keyManager.CreateSigningKey("wrong-read", crypto.KeyTypeEd448)
		require.NoError(t, err)
		newWriteSigner, _, err := keyManager.CreateSigningKey("wrong-write", crypto.KeyTypeEd448)
		require.NoError(t, err)

		// Create update message
		updateMsg := &protobufs.ComputeUpdate{
			Config: &protobufs.ComputeConfiguration{
				ReadPublicKey:  newReadSigner.Public().([]byte),
				WritePublicKey: newWriteSigner.Public().([]byte),
				OwnerPublicKey: ownerPublicKey,
			},
		}

		// Sign with wrong key
		updateWithoutSig := proto.Clone(updateMsg).(*protobufs.ComputeUpdate)
		updateWithoutSig.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSig.ToCanonicalBytes()
		require.NoError(t, err)

		sig, err := wrongSigner.SignWithDomain(message, append(computeAddress, []byte("COMPUTE_UPDATE")...))
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
		copy(domain[:], computeAddress)

		updateState, err := computeIntrinsic.Deploy(
			domain,
			nil,
			[]byte("wrong-owner"),
			big.NewInt(0),
			updatePayload,
			7,
			deployState,
		)

		// Should fail due to wrong signature
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
		assert.Nil(t, updateState)
	})
}
