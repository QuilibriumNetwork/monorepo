//go:build integrationtest
// +build integrationtest

package hypergraph_test

import (
	"crypto/rand"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func TestHypergraphIntrinsicIntegration(t *testing.T) {

	// Setup in-memory database and hypergraph
	logger, _ := zap.NewProduction()
	db := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	defer db.Close()

	encryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	prover := bls48581.NewKZGInclusionProver(logger)

	hyperstore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, logger, encryptor, prover)

	hg := hgcrdt.NewHypergraph(logger, hyperstore, prover, []int{}, &tests.Nopthenticator{})

	// Create a key manager with Ed448 keys for hypergraph operations
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	readSigner, _, err := keyManager.CreateSigningKey("hypergraph-read", crypto.KeyTypeEd448)
	require.NoError(t, err)
	writeSigner, _, err := keyManager.CreateSigningKey("hypergraph-write", crypto.KeyTypeEd448)
	require.NoError(t, err)

	// Create hypergraph configuration
	config := &hypergraph.HypergraphIntrinsicConfiguration{
		ReadPublicKey:  readSigner.Public().([]byte),
		WritePublicKey: writeSigner.Public().([]byte),
	}

	// Create hypergraph intrinsic
	hypergraphIntrinsic := hypergraph.NewHypergraphIntrinsic(config, hg, prover, keyManager, writeSigner, encryptor)

	var deployState state.State = hgstate.NewHypergraphState(hg)

	// Deploy the hypergraph intrinsic
	deployState, err = hypergraphIntrinsic.Deploy(
		hypergraph.HYPERGRAPH_BASE_DOMAIN,
		[][]byte{}, // No provers for hypergraph intrinsic
		[]byte("creator"),
		big.NewInt(0),
		[]byte(
			`BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX blob: <https://types.quilibrium.com/schema-repository/example/blob/>

blob:Blob a rdfs:Class.
	blob:Data a rdfs:Property;
	rdfs:domain qcl:ByteArray;
	qcl:size 32;
	qcl:order 0;
	rdfs:range blob:Blob.
`,
		),
		1,
		deployState,
	)
	require.NoError(t, err)
	require.NotNil(t, deployState)

	domain := deployState.(*hgstate.HypergraphState).Changeset()[0].Address

	// Get the intrinsic domain for operations
	require.NotEmpty(t, domain)

	// Commit the deployment
	err = deployState.Commit()
	require.NoError(t, err)

	t.Run("Vertex operations lifecycle", func(t *testing.T) {
		// Create test data
		dataAddress := [32]byte{}
		_, err := rand.Read(dataAddress[:])
		require.NoError(t, err)
		testData := []byte("test vertex data")

		t.Log("Testing vertex add...")
		vertexAdd := hypergraph.NewVertexAdd([32]byte(domain), dataAddress, testData, writeSigner.Public().([]byte), prover, writeSigner, config, encryptor, keyManager)

		err = vertexAdd.Prove(100)
		require.NoError(t, err)

		// Convert to bytes and invoke
		addBytes, err := vertexAdd.ToBytes()
		require.NoError(t, err)

		state, err := hypergraphIntrinsic.InvokeStep(100, addBytes, big.NewInt(1000), big.NewInt(1), deployState)
		require.NoError(t, err)
		require.NotNil(t, state)

		// Commit the state
		err = state.Commit()
		require.NoError(t, err)

		// Verify vertex was added to hypergraph
		fullAddress := [64]byte{}
		copy(fullAddress[:32], domain[:])
		copy(fullAddress[32:], dataAddress[:])

		txn, err := hg.NewTransaction(false)
		require.NoError(t, err)
		vertex, err := hg.GetVertex(fullAddress)
		require.NoError(t, err)
		require.NotNil(t, vertex)

		// Verify vertex data
		storedTree, err := hg.GetVertexData(fullAddress)
		require.NoError(t, err)
		require.NotNil(t, storedTree)

		storedData, err := storedTree.Get([]byte{0, 0, 0, 0, 0, 0, 0, 0})
		require.NoError(t, err)
		assert.Len(t, storedData, 621)

		err = txn.Abort()
		require.NoError(t, err)

		t.Log("Testing vertex remove...")
		vertexRemove := hypergraph.NewVertexRemove([32]byte(domain), dataAddress, writeSigner)

		err = vertexRemove.Prove(200)
		require.NoError(t, err)

		// Convert to bytes and invoke
		removeBytes, err := vertexRemove.ToBytes()
		require.NoError(t, err)

		state, err = hypergraphIntrinsic.InvokeStep(200, removeBytes, big.NewInt(100), big.NewInt(1), state)
		require.NoError(t, err)

		// Commit the state
		err = state.Commit()
		require.NoError(t, err)

		// Verify vertex was removed
		txn, err = hg.NewTransaction(false)
		assert.NoError(t, err)
		vertex, err = hg.GetVertex(fullAddress)
		assert.Nil(t, vertex)
		assert.Error(t, err)

		err = txn.Abort()
		require.NoError(t, err)
	})

	t.Run("Hyperedge operations lifecycle", func(t *testing.T) {
		// Create vertices first
		vertices := make([]*hypergraph.VertexAdd, 3)
		for i := range vertices {
			dataAddr := [32]byte{}
			_, err := rand.Read(dataAddr[:])
			require.NoError(t, err)

			// Add vertex
			vertexAdd := hypergraph.NewVertexAdd([32]byte(domain), dataAddr, []byte{byte(i)}, writeSigner.Public().([]byte), prover, writeSigner, config, encryptor, keyManager)
			err = vertexAdd.Prove(300 + uint64(i))
			require.NoError(t, err)

			addBytes, err := vertexAdd.ToBytes()
			require.NoError(t, err)

			state, err := hypergraphIntrinsic.InvokeStep(300+uint64(i), addBytes, big.NewInt(100), big.NewInt(1), deployState)
			require.NoError(t, err)

			err = state.Commit()
			require.NoError(t, err)

			// Store the full address
			vertices[i] = vertexAdd
		}

		// Create hyperedge
		hyperedgeAddress := make([]byte, 32)
		rand.Read(hyperedgeAddress)
		// hyperedgeData := []byte("hyperedge test data")
		hyperedge := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))

		v, err := hg.GetVertex([64]byte(slices.Concat(vertices[0].Domain[:], vertices[0].DataAddress[:])))
		require.NoError(t, err)

		hyperedge.AddExtrinsic(v)

		t.Log("Testing hyperedge add...")
		hyperedgeAdd := hypergraph.NewHyperedgeAdd([32]byte(domain), hyperedge, prover, writeSigner)

		err = hyperedgeAdd.Prove(12347)
		require.NoError(t, err)

		// Convert to bytes and invoke
		addBytes, err := hyperedgeAdd.ToBytes()
		require.NoError(t, err)

		state, err := hypergraphIntrinsic.InvokeStep(12347, addBytes, big.NewInt(1000), big.NewInt(1), deployState)
		require.NoError(t, err)

		// Commit the state
		err = state.Commit()
		require.NoError(t, err)

		// Verify hyperedge was added
		txn, err := hg.NewTransaction(false)
		require.NoError(t, err)
		storedHyperedge, err := hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		require.NoError(t, err)
		require.NotNil(t, storedHyperedge)

		// Verify hyperedge data
		// assert.Equal(t, hyperedgeData, storedHyperedge.GetExtrinsicTree()())
		// assert.Equal(t, vertices, storedHyperedge.GetVertices())

		err = txn.Abort()
		require.NoError(t, err)

		t.Log("Testing hyperedge remove...")
		hyperedgeRemove := hypergraph.NewHyperedgeRemove([32]byte(domain), hyperedge, writeSigner)

		err = hyperedgeRemove.Prove(500)
		require.NoError(t, err)

		// Convert to bytes and invoke
		removeBytes, err := hyperedgeRemove.ToBytes()
		require.NoError(t, err)

		state, err = hypergraphIntrinsic.InvokeStep(500, removeBytes, big.NewInt(100), big.NewInt(1), state)
		require.NoError(t, err)

		// Commit the state
		err = state.Commit()
		require.NoError(t, err)

		// Verify hyperedge was removed
		txn, err = hg.NewTransaction(false)
		require.NoError(t, err)
		storedHyperedge, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.Nil(t, storedHyperedge)
		assert.Error(t, err)

		err = txn.Abort()
		require.NoError(t, err)
	})

	t.Run("Complex operations sequence", func(t *testing.T) {
		// Add multiple vertices
		vertexCount := 5
		vertexAddresses := make([][32]byte, vertexCount)
		fullAddresses := make([][64]byte, vertexCount)

		for i := 0; i < vertexCount; i++ {
			_, err := rand.Read(vertexAddresses[i][:])
			require.NoError(t, err)

			data := []byte("vertex " + string(rune('A'+i)))

			vertexAdd := hypergraph.NewVertexAdd([32]byte(domain), vertexAddresses[i], data, writeSigner.Public().([]byte), prover, writeSigner, config, encryptor, keyManager)
			err = vertexAdd.Prove(600 + uint64(i))
			require.NoError(t, err)

			addBytes, err := vertexAdd.ToBytes()
			require.NoError(t, err)

			state, err := hypergraphIntrinsic.InvokeStep(600+uint64(i), addBytes, big.NewInt(100), big.NewInt(1), deployState)
			require.NoError(t, err)

			err = state.Commit()
			require.NoError(t, err)

			copy(fullAddresses[i][:32], domain[:])
			copy(fullAddresses[i][32:], vertexAddresses[i][:])
		}

		edges := [3][]byte{}
		edges[0] = make([]byte, 32)
		edges[1] = make([]byte, 32)
		edges[2] = make([]byte, 32)
		rand.Read(edges[0])
		rand.Read(edges[1])
		rand.Read(edges[2])

		// Create multiple hyperedges connecting different subsets
		hyperedges := []thypergraph.Hyperedge{
			hgcrdt.NewHyperedge([32]byte(domain), [32]byte(edges[0])),
			hgcrdt.NewHyperedge([32]byte(domain), [32]byte(edges[1])),
			hgcrdt.NewHyperedge([32]byte(domain), [32]byte(edges[2])),
		}

		vertex0, _ := hg.GetVertex([64]byte(fullAddresses[0]))
		vertex1, _ := hg.GetVertex([64]byte(fullAddresses[1]))
		vertex2, _ := hg.GetVertex([64]byte(fullAddresses[2]))
		vertex3, _ := hg.GetVertex([64]byte(fullAddresses[3]))
		vertex4, _ := hg.GetVertex([64]byte(fullAddresses[4]))

		hyperedges[0].AddExtrinsic(vertex0)
		hyperedges[0].AddExtrinsic(vertex1)
		hyperedges[1].AddExtrinsic(vertex2)
		hyperedges[2].AddExtrinsic(vertex3)
		hyperedges[2].AddExtrinsic(vertex4)

		// Add all hyperedges
		for i, edge := range hyperedges {
			hyperedgeAdd := hypergraph.NewHyperedgeAdd([32]byte(domain), edge, prover, writeSigner)
			err = hyperedgeAdd.Prove(700 + uint64(i))
			require.NoError(t, err)

			addBytes, err := hyperedgeAdd.ToBytes()
			require.NoError(t, err)

			state, err := hypergraphIntrinsic.InvokeStep(700+uint64(i), addBytes, big.NewInt(1000), big.NewInt(1), deployState)
			require.NoError(t, err)

			err = state.Commit()
			require.NoError(t, err)
		}

		// Verify all vertices and hyperedges exist
		for _, addr := range fullAddresses {
			vertex, err := hg.GetVertex(addr)
			require.NoError(t, err)
			require.NotNil(t, vertex)

			tree, err := hg.GetVertexData(addr)
			require.NoError(t, err)
			data, err := tree.Get([]byte{0, 0, 0, 0, 0, 0, 0, 0})
			require.NoError(t, err)
			assert.Len(t, data, 621)
		}

		for _, edge := range hyperedges {
			storedEdge, err := hg.GetHyperedge(edge.GetID())
			require.NoError(t, err)
			require.NotNil(t, storedEdge)
		}
	})

	t.Run("Edge cases and error handling", func(t *testing.T) {
		// Test removing non-existent vertex
		nonExistentAddr := [32]byte{}
		_, err := rand.Read(nonExistentAddr[:])
		require.NoError(t, err)

		vertexRemove := hypergraph.NewVertexRemove([32]byte(domain), nonExistentAddr, writeSigner)
		err = vertexRemove.Prove(800)
		require.NoError(t, err)

		removeBytes, err := vertexRemove.ToBytes()
		require.NoError(t, err)

		// Should fail during materialize
		_, err = hypergraphIntrinsic.InvokeStep(800, removeBytes, big.NewInt(100), big.NewInt(1), deployState)
		require.Error(t, err)

		// Test invalid operation bytes
		invalidBytes := []byte{0, 0, 0, 99} // Invalid operation type
		_, err = hypergraphIntrinsic.InvokeStep(800, invalidBytes, big.NewInt(100), big.NewInt(1), deployState)
		require.Error(t, err)

		// Test insufficient fee
		largeData := make([]byte, 1000)
		_, err = rand.Read(largeData)
		require.NoError(t, err)

		dataAddr := [32]byte{}
		_, err = rand.Read(dataAddr[:])
		require.NoError(t, err)

		vertexAdd := hypergraph.NewVertexAdd([32]byte(domain), dataAddr, largeData, writeSigner.Public().([]byte), prover, writeSigner, config, encryptor, keyManager)
		err = vertexAdd.Prove(900)
		require.NoError(t, err)

		addBytes, err := vertexAdd.ToBytes()
		require.NoError(t, err)

		// Fee too small for the data size
		_, err = hypergraphIntrinsic.InvokeStep(900, addBytes, big.NewInt(1), big.NewInt(1), deployState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient fee")
	})
}
