package hypergraph_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"slices"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	tcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// setupTest creates a test environment with a HypergraphState
func setupTest(t *testing.T) (*hypergraph.HypergraphState, thypergraph.Hypergraph, tcrypto.VerEncProof, []byte, tcrypto.InclusionProver) {
	logger, _ := zap.NewDevelopment()
	s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	enc := &mocks.MockVerifiableEncryptor{}
	incProver := &mocks.MockInclusionProver{}
	vep := &mocks.MockVerEncProof{}
	ve := &mocks.MockVerEnc{}
	pub, _, _ := ed448.GenerateKey(rand.Reader)
	ve.On("ToBytes").Return([]byte{})
	ve.On("GetStatement").Return(make([]byte, 74))
	vep.On("Compress").Return(ve)
	enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]tcrypto.VerEncProof{
		vep,
	})
	hg := hgcrdt.NewHypergraph(
		logger,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, incProver),
		incProver,
		[]int{},
		&tests.Nopthenticator{},
	)
	st := hypergraph.NewHypergraphState(hg)

	return st, hg, vep, pub, incProver
}

// createDataTree creates a data tree for testing
func createDataTree(vep tcrypto.VerEncProof, incProver tcrypto.InclusionProver) *crypto.VectorCommitmentTree {
	data := []thypergraph.Encrypted{vep.Compress()}
	dataTree := &crypto.VectorCommitmentTree{}
	for _, d := range data {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
	}
	dataTree.Commit(incProver, false)
	return dataTree
}

// generateRandomBytes generates random bytes of specified length
func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	rand.Read(bytes)
	pbi, _ := poseidon.HashBytes(bytes)
	return pbi.FillBytes(make([]byte, 32))
}

func TestHypergraphState(t *testing.T) {
	// Test state operations
	t.Run("State Operations", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		incProver := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]tcrypto.VerEncProof{
			vep,
		})
		hg := hgcrdt.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, incProver),
			incProver,
			[]int{},
			&tests.Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.VectorCommitmentTree{}
		for _, d := range []thypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(incProver, false)
		st := hypergraph.NewHypergraphState(hg)
		domain := make([]byte, 32)
		vertexAddress := make([]byte, 32)
		hyperedgeAddress := make([]byte, 32)

		rand.Read(domain)
		rand.Read(vertexAddress)
		rand.Read(hyperedgeAddress)

		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)
		err := st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.NoError(t, err)

		he := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))
		he.AddExtrinsic(vertexAddState.GetVertex())
		err = st.Set(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeAddsDiscriminator,
			0,
			st.NewHyperedgeAddMaterializedState(
				0,
				nil,
				he,
			),
		)
		assert.NoError(t, err)

		// pre-commit assertions:
		assert.Equal(t, 2, len(st.Changeset()))
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.Error(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.Error(t, err)

		// post-commit assertions:
		err = st.Commit()
		assert.NoError(t, err)
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.NoError(t, err)
	})

	// Test invalid domain length in Init
	t.Run("Init with Invalid Domain Length", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Test with invalid domain length
		err := st.Init(
			make([]byte, 16), // Not 32 bytes
			&crypto.VectorCommitmentTree{},
			&crypto.VectorCommitmentTree{},
			"",
			[]*crypto.VectorCommitmentTree{},
			[]byte{},
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDomain))
	})

	// Test too many additional data elements in Init
	t.Run("Init with Too Many Additional Data", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Create too many additional data elements (> 62)
		additionalData := make([]*crypto.VectorCommitmentTree, 63)
		for i := range additionalData {
			additionalData[i] = &crypto.VectorCommitmentTree{}
		}

		// Test with too many additional data elements
		err := st.Init(
			make([]byte, 32),
			&crypto.VectorCommitmentTree{},
			&crypto.VectorCommitmentTree{},
			"",
			additionalData,
			[]byte{},
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidData))
	})

	// Test setting with invalid discriminator
	t.Run("Set with Invalid Discriminator", func(t *testing.T) {
		st, _, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		vertexAddress := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)

		// Test with invalid discriminator
		invalidDiscriminator := generateRandomBytes(32)
		err := st.Set(
			domain,
			vertexAddress,
			invalidDiscriminator,
			0,
			vertexAddState,
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDiscriminator))
	})

	// Test setting with type mismatch
	t.Run("Set with Type Mismatch", func(t *testing.T) {
		st, _, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		address := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(address),
			0,
			nil,
			dataTree,
		)

		// Try to set a vertex with hyperedge discriminator
		err := st.Set(
			domain,
			address,
			hypergraph.HyperedgeAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDiscriminator))

		// Try to set a hyperedge with vertex discriminator
		he := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(address))
		err = st.Set(
			domain,
			address,
			hypergraph.VertexAddsDiscriminator,
			0,
			st.NewHyperedgeAddMaterializedState(
				0,
				nil,
				he,
			),
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDiscriminator))
	})

	// Test getting with invalid discriminator
	t.Run("Get with Invalid Discriminator", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		address := generateRandomBytes(32)

		// Test with invalid discriminator
		invalidDiscriminator := generateRandomBytes(32)
		_, err := st.Get(
			domain,
			address,
			invalidDiscriminator,
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDiscriminator))
	})

	// Test deleting with invalid discriminator
	t.Run("Delete with Invalid Discriminator", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		address := generateRandomBytes(32)

		// Test with invalid discriminator
		invalidDiscriminator := generateRandomBytes(32)
		err := st.Delete(
			domain,
			address,
			invalidDiscriminator,
			0,
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), state.ErrInvalidDiscriminator))
	})

	// Test deleting a non-existent vertex
	t.Run("Delete Non-existent Vertex", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		address := generateRandomBytes(32)

		// Try to delete a non-existent vertex
		err := st.Delete(
			domain,
			address,
			hypergraph.VertexRemovesDiscriminator,
			0,
		)
		assert.Error(t, err)
	})

	// Test deleting a non-existent hyperedge
	t.Run("Delete Non-existent Hyperedge", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		address := generateRandomBytes(32)

		// Try to delete a non-existent hyperedge
		err := st.Delete(
			domain,
			address,
			hypergraph.HyperedgeRemovesDiscriminator,
			0,
		)
		assert.Error(t, err)
	})

	// Test revert operation
	t.Run("Revert Operations", func(t *testing.T) {
		st, hg, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		vertexAddress := generateRandomBytes(32)
		hyperedgeAddress := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)

		// Add a vertex
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)
		err := st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.NoError(t, err)

		// Add a hyperedge
		he := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))
		he.AddExtrinsic(vertexAddState.GetVertex())
		err = st.Set(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeAddsDiscriminator,
			0,
			st.NewHyperedgeAddMaterializedState(
				0,
				nil,
				he,
			),
		)
		assert.NoError(t, err)

		// Commit the changes
		err = st.Commit()
		assert.NoError(t, err)

		// Verify vertex and hyperedge exist
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.NoError(t, err)
		preRemove := hg.Commit()

		// Delete vertex and hyperedge
		st = hypergraph.NewHypergraphState(hg)
		err = st.Delete(
			domain,
			vertexAddress,
			hypergraph.VertexRemovesDiscriminator,
			1,
		)
		assert.NoError(t, err)
		err = st.Delete(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeRemovesDiscriminator,
			1,
		)

		assert.NoError(t, err)

		// Commit the deletes
		err = st.Commit()
		assert.NoError(t, err)
		postRemove := hg.Commit()

		// Verify vertex and hyperedge are removed
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.Error(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.Error(t, err)

		// Now try to add again, confirm it errors.
		st2 := hypergraph.NewHypergraphState(hg)

		// Re-add vertex and hyperedge
		vertexAddState = st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			2,
			nil,
			dataTree,
		)
		err = st2.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			2,
			vertexAddState,
		)
		assert.Error(t, err)

		he = hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))
		he.AddExtrinsic(vertexAddState.GetVertex())
		err = st2.Set(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeAddsDiscriminator,
			2,
			st2.NewHyperedgeAddMaterializedState(
				2,
				nil,
				he,
			),
		)
		assert.Error(t, err)

		shardKey := crypto.ShardKey{
			L1: [3]byte(p2p.GetBloomFilterIndices(domain, 256, 3)),
			L2: [32]byte(domain),
		}
		// Now revert the deletes
		vrrecs, err := hg.GetChanges(1, 2, string(thypergraph.RemovesPhaseType), string(thypergraph.VertexAtomType), shardKey)
		assert.NoError(t, err)
		assert.Len(t, vrrecs, 1)
		assert.True(t, bytes.Equal(slices.Concat(domain, vertexAddress), vrrecs[0].Key))
		hrrecs, err := hg.GetChanges(1, 2, string(thypergraph.RemovesPhaseType), string(thypergraph.HyperedgeAtomType), shardKey)
		assert.NoError(t, err)
		assert.Len(t, hrrecs, 1)
		assert.True(t, bytes.Equal(slices.Concat(domain, hyperedgeAddress), hrrecs[0].Key))
		txn, _ := hg.NewTransaction(false)
		err = hg.RevertChanges(txn, 1, 2, shardKey)
		assert.NoError(t, err)
		err = txn.Commit()
		assert.NoError(t, err)
		postRevert := hg.Commit()

		for i := range preRemove {
			for j := range preRemove[i] {
				assert.True(t, bytes.Equal(preRemove[i][j], postRevert[i][j]))
				// The remove records will have differing commit values
				if j%2 == 1 {
					assert.False(t, bytes.Equal(preRemove[i][j], postRemove[i][j]))
				}
			}
		}

		// The previously removed entries should now exist again
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.NoError(t, err)

		// Now update the entries
		st = hypergraph.NewHypergraphState(hg)
		newDataTree := createDataTree(vep, incProver)

		// Updating the vertex should now work
		vertexAddState = st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			2,
			dataTree,
			newDataTree,
		)
		err = st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			2,
			vertexAddState,
		)
		assert.NoError(t, err)

		// Same for the hyperedge
		newhe := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))
		newhe.AddExtrinsic(vertexAddState.GetVertex())
		err = st.Set(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeAddsDiscriminator,
			2,
			st.NewHyperedgeAddMaterializedState(
				2,
				he.GetExtrinsicTree(),
				newhe,
			),
		)
		assert.NoError(t, err)

		// Commit the changes
		err = st.Commit()
		assert.NoError(t, err)

		// Verify vertex and hyperedge exist
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.NoError(t, err)
	})

	// Test abort operation
	t.Run("Abort Operations", func(t *testing.T) {
		st, hg, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		vertexAddress := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)

		// Add a vertex
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)
		err := st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.NoError(t, err)

		// Verify changeset has an entry
		assert.Equal(t, 1, len(st.Changeset()))

		// Abort the operations
		err = st.Abort()
		assert.NoError(t, err)

		// Verify changeset is empty
		assert.Equal(t, 0, len(st.Changeset()))

		// Verify nothing was committed
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.Error(t, err)
	})

	// Test the complete vertex lifecycle
	t.Run("Vertex Lifecycle", func(t *testing.T) {
		st, hg, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		vertexAddress := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)

		// 1. Add a vertex
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)
		err := st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.NoError(t, err)

		// 2. Commit the addition
		err = st.Commit()
		assert.NoError(t, err)

		// 3. Verify the vertex exists
		st = hypergraph.NewHypergraphState(hg)
		vertexData, err := st.Get(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
		)
		assert.NoError(t, err)
		assert.NotNil(t, vertexData)

		// 4. Delete the vertex
		err = st.Delete(
			domain,
			vertexAddress,
			hypergraph.VertexRemovesDiscriminator,
			1,
		)
		assert.NoError(t, err)

		// 5. Verify the deletion is in the changeset but not committed yet
		assert.Equal(t, 1, len(st.Changeset()))
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err) // Still exists until commit

		// 6. Commit the deletion
		err = st.Commit()
		assert.NoError(t, err)

		// 7. Verify the vertex is now gone
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.Error(t, err)
		assert.True(t, errors.Is(errors.Cause(errors.Cause(err)), thypergraph.ErrRemoved))

		// 8. Attempt to get the deleted vertex
		_, err = st.Get(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
		)
		assert.Error(t, err)
	})

	// Test the complete hyperedge lifecycle
	t.Run("Hyperedge Lifecycle", func(t *testing.T) {
		st, hg, vep, _, incProver := setupTest(t)

		// Setup data
		domain := generateRandomBytes(32)
		vertexAddress := generateRandomBytes(32)
		hyperedgeAddress := generateRandomBytes(32)
		dataTree := createDataTree(vep, incProver)

		// 1. Add a vertex (needed for the hyperedge)
		vertexAddState := st.NewVertexAddMaterializedState(
			[32]byte(domain),
			[32]byte(vertexAddress),
			0,
			nil,
			dataTree,
		)
		err := st.Set(
			domain,
			vertexAddress,
			hypergraph.VertexAddsDiscriminator,
			0,
			vertexAddState,
		)
		assert.NoError(t, err)

		// 2. Add a hyperedge
		he := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(hyperedgeAddress))
		he.AddExtrinsic(vertexAddState.GetVertex())
		err = st.Set(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeAddsDiscriminator,
			0,
			st.NewHyperedgeAddMaterializedState(
				0,
				nil,
				he,
			),
		)
		assert.NoError(t, err)

		// 3. Commit both additions
		err = st.Commit()
		assert.NoError(t, err)

		// 4. Verify both exist
		st = hypergraph.NewHypergraphState(hg)
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.NoError(t, err)

		// 5. Delete the hyperedge
		err = st.Delete(
			domain,
			hyperedgeAddress,
			hypergraph.HyperedgeRemovesDiscriminator,
			1,
		)
		assert.NoError(t, err)

		// 6. Commit the deletion
		err = st.Commit()
		assert.NoError(t, err)

		// 7. Verify the hyperedge is gone but vertex remains
		_, err = hg.GetHyperedge([64]byte(slices.Concat(domain, hyperedgeAddress)))
		assert.Error(t, err)
		_, err = hg.GetVertex([64]byte(slices.Concat(domain, vertexAddress)))
		assert.NoError(t, err)
	})

	// Test initialization with different additional data sizes
	t.Run("Init with Different Additional Data Sizes", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		// Test with valid domain and additional data
		for length := 0; length <= 59; length += 1 {
			additionalData := make([]*crypto.VectorCommitmentTree, length)
			for j := range additionalData {
				// For lengths below or equal to 13 (would be indices 3-15), we're going
				// to fill all of them. This should not error on the length 0, but
				// should error on any before 14 because these are reserved ranges
				if length <= 13 {
					additionalData[j] = &crypto.VectorCommitmentTree{}
				} else {
					if j >= 13 {
						additionalData[j] = &crypto.VectorCommitmentTree{}
					}
				}
			}

			err := st.Init(
				make([]byte, 32),
				&crypto.VectorCommitmentTree{},
				&crypto.VectorCommitmentTree{},
				"",
				additionalData,
				[]byte{},
			)
			if length > 0 && length <= 13 {
				assert.Error(t, err, length)
				assert.Equal(t, 0, len(st.Changeset()))
			} else {
				assert.NoError(t, err, length)
				assert.Equal(t, 1, len(st.Changeset()))
			}

			// Reset for next test
			st.Abort()
		}
	})

	// Test with nil consensus metadata
	t.Run("Init with Nil Consensus Metadata", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		err := st.Init(
			make([]byte, 32),
			nil, // Nil consensus metadata
			&crypto.VectorCommitmentTree{},
			"",
			[]*crypto.VectorCommitmentTree{},
			[]byte{},
		)
		assert.Error(t, err)
	})

	// Test with nil sumcheck info
	t.Run("Init with Nil Sumcheck Info", func(t *testing.T) {
		st, _, _, _, _ := setupTest(t)

		err := st.Init(
			make([]byte, 32),
			&crypto.VectorCommitmentTree{},
			nil, // Nil sumcheck info
			"",
			[]*crypto.VectorCommitmentTree{},
			[]byte{},
		)
		assert.Error(t, err)
	})
}
