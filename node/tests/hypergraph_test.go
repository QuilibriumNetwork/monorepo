package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestHypergraph(t *testing.T) {
	// Test conversion operations
	t.Run("Conversion retains ordering", func(t *testing.T) {
		prover := &mocks.MockInclusionProver{}
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		verEnc := &mocks.MockVerifiableEncryptor{}
		ves := make([]hypergraph.Encrypted, 1000)
		for i := range ves {
			ve := &mocks.MockVerEnc{}
			ve.On("ToBytes").Return([]byte{byte(i)})
			verEnc.On("FromBytes", []byte{byte(i)}).Return(ve)

			ve.On("GetStatement").Return(bytes.Repeat([]byte{0x02, byte(i)}, 37))
			ves[i] = ve
		}
		tree := hypergraph.EncryptedToVertexTree(prover, ves)
		for i, leaf := range tries.GetAllPreloadedLeaves(tree.Root) {
			if !bytes.Equal(leaf.HashTarget, bytes.Repeat([]byte{0x02, byte(i)}, 37)) {
				t.Errorf("mismatch hashtarget on index %d", i)
			}
			if !bytes.Equal(leaf.Value, []byte{byte(i)}) {
				t.Errorf("mismatch value on index %d", i)
			}
		}

		encryptedSet := hypergraph.VertexTreeToEncrypted(verEnc, tree)
		for i, e := range encryptedSet {
			if !bytes.Equal(e.ToBytes(), []byte{byte(i)}) {
				t.Errorf("mismatch value on index %d", i)
			}
		}
	})

	// Test vertex operations
	t.Run("Vertex Operations", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v1 := hg.NewVertex([32]byte{1}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())
		v2 := hg.NewVertex([32]byte{1}, [32]byte{2}, dataTree.Commit(prover, false), dataTree.GetSize())

		// Add vertices
		err := hgcrdt.AddVertex(nil, v1)
		if err != nil {
			t.Errorf("Failed to add vertex v1: %v", err)
		}
		err = hgcrdt.AddVertex(nil, v2)
		if err != nil {
			t.Errorf("Failed to add vertex v2: %v", err)
		}

		// Lookup vertices
		if !hgcrdt.LookupVertex(v1) {
			t.Error("Failed to lookup vertex v1")
		}
		if !hgcrdt.LookupVertex(v2) {
			t.Error("Failed to lookup vertex v2")
		}

		// Remove vertex
		err = hgcrdt.RemoveVertex(nil, v1)
		if err != nil {
			t.Errorf("Failed to remove vertex v1: %v", err)
		}
		if hgcrdt.LookupVertex(v1) {
			t.Error("Vertex v1 still exists after removal")
		}
		if !hgcrdt.LookupVertex(v2) {
			t.Error("Vertex v2 was incorrectly removed")
		}
	})

	// Test hyperedge operations
	t.Run("Hyperedge Operations", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v3 := hg.NewVertex([32]byte{2}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())
		v4 := hg.NewVertex([32]byte{2}, [32]byte{2}, dataTree.Commit(prover, false), dataTree.GetSize())
		hgcrdt.AddVertex(nil, v3)
		hgcrdt.AddVertex(nil, v4)

		h1 := hg.NewHyperedge([32]byte{3}, [32]byte{1})
		h1.AddExtrinsic(v3)
		h1.AddExtrinsic(v4)

		// Add hyperedge
		err := hgcrdt.AddHyperedge(nil, h1)
		if err != nil {
			t.Errorf("Failed to add hyperedge h1: %v", err)
		}

		// Lookup hyperedge
		if !hgcrdt.LookupHyperedge(h1) {
			t.Error("Failed to lookup hyperedge h1")
		}

		// Remove hyperedge
		err = hgcrdt.RemoveHyperedge(nil, h1)
		if err != nil {
			t.Errorf("Failed to remove hyperedge h1: %v", err)
		}
		if hgcrdt.LookupHyperedge(h1) {
			t.Error("Hyperedge h1 still exists after removal")
		}
	})

	// Test "within" relationship
	t.Run("Within Relationship", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v5 := hg.NewVertex([32]byte{4}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())
		v6 := hg.NewVertex([32]byte{4}, [32]byte{2}, dataTree.Commit(prover, false), dataTree.GetSize())
		hgcrdt.AddVertex(nil, v5)
		hgcrdt.AddVertex(nil, v6)

		h2 := hg.NewHyperedge([32]byte{5}, [32]byte{1})
		h2.AddExtrinsic(v5)
		h2.AddExtrinsic(v6)
		hgcrdt.AddHyperedge(nil, h2)

		if !hgcrdt.Within(v5, h2) {
			t.Error("v5 should be within h2")
		}
		if !hgcrdt.Within(v6, h2) {
			t.Error("v6 should be within h2")
		}

		v7 := hg.NewVertex([32]byte{4}, [32]byte{3}, dataTree.Commit(prover, false), dataTree.GetSize())
		hgcrdt.AddVertex(nil, v7)
		if hgcrdt.Within(v7, h2) {
			t.Error("v7 should not be within h2")
		}
	})

	// Test nested hyperedges
	t.Run("Nested Hyperedges", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v8 := hg.NewVertex([32]byte{6}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())
		v9 := hg.NewVertex([32]byte{6}, [32]byte{2}, dataTree.Commit(prover, false), dataTree.GetSize())
		hgcrdt.AddVertex(nil, v8)
		hgcrdt.AddVertex(nil, v9)

		h3 := hg.NewHyperedge([32]byte{7}, [32]byte{1})
		h3.AddExtrinsic(v8)
		h4 := hg.NewHyperedge([32]byte{7}, [32]byte{2})
		h4.AddExtrinsic(h3)
		h4.AddExtrinsic(v9)
		hgcrdt.AddHyperedge(nil, h3)
		hgcrdt.AddHyperedge(nil, h4)

		if !hgcrdt.Within(v8, h4) {
			t.Error("v8 should be within h4 (nested)")
		}
		if !hgcrdt.Within(v9, h4) {
			t.Error("v9 should be within h4 (direct)")
		}
	})

	// Test error cases
	t.Run("Error Cases", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v10 := hg.NewVertex([32]byte{8}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())

		h5 := hg.NewHyperedge([32]byte{8}, [32]byte{2})
		h5.AddExtrinsic(v10)

		// Add vertex and hyperedge
		hgcrdt.AddVertex(nil, v10)
		hgcrdt.AddHyperedge(nil, h5)
	})

	// Test sharding
	t.Run("Sharding", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		s := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		enc := &mocks.MockVerifiableEncryptor{}
		prover := &mocks.MockInclusionProver{}
		vep := &mocks.MockVerEncProof{}
		ve := &mocks.MockVerEnc{}
		pub, _, _ := ed448.GenerateKey(rand.Reader)
		mockCommit := make([]byte, 74)
		mockCommit[0] = 0x02
		rand.Read(mockCommit[1:])
		prover.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
		ve.On("ToBytes").Return([]byte{})
		ve.On("GetStatement").Return(make([]byte, 74))
		vep.On("Compress").Return(ve)
		enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
			vep,
		})
		hgcrdt := hg.NewHypergraph(
			logger,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, prover),
			prover,
			[]int{},
			&Nopthenticator{},
		)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &tries.VectorCommitmentTree{}
		for _, d := range []hypergraph.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
		}
		dataTree.Commit(prover, false)
		v11 := hg.NewVertex([32]byte{9}, [32]byte{1}, dataTree.Commit(prover, false), dataTree.GetSize())
		v12 := hg.NewVertex([32]byte{9}, [32]byte{2}, dataTree.Commit(prover, false), dataTree.GetSize())
		hgcrdt.AddVertex(nil, v11)
		hgcrdt.AddVertex(nil, v12)

		shard11 := hypergraph.GetShardAddress(v11)
		shard12 := hypergraph.GetShardAddress(v12)

		if !bytes.Equal(shard11.L1[:], shard12.L1[:]) ||
			!bytes.Equal(shard11.L2[:], shard12.L2[:]) ||
			bytes.Equal(shard11.L3[:], shard12.L3[:]) {
			t.Error("v11 and v12 should be in the same L1 shard and the same L2 shard but not the same L3 shard")
		}
	})
}
