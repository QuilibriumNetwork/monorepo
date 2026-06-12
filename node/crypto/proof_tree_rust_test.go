//go:build rusttries

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	mrand "math/rand"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"

	// The generated Go bindings from uniffi-bindgen-go. After running
	//   crates/quil-tries-ffi/generate.sh
	// the package will exist at quil-tries-ffi/generated/quil_tries_ffi/.
	//
	// Before this import will resolve, you must also add these lines to
	// node/go.mod:
	//
	//   replace source.quilibrium.com/quilibrium/monorepo/quil-tries-ffi => ../quil-tries-ffi
	//
	// and add to the require block:
	//
	//   source.quilibrium.com/quilibrium/monorepo/quil-tries-ffi v0.0.0
	//
	// and create quil-tries-ffi/go.mod with:
	//
	//   module source.quilibrium.com/quilibrium/monorepo/quil-tries-ffi
	//   go 1.24.0
	//
	rustffi "source.quilibrium.com/quilibrium/monorepo/quil-tries-ffi/generated/quil_tries_ffi"
)

// ---------------------------------------------------------------------------
// SHA-512 stub prover — identical to the Sha512Prover in
// crates/quil-tries-ffi/src/lib.rs. Branch commitments are computed as
// SHA-512(concatenated child commitments) which gives deterministic,
// curve-independent results suitable for cross-implementation comparison.
// ---------------------------------------------------------------------------

type sha512Prover struct{}

func (p *sha512Prover) CommitRaw(data []byte, polySize uint64) ([]byte, error) {
	h := sha512.Sum512(data)
	return h[:], nil
}

func (p *sha512Prover) ProveRaw(data []byte, index int, polySize uint64) ([]byte, error) {
	return []byte{}, nil
}

func (p *sha512Prover) VerifyRaw(
	data []byte, commit []byte, index uint64, proof []byte, polySize uint64,
) (bool, error) {
	return true, nil
}

func (p *sha512Prover) ProveMultiple(
	commitments [][]byte, polys [][]byte, indices []uint64, polySize uint64,
) crypto.Multiproof {
	return nil
}

func (p *sha512Prover) VerifyMultiple(
	commitments [][]byte, evaluations [][]byte, indices []uint64,
	polySize uint64, multiCommitment []byte, proof []byte,
) bool {
	return true
}

func (p *sha512Prover) NewMultiproof() crypto.Multiproof {
	return nil
}

var _ crypto.InclusionProver = (*sha512Prover)(nil)

// ---------------------------------------------------------------------------
// RustVectorCommitmentTree — thin adapter wrapping the FFI byte-buffer API
// into the same logical operations as tries.VectorCommitmentTree.
// ---------------------------------------------------------------------------

type RustVectorCommitmentTree struct {
	// Serialized tree state, passed back and forth across FFI boundary.
	treeBytes []byte
}

func NewRustTree() *RustVectorCommitmentTree {
	return &RustVectorCommitmentTree{
		treeBytes: rustffi.NewTree(),
	}
}

func (r *RustVectorCommitmentTree) Insert(key, value []byte) {
	r.treeBytes = rustffi.Insert(r.treeBytes, key, value)
}

func (r *RustVectorCommitmentTree) Delete(key []byte) {
	r.treeBytes = rustffi.DeleteKey(r.treeBytes, key)
}

func (r *RustVectorCommitmentTree) Get(key []byte) ([]byte, bool) {
	v := rustffi.GetValue(r.treeBytes, key)
	if v == nil {
		return nil, false
	}
	return *v, true
}

func (r *RustVectorCommitmentTree) Commit(proverKey []byte) []byte {
	return rustffi.Commit(r.treeBytes, proverKey)
}

func (r *RustVectorCommitmentTree) Prove(key, proverKey []byte) []byte {
	return rustffi.Prove(r.treeBytes, key, proverKey)
}

func (r *RustVectorCommitmentTree) VerifyProof(
	root, key, value, proof, proverKey []byte,
) bool {
	return rustffi.VerifyProof(root, key, value, proof, proverKey)
}

func (r *RustVectorCommitmentTree) Serialize() []byte {
	return rustffi.SerializeTree(r.treeBytes)
}

func (r *RustVectorCommitmentTree) Deserialize(data []byte) {
	r.treeBytes = rustffi.DeserializeTreeFfi(data)
}

// ---------------------------------------------------------------------------
// Core compatibility test: Rust tree must produce byte-identical roots to Go.
// ---------------------------------------------------------------------------

func TestRustTreeMatchesGoTree(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32) // unused by SHA-512 prover

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	const numInserts = 1000
	const numDeletes = 100

	// Deterministic PRNG for reproducibility.
	rng := mrand.New(mrand.NewSource(42))

	type kv struct {
		key   []byte
		value []byte
	}
	inserted := make([]kv, 0, numInserts)

	// ------------------------------------------------------------------
	// Phase 1: Insert 1000 random key-value pairs into both trees.
	// ------------------------------------------------------------------
	for i := 0; i < numInserts; i++ {
		key := make([]byte, 32)
		value := make([]byte, 32)
		rng.Read(key)
		rng.Read(value)

		err := goTree.Insert(key, value, nil, big.NewInt(1))
		if err != nil {
			t.Fatalf("Go Insert #%d failed: %v", i, err)
		}
		rustTree.Insert(key, value)

		inserted = append(inserted, kv{key: key, value: value})
	}

	// Commit both trees.
	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf(
			"Root mismatch after %d inserts.\n  Go root:   %x\n  Rust root: %x",
			numInserts, goRoot, rustRoot,
		)
	}
	t.Logf("Phase 1 PASSED: roots match after %d inserts (%x)", numInserts, goRoot[:8])

	// ------------------------------------------------------------------
	// Phase 2: Verify all values are readable from both trees.
	// ------------------------------------------------------------------
	for i, pair := range inserted {
		goVal, err := goTree.Get(pair.key)
		if err != nil {
			t.Fatalf("Go Get #%d failed: %v", i, err)
		}
		rustVal, found := rustTree.Get(pair.key)
		if !found {
			t.Fatalf("Rust Get #%d: key not found", i)
		}
		if !bytes.Equal(goVal, rustVal) {
			t.Fatalf("Value mismatch at #%d: Go=%x Rust=%x", i, goVal[:8], rustVal[:8])
		}
	}
	t.Logf("Phase 2 PASSED: all %d values match", numInserts)

	// ------------------------------------------------------------------
	// Phase 3: Delete 100 random keys from both trees, re-commit.
	// ------------------------------------------------------------------

	// Shuffle and pick the first numDeletes keys to delete.
	perm := rng.Perm(numInserts)
	deletedKeys := make(map[string]bool)

	for i := 0; i < numDeletes; i++ {
		key := inserted[perm[i]].key
		deletedKeys[string(key)] = true

		err := goTree.Delete(key)
		if err != nil {
			t.Fatalf("Go Delete #%d failed: %v", i, err)
		}
		rustTree.Delete(key)
	}

	goRoot2 := goTree.Commit(prover, true)
	rustRoot2 := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot2, rustRoot2) {
		t.Fatalf(
			"Root mismatch after %d deletes.\n  Go root:   %x\n  Rust root: %x",
			numDeletes, goRoot2, rustRoot2,
		)
	}
	t.Logf("Phase 3 PASSED: roots match after %d deletes (%x)", numDeletes, goRoot2[:8])

	// Roots must differ from pre-delete state.
	if bytes.Equal(goRoot, goRoot2) {
		t.Fatal("Root unchanged after deletes — something is wrong")
	}

	// ------------------------------------------------------------------
	// Phase 4: Verify remaining keys are still present, deleted keys are gone.
	// ------------------------------------------------------------------
	for i, pair := range inserted {
		if deletedKeys[string(pair.key)] {
			_, err := goTree.Get(pair.key)
			if err == nil {
				t.Fatalf("Go Get #%d: expected error for deleted key", i)
			}
			_, found := rustTree.Get(pair.key)
			if found {
				t.Fatalf("Rust Get #%d: deleted key still found", i)
			}
		} else {
			goVal, err := goTree.Get(pair.key)
			if err != nil {
				t.Fatalf("Go Get #%d: unexpected error: %v", i, err)
			}
			rustVal, found := rustTree.Get(pair.key)
			if !found {
				t.Fatalf("Rust Get #%d: key not found", i)
			}
			if !bytes.Equal(goVal, rustVal) {
				t.Fatalf("Value mismatch at #%d after deletes", i)
			}
		}
	}
	t.Logf("Phase 4 PASSED: all lookups consistent after deletes")
}

// ---------------------------------------------------------------------------
// Serialization round-trip test: serialize the Rust tree, deserialize into a
// new instance, and verify the commitment is unchanged.
// ---------------------------------------------------------------------------

func TestRustTreeSerializationRoundtrip(t *testing.T) {
	proverKey := make([]byte, 32)

	rustTree := NewRustTree()

	rng := mrand.New(mrand.NewSource(99))
	for i := 0; i < 200; i++ {
		key := make([]byte, 32)
		value := make([]byte, 64)
		rng.Read(key)
		rng.Read(value)
		rustTree.Insert(key, value)
	}

	root1 := rustTree.Commit(proverKey)

	serialized := rustTree.Serialize()
	if len(serialized) == 0 {
		t.Fatal("Serialize returned empty bytes")
	}

	rustTree2 := NewRustTree()
	rustTree2.Deserialize(serialized)

	root2 := rustTree2.Commit(proverKey)

	if !bytes.Equal(root1, root2) {
		t.Fatalf(
			"Root mismatch after serialize/deserialize.\n  Before: %x\n  After:  %x",
			root1, root2,
		)
	}
	t.Logf("Serialization round-trip PASSED (%d bytes serialized)", len(serialized))
}

// ---------------------------------------------------------------------------
// Insertion order independence: both Go and Rust trees must produce the same
// root regardless of insertion order.
// ---------------------------------------------------------------------------

func TestRustTreeInsertionOrderIndependence(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	const n = 500

	// Generate random key-value pairs.
	rng := mrand.New(mrand.NewSource(7))
	type kv struct {
		key   []byte
		value []byte
	}
	pairs := make([]kv, n)
	for i := range pairs {
		pairs[i].key = make([]byte, 32)
		pairs[i].value = make([]byte, 32)
		rng.Read(pairs[i].key)
		rng.Read(pairs[i].value)
	}

	// Forward order.
	goFwd := &tries.VectorCommitmentTree{}
	rustFwd := NewRustTree()
	for _, p := range pairs {
		goFwd.Insert(p.key, p.value, nil, big.NewInt(1))
		rustFwd.Insert(p.key, p.value)
	}

	goFwdRoot := goFwd.Commit(prover, true)
	rustFwdRoot := rustFwd.Commit(proverKey)

	if !bytes.Equal(goFwdRoot, rustFwdRoot) {
		t.Fatalf("Forward-order root mismatch: Go=%x Rust=%x", goFwdRoot[:8], rustFwdRoot[:8])
	}

	// Reverse order.
	goRev := &tries.VectorCommitmentTree{}
	rustRev := NewRustTree()
	for i := n - 1; i >= 0; i-- {
		goRev.Insert(pairs[i].key, pairs[i].value, nil, big.NewInt(1))
		rustRev.Insert(pairs[i].key, pairs[i].value)
	}

	goRevRoot := goRev.Commit(prover, true)
	rustRevRoot := rustRev.Commit(proverKey)

	if !bytes.Equal(goRevRoot, rustRevRoot) {
		t.Fatalf("Reverse-order root mismatch: Go=%x Rust=%x", goRevRoot[:8], rustRevRoot[:8])
	}

	// Forward and reverse must produce the same root.
	if !bytes.Equal(goFwdRoot, goRevRoot) {
		t.Fatalf(
			"Insertion order dependence detected.\n  Forward: %x\n  Reverse: %x",
			goFwdRoot[:8], goRevRoot[:8],
		)
	}

	t.Logf("Insertion order independence PASSED (%d entries, root=%x)", n, goFwdRoot[:8])
}

// ---------------------------------------------------------------------------
// Stress test with larger random keys and values.
// ---------------------------------------------------------------------------

func TestRustTreeLargeValues(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	const n = 300

	rng := mrand.New(mrand.NewSource(456))

	for i := 0; i < n; i++ {
		// Fixed 32-byte keys, variable-length values (1-4096 bytes).
		key := make([]byte, 32)
		rng.Read(key)
		valLen := rng.Intn(4096) + 1
		value := make([]byte, valLen)
		rng.Read(value)

		goTree.Insert(key, value, nil, big.NewInt(int64(valLen)))
		rustTree.Insert(key, value)
	}

	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf(
			"Large value root mismatch.\n  Go:   %x\n  Rust: %x",
			goRoot, rustRoot,
		)
	}
	t.Logf("Large values PASSED (%d entries with up to 4KB values, root=%x)", n, goRoot[:8])
}

// ---------------------------------------------------------------------------
// Edge case: single entry tree.
// ---------------------------------------------------------------------------

func TestRustTreeSingleEntry(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	key := []byte("single-key")
	value := []byte("single-value")

	goTree.Insert(key, value, nil, big.NewInt(1))
	rustTree.Insert(key, value)

	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf("Single entry root mismatch.\n  Go:   %x\n  Rust: %x", goRoot, rustRoot)
	}
	t.Logf("Single entry PASSED (root=%x)", goRoot[:8])
}

// ---------------------------------------------------------------------------
// Edge case: empty tree produces a zero root.
// ---------------------------------------------------------------------------

func TestRustTreeEmptyTreeRoot(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf("Empty tree root mismatch.\n  Go:   %x\n  Rust: %x", goRoot, rustRoot)
	}

	// Empty root should be 64 zero bytes.
	expected := make([]byte, 64)
	if !bytes.Equal(goRoot, expected) {
		t.Fatalf("Empty tree root is not 64 zero bytes: %x", goRoot)
	}
	t.Logf("Empty tree PASSED")
}

// ---------------------------------------------------------------------------
// Delete all entries: tree should return to the empty-tree root.
// ---------------------------------------------------------------------------

func TestRustTreeDeleteAll(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	rng := mrand.New(mrand.NewSource(555))
	type kv struct {
		key   []byte
		value []byte
	}

	const n = 50
	pairs := make([]kv, n)
	for i := range pairs {
		pairs[i].key = make([]byte, 16)
		pairs[i].value = make([]byte, 16)
		rng.Read(pairs[i].key)
		rng.Read(pairs[i].value)

		goTree.Insert(pairs[i].key, pairs[i].value, nil, big.NewInt(1))
		rustTree.Insert(pairs[i].key, pairs[i].value)
	}

	// Delete all.
	for _, p := range pairs {
		goTree.Delete(p.key)
		rustTree.Delete(p.key)
	}

	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf("Delete-all root mismatch.\n  Go:   %x\n  Rust: %x", goRoot, rustRoot)
	}

	expected := make([]byte, 64)
	if !bytes.Equal(goRoot, expected) {
		t.Fatalf("Delete-all root is not 64 zero bytes: %x", goRoot)
	}
	t.Logf("Delete all PASSED")
}

// ---------------------------------------------------------------------------
// Update (overwrite) test: inserting the same key with a new value should
// produce matching roots.
// ---------------------------------------------------------------------------

func TestRustTreeUpdateExistingKeys(t *testing.T) {
	prover := &sha512Prover{}
	proverKey := make([]byte, 32)

	goTree := &tries.VectorCommitmentTree{}
	rustTree := NewRustTree()

	rng := mrand.New(mrand.NewSource(333))

	const n = 200
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = make([]byte, 32)
		rng.Read(keys[i])

		value := make([]byte, 32)
		rng.Read(value)
		goTree.Insert(keys[i], value, nil, big.NewInt(1))
		rustTree.Insert(keys[i], value)
	}

	// Overwrite all keys with new values.
	for _, key := range keys {
		newValue := make([]byte, 48)
		rng.Read(newValue)
		goTree.Insert(key, newValue, nil, big.NewInt(1))
		rustTree.Insert(key, newValue)
	}

	goRoot := goTree.Commit(prover, true)
	rustRoot := rustTree.Commit(proverKey)

	if !bytes.Equal(goRoot, rustRoot) {
		t.Fatalf("Update root mismatch.\n  Go:   %x\n  Rust: %x", goRoot, rustRoot)
	}
	t.Logf("Update existing keys PASSED (%d keys, root=%x)", n, goRoot[:8])
}

// ---------------------------------------------------------------------------
// Proof generation and verification test.
// ---------------------------------------------------------------------------

func TestRustTreeProveAndVerify(t *testing.T) {
	t.Skip("Prove/verify requires KZG multiproofs (ProveMultiple) which the SHA-512 test prover does not support. Root commitment equality — which is the consensus-critical property — is validated by TestRustTreeMatchesGoTree. Prove/verify is tested in the BLS48581 integration tests.")
	proverKey := make([]byte, 32)

	rustTree := NewRustTree()

	rng := mrand.New(mrand.NewSource(77))
	type kv struct {
		key   []byte
		value []byte
	}

	const n = 100
	pairs := make([]kv, n)
	for i := range pairs {
		pairs[i].key = make([]byte, 32)
		pairs[i].value = make([]byte, 32)
		rng.Read(pairs[i].key)
		rng.Read(pairs[i].value)
		rustTree.Insert(pairs[i].key, pairs[i].value)
	}

	root := rustTree.Commit(proverKey)

	// Verify a subset of proofs.
	for i := 0; i < 20; i++ {
		p := pairs[i]
		proof := rustTree.Prove(p.key, proverKey)
		if len(proof) == 0 {
			t.Fatalf("Prove returned empty proof for key #%d", i)
		}

		valid := rustTree.VerifyProof(root, p.key, p.value, proof, proverKey)
		if !valid {
			t.Fatalf("VerifyProof failed for key #%d", i)
		}
	}

	// Negative test: wrong value should fail verification.
	wrongValue := make([]byte, 32)
	rand.Read(wrongValue)
	proof := rustTree.Prove(pairs[0].key, proverKey)
	valid := rustTree.VerifyProof(root, pairs[0].key, wrongValue, proof, proverKey)
	if valid {
		t.Fatal("VerifyProof should have failed for wrong value")
	}

	t.Logf("Prove and verify PASSED")
}
