//go:build integrationtest
// +build integrationtest

package crypto

import (
	"bytes"
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// This test requires native code integration to be useful
var verEncr = verenc.NewMPCitHVerifiableEncryptor(1)

func BenchmarkLazyVectorCommitmentTreeInsert(b *testing.B) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	store := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: store, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)

		addresses = append(addresses, append(append([]byte{}, make([]byte, 32)...), d...))
		err := tree.Insert(nil, d, d, nil, big.NewInt(1))
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
	}
}

func BenchmarkLazyVectorCommitmentTreeCommit(b *testing.B) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	store := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: store, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, append(append([]byte{}, make([]byte, 32)...), d...))
		err := tree.Insert(nil, d, d, nil, big.NewInt(1))
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		tree.Commit(false)
	}
}

func BenchmarkLazyVectorCommitmentTreeProve(b *testing.B) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	store := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: store, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, append(append([]byte{}, make([]byte, 32)...), d...))
		err := tree.Insert(nil, d, d, nil, big.NewInt(1))
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		tree.Commit(false)
		tree.Prove(d)
	}
}

func BenchmarkLazyVectorCommitmentTreeVerify(b *testing.B) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	store := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: store, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, append(append([]byte{}, make([]byte, 32)...), d...))
		err := tree.Insert(nil, d, d, nil, big.NewInt(1))
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		c := tree.Commit(false)
		p := tree.Prove(d)
		if valid, _ := tree.Verify(c, p); !valid {
			b.Errorf("bad proof")
		}
	}
}

func TestLazyVectorCommitmentTrees(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Test single insert
	err := tree.Insert(nil, []byte("key1"), []byte("value1"), nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to insert: %v", err)
	}

	// Test duplicate key
	err = tree.Insert(nil, []byte("key1"), []byte("value2"), nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to update existing key: %v", err)
	}

	value, err := tree.Get([]byte("key1"))
	if err != nil {
		t.Errorf("Failed to get value: %v", err)
	}
	if !bytes.Equal(value, []byte("value2")) {
		t.Errorf("Expected value2, got %s", string(value))
	}

	// Test empty key
	err = tree.Insert(nil, []byte{}, []byte("value"), nil, big.NewInt(1))
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Test get on empty tree
	_, err = tree.Get([]byte("nonexistent"))
	if err == nil {
		t.Error("Expected error for nonexistent key, got none")
	}

	// Insert and get
	tree.Insert(nil, []byte("key1"), []byte("value1"), nil, big.NewInt(1))
	value, err = tree.Get([]byte("key1"))
	if err != nil {
		t.Errorf("Failed to get value: %v", err)
	}
	if !bytes.Equal(value, []byte("value1")) {
		t.Errorf("Expected value1, got %s", string(value))
	}

	// Test empty key
	_, err = tree.Get([]byte{})
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Test delete on empty tree
	err = tree.Delete(nil, []byte("nonexistent"))
	if err != nil {
		t.Errorf("Delete on empty tree should not return error: %v", err)
	}

	// Insert and delete
	tree.Insert(nil, []byte("key1"), []byte("value1"), nil, big.NewInt(1))
	err = tree.Delete(nil, []byte("key1"))
	if err != nil {
		t.Errorf("Failed to delete: %v", err)
	}

	// Verify deletion
	v, err := tree.Get([]byte("key1"))
	if err == nil {
		t.Errorf("Expected error for deleted key, got none, %v", v)
	}

	// Test empty key
	err = tree.Delete(nil, []byte{})
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Insert keys that share common prefix
	keys := []string{
		"key1",
		"key2",
		"key3",
		"completely_different",
	}

	for i, key := range keys {
		err := tree.Insert(nil, []byte(key), []byte("value"+string(rune('1'+i))), nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert key %s: %v", key, err)
		}
	}

	// Verify all values
	for i, key := range keys {
		value, err := tree.Get([]byte(key))
		if err != nil {
			t.Errorf("Failed to get key %s: %v", key, err)
		}
		expected := []byte("value" + string(rune('1'+i)))
		if !bytes.Equal(value, expected) {
			t.Errorf("Expected %s, got %s", string(expected), string(value))
		}
	}

	// Delete middle key
	err = tree.Delete(nil, []byte("key2"))
	if err != nil {
		t.Errorf("Failed to delete key2: %v", err)
	}

	// Verify key2 is gone but others remain
	_, err = tree.Get([]byte("key2"))
	if err == nil {
		t.Error("Expected error for deleted key2, got none")
	}

	// Check remaining keys
	remainingKeys := []string{"key1", "key3", "completely_different"}
	remainingValues := []string{"value1", "value3", "value4"}
	for i, key := range remainingKeys {
		value, err := tree.Get([]byte(key))
		if err != nil {
			t.Errorf("Failed to get key %s after deletion: %v", key, err)
		}
		expected := []byte(remainingValues[i])
		if !bytes.Equal(value, expected) {
			t.Errorf("Expected %s, got %s", string(expected), string(value))
		}
	}

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Empty tree should be empty
	emptyRoot := tree.Root
	if emptyRoot != nil {
		t.Errorf("Expected empty root")
	}

	// Root should change after insert
	tree.Insert(nil, []byte("key1"), []byte("value1"), nil, big.NewInt(1))
	firstRoot := tree.Commit(false)

	if bytes.Equal(firstRoot, bytes.Repeat([]byte{0x00}, 64)) {
		t.Error("Root hash should change after insert")
	}

	// Root should change after update
	tree.Insert(nil, []byte("key1"), []byte("value2"), nil, big.NewInt(1))
	secondRoot := tree.Commit(false)

	if bytes.Equal(secondRoot, firstRoot) {
		t.Error("Root hash should change after update")
	}

	// Root should change after delete
	tree.Delete(nil, []byte("key1"))
	thirdRoot := tree.Root

	if thirdRoot != nil {
		t.Error("Root hash should match empty tree after deleting all entries")
	}

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}
	cmptree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	addresses := [][]byte{}

	for i := 0; i < 10000; i++ {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, append(append([]byte{}, make([]byte, 32)...), d...))
	}

	kept := [][]byte{}
	for i := 0; i < 5000; i++ {
		kept = append(kept, addresses[i])
	}

	newAdditions := [][]byte{}
	for i := 0; i < 5000; i++ {
		d := make([]byte, 32)
		rand.Read(d)
		newAdditions = append(newAdditions, append(append([]byte{}, make([]byte, 32)...), d...))
		kept = append(kept, append(append([]byte{}, make([]byte, 32)...), d...))
	}

	// Insert 10000 items
	for i := 0; i < 10000; i++ {
		key := addresses[i]
		value := addresses[i]
		err := tree.Insert(nil, key, value, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	if tree.GetSize().Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("invalid tree size: %s", tree.GetSize().String())
	}

	// Insert 10000 items in reverse
	for i := 9999; i >= 0; i-- {
		key := addresses[i]
		value := addresses[i]
		err := cmptree.Insert(nil, key, value, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Verify all items
	for i := 0; i < 10000; i++ {
		key := addresses[i]
		expected := addresses[i]
		value, err := tree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		cmpvalue, err := cmptree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		if !bytes.Equal(value, expected) {
			t.Errorf("Item %d: expected %x, got %x", i, string(expected), string(value))
		}
		if !bytes.Equal(value, cmpvalue) {
			t.Errorf("Item %d: expected %x, got %x", i, string(value), string(cmpvalue))
		}
	}

	// delete keys
	for i := 5000; i < 10000; i++ {
		key := addresses[i]
		tree.Delete(nil, key)
	}

	if tree.GetSize().Cmp(big.NewInt(5000)) != 0 {
		t.Errorf("invalid tree size: %s", tree.GetSize().String())
	}

	// add new
	for i := 0; i < 5000; i++ {
		tree.Insert(nil, newAdditions[i], newAdditions[i], nil, big.NewInt(1))
	}

	if tree.GetSize().Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("invalid tree size: %s", tree.GetSize().String())
	}

	cmptree = &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	for i := 0; i < 10000; i++ {
		cmptree.Insert(nil, kept[i], kept[i], nil, big.NewInt(1))
	}
	// Verify all items
	for i := 0; i < 10000; i++ {
		key := kept[i]
		expected := kept[i]
		value, err := tree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		cmpvalue, err := cmptree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		if !bytes.Equal(value, expected) {
			t.Errorf("Item %d: expected %x, got %x", i, string(expected), string(value))
		}
		if !bytes.Equal(expected, cmpvalue) {
			t.Errorf("Item %d: expected %x, got %x", i, string(value), string(cmpvalue))
		}
	}
	tcommit := tree.Commit(false)
	cmptcommit := cmptree.Commit(false)

	if !bytes.Equal(tcommit, cmptcommit) {
		t.Errorf("tree mismatch, %x, %x", tcommit, cmptcommit)
	}

	proofs := tree.Prove(addresses[500])
	if valid, _ := tree.Verify(tcommit, proofs); !valid {
		t.Errorf("proof failed")
	}

	leaves, longestBranch := tree.GetMetadata()

	if leaves != 10000 {
		t.Errorf("incorrect leaf count, %d, %d,", 10000, leaves)
	}

	// Statistical assumption, can be flaky
	if longestBranch < 4 || longestBranch > 5 {
		crypto.DebugNode(tree.SetType, tree.PhaseType, tree.ShardKey, tree.Root, 0, "")
		t.Errorf("unlikely longest branch count, %d, %d, review this tree", 4, longestBranch)
	}
}

// TestTreeLeafReaddition tests that re-adding the exact same leaf does not
// increase the Size metadata, does not invalidate commitments, and does not
// make previous proofs invalid.
func TestTreeLeafReaddition(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Generate 1000 random 64-byte keys and corresponding values
	numKeys := 1000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		// Generate random 64-byte key
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		// Generate random value
		val := make([]byte, 32)
		rand.Read(val)
		values[i] = val

		// Insert into tree
		err := tree.Insert(nil, key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Get original size metadata
	originalSize := tree.GetSize()
	expectedSize := big.NewInt(int64(numKeys))
	if originalSize.Cmp(expectedSize) != 0 {
		t.Errorf("Expected tree size to be %s, got %s", expectedSize.String(), originalSize.String())
	}

	// Commit the tree and get root commitment
	originalRoot := tree.Commit(false)

	// Choose a random key to test with
	testIndex := mrand.Intn(numKeys)
	testKey := keys[testIndex]
	testValue := values[testIndex]

	// Generate proof for the selected leaf
	originalProof := tree.Prove(testKey)

	// Validate the proof
	if valid, _ := tree.Verify(originalRoot, originalProof); !valid {
		t.Errorf("Failed to verify original proof")
	}

	// Re-add the exact same leaf
	err := tree.Insert(nil, testKey, testValue, nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to re-insert the same leaf: %v", err)
	}

	// Check size hasn't changed
	newSize := tree.GetSize()
	if newSize.Cmp(originalSize) != 0 {
		t.Errorf("Expected size to remain %s after re-adding same leaf, got %s", originalSize.String(), newSize.String())
	}

	// Commit again
	newRoot := tree.Commit(false)

	// Check commitment hasn't changed
	if !bytes.Equal(originalRoot, newRoot) {
		t.Errorf("Expected commitment to remain the same after re-adding the same leaf")
	}

	// Verify the original proof still works
	if valid, _ := tree.Verify(newRoot, originalProof); !valid {
		t.Errorf("Original proof no longer valid after re-adding the same leaf")
	}
}

// TestTreeRemoveReaddLeaf tests that removing a leaf and re-adding it
// decreases and increases the size metadata appropriately, invalidates commitments,
// but proofs still work after recommitting the tree.
func TestTreeRemoveReaddLeaf(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Generate 1000 random 64-byte keys and corresponding values
	numKeys := 1000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		// Generate random 64-byte key
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		// Generate random value
		val := make([]byte, 32)
		rand.Read(val)
		values[i] = val

		// Insert into tree
		err := tree.Insert(nil, key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Get original size metadata
	originalSize := tree.GetSize()
	expectedSize := big.NewInt(int64(numKeys))
	if originalSize.Cmp(expectedSize) != 0 {
		t.Errorf("Expected tree size to be %s, got %s", expectedSize.String(), originalSize.String())
	}

	// Commit the tree and get root commitment
	originalRoot := tree.Commit(false)

	// Choose a random key to test with
	testIndex := mrand.Intn(numKeys)
	testKey := keys[testIndex]
	testValue := values[testIndex]

	// Generate proof for the selected leaf
	originalProof := tree.Prove(testKey)

	// Validate the proof
	if valid, _ := tree.Verify(originalRoot, originalProof); !valid {
		t.Errorf("Failed to verify original proof")
	}

	// Remove the leaf
	err := tree.Delete(nil, testKey)
	if err != nil {
		t.Errorf("Failed to delete leaf: %v", err)
	}

	// Check size has decreased
	reducedSize := tree.GetSize()
	expectedReducedSize := big.NewInt(int64(numKeys - 1))
	if reducedSize.Cmp(expectedReducedSize) != 0 {
		t.Errorf("Expected size to be %s after removing leaf, got %s", expectedReducedSize.String(), reducedSize.String())
	}

	// Commit after deletion
	deletedRoot := tree.Commit(false)

	// Check commitment has changed
	if bytes.Equal(originalRoot, deletedRoot) {
		t.Errorf("Expected commitment to change after removing a leaf")
	}

	// Verify the proof fails
	if valid, _ := tree.Verify(deletedRoot, originalProof); valid {
		t.Errorf("Original proof still verified")
	}

	// Re-add the same leaf
	err = tree.Insert(nil, testKey, testValue, nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to re-add leaf: %v", err)
	}

	// Check size has increased back to original
	restoredSize := tree.GetSize()
	if restoredSize.Cmp(originalSize) != 0 {
		t.Errorf("Expected size to be restored to %s after re-adding leaf, got %s", originalSize.String(), restoredSize.String())
	}

	// Commit again
	restoredRoot := tree.Commit(false)

	// Check commitment is different due to the rebuild process
	if bytes.Equal(deletedRoot, restoredRoot) {
		t.Errorf("Expected commitment to change after re-adding the leaf")
	}

	// Generate a new proof
	newProof := tree.Prove(testKey)

	// Verify the new proof works
	if valid, _ := tree.Verify(restoredRoot, newProof); !valid {
		t.Errorf("New proof not valid after re-adding the leaf")
	}

	// Check if original and new root match - should match since it's the same data
	if bytes.Equal(originalRoot, restoredRoot) {
		t.Logf("Original and restored roots match, which is expected for deterministic implementations")
	} else {
		t.Fatalf("Note: Original and restored roots differ, which is acceptable for some implementations with randomized components")
	}
}

// TestTreeLongestBranch tests that the longest branch metadata value is always
// correct.
func TestTreeLongestBranch(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Test with an empty tree
	leaves, longestBranch := tree.GetMetadata()
	if leaves != 0 {
		t.Errorf("Expected 0 leaves in empty tree, got %d", leaves)
	}
	if longestBranch != 0 {
		t.Errorf("Expected longest branch of 0 in empty tree, got %d", longestBranch)
	}

	// Insert one item with a random 64-byte key
	key1 := make([]byte, 64)
	rand.Read(key1)
	value1 := make([]byte, 32)
	rand.Read(value1)

	tree.Insert(nil, key1, value1, nil, big.NewInt(1))
	tree.Commit(false)

	leaves, longestBranch = tree.GetMetadata()
	if leaves != 1 {
		t.Errorf("Expected 1 leaf after single insert, got %d", leaves)
	}
	if longestBranch != 0 {
		t.Errorf("Expected longest branch of 0 with single leaf, got %d", longestBranch)
	}

	// Generate batch 1: Add 999 more random keys (total 1000)
	batch1Size := 999
	batch1Keys := make([][]byte, batch1Size)

	for i := 0; i < batch1Size; i++ {
		key := make([]byte, 64)
		rand.Read(key)
		batch1Keys[i] = key

		val := make([]byte, 32)
		rand.Read(val)

		err := tree.Insert(nil, key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert batch 1 item %d: %v", i, err)
		}
	}
	origCommit := tree.Commit(false)
	origProof := tree.Prove(batch1Keys[500])

	// With 1000 random keys, we should have created some branches
	leaves, longestBranch = tree.GetMetadata()
	expectedLeaves := 1000
	if leaves != expectedLeaves {
		t.Errorf("Expected %d leaves after batch 1, got %d", expectedLeaves, leaves)
	}

	// Due to random distribution of keys, we expect a minimum branch depth
	// For 1000 64-byte keys, we expect a minimum branch depth of at least 3
	expectedMinLongestBranch := 3
	if longestBranch < expectedMinLongestBranch {
		t.Errorf("Expected longest branch of at least %d with 1000 random keys, got %d",
			expectedMinLongestBranch, longestBranch)
	}

	expectedMaxLongestBranch := 4
	if longestBranch > expectedMaxLongestBranch {
		t.Errorf("Expected longest branch to be at most %d with 1000 random keys, got %d",
			expectedMaxLongestBranch, longestBranch)
	}

	t.Logf("Tree with 1000 random keys has longest branch of %d", longestBranch)

	// Generate batch 2: Insert 1000 more items with controlled prefixes to create
	// deeper branches. We'll create keys with the same prefix bytes to force
	// branch creation
	batch2Size := 1000
	batch2Keys := make([][]byte, batch2Size)

	// Create a common prefix for first 8 bytes (forcing branch at this level)
	commonPrefix := make([]byte, 8)
	rand.Read(commonPrefix)

	for i := 0; i < batch2Size; i++ {
		key := make([]byte, 64)
		// First 8 bytes are the same for all keys
		copy(key[:8], commonPrefix)
		// Next bytes are random but within controlled ranges to create subgroups
		// This creates deeper branch structures
		key[8] = byte(i % 4)  // Creates 4 major groups
		key[9] = byte(i % 16) // Creates 16 subgroups
		// Rest is random
		rand.Read(key[10:])

		batch2Keys[i] = key

		val := make([]byte, 32)
		rand.Read(val)

		err := tree.Insert(nil, key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert batch 2 item %d: %v", i, err)
		}
	}
	batch2Commit := tree.Commit(false)

	// With controlled prefixes, branches should be deeper
	leaves, newLongestBranch := tree.GetMetadata()
	expectedLeaves = 2000 // 1000 from batch 1 + 1000 from batch 2
	if leaves != expectedLeaves {
		t.Errorf("Expected %d leaves after batch 2, got %d", expectedLeaves, leaves)
	}

	// With our specific prefix design, branches should be deeper
	// The depth should have increased from batch 1
	if newLongestBranch <= longestBranch {
		t.Errorf("Expected longest branch to increase after adding batch 2 with controlled prefixes, "+
			"previous: %d, current: %d", longestBranch, newLongestBranch)
	}

	t.Logf("Tree with 2000 keys including controlled prefixes has longest branch of %d", newLongestBranch)

	// Delete all batch 2 keys
	for _, key := range batch2Keys {
		err := tree.Delete(nil, key)
		if err != nil {
			t.Errorf("Failed to delete structured key: %v", err)
		}
	}
	newCommit := tree.Commit(false)

	if valid, _ := tree.Verify(newCommit, origProof); !valid {
		t.Errorf("Proof does not sustain after tree rollback.")
	}

	if bytes.Equal(origCommit, batch2Commit) {
		t.Errorf("Commits match after altering tree to second batch\norig: %x\n new: %x", origCommit, batch2Commit)
	}

	if !bytes.Equal(origCommit, newCommit) {
		t.Errorf("Commits do not match after reverting tree to original first batch\norig: %x\n new: %x", origCommit, newCommit)
	}

	// After deleting all batch 2 keys, we should be back to the original branch depth
	leaves, finalLongestBranch := tree.GetMetadata()
	expectedLeaves = 1000 // Back to just batch 1
	if leaves != expectedLeaves {
		t.Errorf("Expected %d leaves after deleting batch 2, got %d", expectedLeaves, leaves)
	}

	// Longest branch should have decreased since we removed the structured keys
	if finalLongestBranch > newLongestBranch {
		t.Errorf("Expected longest branch to decrease after deleting structured keys, "+
			"previous: %d, current: %d", newLongestBranch, finalLongestBranch)
	}

	// Must be the same
	expectedDiffFromOriginal := 0
	diff := int(finalLongestBranch) - int(longestBranch)
	if diff < 0 {
		diff = -diff // Absolute value
	}
	if diff != expectedDiffFromOriginal {
		t.Logf("Note: Longest branch after deleting batch 2 (%d) differs significantly from "+
			"original batch 1 longest branch (%d)", finalLongestBranch, longestBranch)
	}
}

// TestTreeBranchStructure tests that the tree structure is preserved after
// adding and removing leaves that cause branch creation due to shared prefixes.
func TestTreeBranchStructure(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create three base keys with 64-byte size
	numBaseKeys := 3
	baseKeys := make([][]byte, numBaseKeys)
	baseValues := make([][]byte, numBaseKeys)

	// Create base keys that share same first byte and have a controlled second and
	// third, but are otherwise random
	for i := 0; i < numBaseKeys; i++ {
		key := make([]byte, 64)
		//       101000 001010 0000
		key[0] = 0xA0 // Common first byte
		key[1] = 0xA0
		//      finalizes the third path nibble as i -> 0, 1, 2
		key[2] = byte((i << 6) & 0xFF)
		rand.Read(key[3:])
		baseKeys[i] = key

		val := make([]byte, 32)
		rand.Read(val)
		baseValues[i] = val

		err := tree.Insert(nil, key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert base key %d: %v", i, err)
		}
	}

	// Commit the initial state
	initialRoot := tree.Commit(false)
	initialSize := tree.GetSize()

	// Confirm initial state
	if initialSize.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("Expected initial size of 3, got %s", initialSize.String())
	}

	// Get proofs for existing keys to check later
	initialProof := tree.Prove(baseKeys[0])
	initialProof2 := tree.Prove(baseKeys[1])
	if bytes.Equal(initialProof.Multiproof.GetProof(), initialProof2.Multiproof.GetProof()) {
		t.Errorf("proof should not be equal")
	}

	// Add a key that forces a new branch creation due to shared prefix with
	// baseKeys[0]
	branchKey := make([]byte, 64)
	copy(branchKey, baseKeys[0]) // Start with same bytes as baseKeys[0]
	// Modify just one byte in the middle to create branch point
	branchKey[32] ^= 0xFF
	branchValue := make([]byte, 32)
	rand.Read(branchValue)

	err := tree.Insert(nil, branchKey, branchValue, nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to insert branch-creating key: %v", err)
	}

	// Commit after adding the branch-creating key
	branchRoot := tree.Commit(false)
	branchSize := tree.GetSize()

	// Confirm size increased
	if branchSize.Cmp(big.NewInt(4)) != 0 {
		t.Errorf("Expected size of 4 after adding branch key, got %s", branchSize.String())
	}

	// Confirm commitment changed
	if bytes.Equal(initialRoot, branchRoot) {
		t.Errorf("Expected root to change after adding branch-creating key")
	}

	// Remove the key that created the branch
	err = tree.Delete(nil, branchKey)
	if err != nil {
		t.Errorf("Failed to delete branch-creating key: %v", err)
	}

	// Commit after removing the branch-creating key
	restoredRoot := tree.Commit(false)
	restoredSize := tree.GetSize()
	// Confirm size returned to original
	if restoredSize.Cmp(initialSize) != 0 {
		t.Errorf("Expected size to return to %s after removing branch key, got %s",
			initialSize.String(), restoredSize.String())
	}

	// The root should match the initial root if the structure was perfectly
	// restored
	if !bytes.Equal(initialRoot, restoredRoot) {
		t.Errorf("Tree structure not perfectly restored: initial root and restored root differ")
	}

	// Confirm original proof still works
	if valid, _ := tree.Verify(restoredRoot, initialProof); !valid {
		t.Errorf("Original proof no longer valid after restoring tree structure")
	}

	// More complex test with multiple branch levels
	// Create groups of keys with controlled prefixes
	numGroups := int64(2)
	keysPerGroup := int64(500)
	groupPrefixLength := 16 // First 16 bytes should be identical within a group

	groupKeys := make([][][]byte, numGroups)
	for i := int64(0); i < numGroups; i++ {
		// Create group prefix - first 16 bytes are the same within each group
		groupPrefix := make([]byte, groupPrefixLength)
		rand.Read(groupPrefix)
		// Ensure that the group is out of band of the initial set.
		groupPrefix[0] = 0xFF

		// Now create the keys for this group
		groupKeys[i] = make([][]byte, keysPerGroup)
		for j := int64(0); j < keysPerGroup; j++ {
			key := make([]byte, 64)
			// Copy the group prefix
			copy(key[:groupPrefixLength], groupPrefix)
			// Fill the rest with random bytes
			rand.Read(key[groupPrefixLength:])
			groupKeys[i][j] = key

			val := make([]byte, 32)
			rand.Read(val)

			err := tree.Insert(nil, key, val, nil, big.NewInt(1))
			if err != nil {
				t.Errorf("Failed to insert complex key [group %d, key %d]: %v", i, j, err)
			}
		}
	}

	// Commit after adding all complex keys
	tree.Commit(false)

	complexSize := tree.GetSize()
	expectedComplexSize := big.NewInt(3 + numGroups*keysPerGroup)
	if complexSize.Cmp(expectedComplexSize) != 0 {
		t.Errorf("Expected complex tree size of %s, got %s",
			expectedComplexSize.String(), complexSize.String())
	}

	// Remove just one group
	for j := int64(0); j < keysPerGroup; j++ {
		err := tree.Delete(nil, groupKeys[0][j])
		if err != nil {
			t.Errorf("Failed to delete key from group 0: %v", err)
		}
	}

	// Commit after removal
	c := tree.Commit(false)

	afterGroupRemoval := tree.GetSize()
	expectedAfterRemoval := big.NewInt(3 + keysPerGroup)
	if afterGroupRemoval.Cmp(expectedAfterRemoval) != 0 {
		t.Errorf("Expected tree size of %s after group removal, got %s",
			expectedAfterRemoval.String(), afterGroupRemoval.String())
	}

	// Confirm full proof
	fullProof := tree.Prove(baseKeys[0])
	// value, err := tree.Get(baseKeys[0])
	// if err != nil {
	// 	t.Errorf("Fetch had error: %v", err)
	// }

	if valid, _ := tree.Verify(c, fullProof); !valid {
		t.Errorf("somehow the regular proof failed?")
	}
}

func TestNonLazyProveVerify(t *testing.T) {
	l, _ := zap.NewProduction()
	prover := bls48581.NewKZGInclusionProver(l)
	tree := &crypto.VectorCommitmentTree{}
	// Generate 1000 random 64-byte keys and corresponding values
	numKeys := 1000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		// Generate random 64-byte key
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		// Generate random value
		val := make([]byte, 32)
		rand.Read(val)
		values[i] = val

		// Insert into tree
		err := tree.Insert(key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Get original size metadata
	originalSize := tree.GetSize()
	expectedSize := big.NewInt(int64(numKeys))
	if originalSize.Cmp(expectedSize) != 0 {
		t.Errorf("Expected tree size to be %s, got %s", expectedSize.String(), originalSize.String())
	}

	// Commit the tree and get root commitment
	originalRoot := tree.Commit(prover, false)

	// Choose a random key to test with
	testIndex := mrand.Intn(numKeys)
	testKey := keys[testIndex]
	testValue := values[testIndex]

	// Generate proof for the selected leaf
	originalProof := tree.Prove(prover, testKey)

	// Validate the proof
	if !crypto.VerifyTreeTraversalProof(prover, originalRoot, originalProof) {
		t.Errorf("Failed to verify original proof")
	}

	// Re-add the exact same leaf
	err := tree.Insert(testKey, testValue, nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to re-insert the same leaf: %v", err)
	}

	// Check size hasn't changed
	newSize := tree.GetSize()
	if newSize.Cmp(originalSize) != 0 {
		t.Errorf("Expected size to remain %s after re-adding same leaf, got %s", originalSize.String(), newSize.String())
	}

	// Commit again
	newRoot := tree.Commit(prover, false)

	// Check commitment hasn't changed
	if !bytes.Equal(originalRoot, newRoot) {
		t.Errorf("Expected commitment to remain the same after re-adding the same leaf")
	}

	// Verify the original proof still works
	if !crypto.VerifyTreeTraversalProof(prover, newRoot, originalProof) {
		t.Errorf("Original proof no longer valid after re-adding the same leaf")
	}
}

func TestNonLazyProveMultipleVerify(t *testing.T) {
	l, _ := zap.NewProduction()
	prover := bls48581.NewKZGInclusionProver(l)
	tree := &crypto.VectorCommitmentTree{}
	// Generate 1000 random 64-byte keys and corresponding values
	numKeys := 1000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		// Generate random 64-byte key
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		// Generate random value
		val := make([]byte, 32)
		rand.Read(val)
		values[i] = val

		// Insert into tree
		err := tree.Insert(key, val, nil, big.NewInt(1))
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Get original size metadata
	originalSize := tree.GetSize()
	expectedSize := big.NewInt(int64(numKeys))
	if originalSize.Cmp(expectedSize) != 0 {
		t.Errorf("Expected tree size to be %s, got %s", expectedSize.String(), originalSize.String())
	}

	// Commit the tree and get root commitment
	originalRoot := tree.Commit(prover, false)

	// Choose a few random keys to test with
	testKeys := [][]byte{}
	testValues := [][]byte{}
	for _ = range 3 {
		testIndex := mrand.Intn(numKeys)
		testKey := keys[testIndex]
		testValue := values[testIndex]
		testKeys = append(testKeys, testKey)
		testValues = append(testValues, testValue)
	}

	// Generate proof for the selected leaf
	originalProof := tree.ProveMultiple(prover, testKeys)

	// Validate the proof
	if !crypto.VerifyTreeTraversalProof(prover, originalRoot, originalProof) {
		t.Errorf("Failed to verify original proof")
	}

	// Re-add the exact same leaf
	err := tree.Insert(testKeys[0], testValues[0], nil, big.NewInt(1))
	if err != nil {
		t.Errorf("Failed to re-insert the same leaf: %v", err)
	}

	// Check size hasn't changed
	newSize := tree.GetSize()
	if newSize.Cmp(originalSize) != 0 {
		t.Errorf("Expected size to remain %s after re-adding same leaf, got %s", originalSize.String(), newSize.String())
	}

	// Commit again
	newRoot := tree.Commit(prover, false)

	// Check commitment hasn't changed
	if !bytes.Equal(originalRoot, newRoot) {
		t.Errorf("Expected commitment to remain the same after re-adding the same leaf")
	}

	// Verify the original proof still works
	if !crypto.VerifyTreeTraversalProof(prover, newRoot, originalProof) {
		t.Errorf("Original proof no longer valid after re-adding the same leaf")
	}
}
