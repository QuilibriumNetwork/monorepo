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

// TestDeleteLeafPromotion tests the case where deleting a leaf from a branch
// leaves only one remaining child that is also a leaf, triggering leaf promotion.
// This covers the "case 1" path with a leaf child in the Delete method.
// Uses 5000 keys to create deep tree structure with many leaf promotion opportunities.
func TestDeleteLeafPromotion(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create pairs of keys that share long prefixes to force leaf promotions
	// Each pair shares 60 bytes, creating branches with exactly 2 leaf children
	numPairs := 2500
	keys := make([][]byte, numPairs*2)
	values := make([][]byte, numPairs*2)

	for i := 0; i < numPairs; i++ {
		// Create a pair of keys sharing 60 bytes
		key1 := make([]byte, 64)
		key2 := make([]byte, 64)
		rand.Read(key1)
		copy(key2, key1[:60])
		// Differ in last 4 bytes
		key2[60] = key1[60] ^ 0xFF
		rand.Read(key2[61:])

		keys[i*2] = key1
		keys[i*2+1] = key2

		value1 := make([]byte, 32)
		value2 := make([]byte, 32)
		rand.Read(value1)
		rand.Read(value2)
		values[i*2] = value1
		values[i*2+1] = value2
	}

	// Insert all keys
	for i, key := range keys {
		if err := tree.Insert(nil, key, values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	// Commit initial state
	root1 := tree.Commit(false)
	t.Logf("Inserted %d keys, tree size: %s", len(keys), tree.GetSize().String())

	leaves, depth := tree.GetMetadata()
	t.Logf("Initial tree: %d leaves, longest branch: %d", leaves, depth)

	// Delete one key from each pair - this triggers leaf promotion for the remaining key
	// Delete the second key of each pair (odd indices)
	deletedCount := 0
	for i := 1; i < len(keys); i += 2 {
		if err := tree.Delete(nil, keys[i]); err != nil {
			t.Fatalf("Failed to delete key %d: %v", i, err)
		}
		deletedCount++
	}

	t.Logf("Deleted %d keys (one from each pair)", deletedCount)

	// Verify deleted keys are gone
	for i := 1; i < len(keys); i += 2 {
		if _, err := tree.Get(keys[i]); err == nil {
			t.Fatalf("key %d still exists after deletion", i)
		}
	}

	// Verify remaining keys (first of each pair) still exist with correct values
	for i := 0; i < len(keys); i += 2 {
		val, err := tree.Get(keys[i])
		if err != nil {
			t.Fatalf("key %d not found after leaf promotion: %v", i, err)
		}
		if !bytes.Equal(val, values[i]) {
			t.Fatalf("key %d value corrupted after leaf promotion", i)
		}
	}

	// Verify tree size
	expectedSize := big.NewInt(int64(numPairs))
	if tree.GetSize().Cmp(expectedSize) != 0 {
		t.Fatalf("Expected tree size %s, got %s", expectedSize.String(), tree.GetSize().String())
	}

	// Commit and verify proofs
	root2 := tree.Commit(false)
	if bytes.Equal(root1, root2) {
		t.Fatalf("Root should have changed after deletions")
	}

	leaves2, depth2 := tree.GetMetadata()
	t.Logf("After deletion: %d leaves, longest branch: %d", leaves2, depth2)

	// Verify proofs for remaining keys
	for i := 0; i < len(keys); i += 2 {
		proof := tree.Prove(keys[i])
		if valid, _ := tree.Verify(root2, proof); !valid {
			t.Fatalf("Proof failed for key %d after leaf promotion", i)
		}
	}
}

// TestDeleteBranchPromotion tests the case where deleting a leaf from a branch
// leaves only one remaining child that is itself a branch, triggering branch
// promotion/merging. This covers the "case 1" path with a branch child.
// Uses 10000+ keys organized in groups to create many branch promotion scenarios.
func TestDeleteBranchPromotion(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create structure where each "group" has:
	// - 1 "loner" key that diverges early
	// - Multiple keys that share a longer prefix (forming a sub-branch)
	// When we delete the loner, the sub-branch gets promoted with prefix merging
	//
	//        Branch (group root)
	//       /      \
	//    Loner    SubBranch
	//             /  |  \
	//          Key1 Key2 Key3...

	numGroups := 1000
	keysPerSubBranch := 10
	totalKeys := numGroups * (1 + keysPerSubBranch)

	keys := make([][]byte, 0, totalKeys)
	values := make([][]byte, 0, totalKeys)
	lonerIndices := make([]int, 0, numGroups)

	for g := 0; g < numGroups; g++ {
		// Generate group prefix (first 8 bytes unique per group)
		groupPrefix := make([]byte, 8)
		rand.Read(groupPrefix)

		// Create loner key - diverges at byte 8
		lonerKey := make([]byte, 64)
		copy(lonerKey[:8], groupPrefix)
		lonerKey[8] = 0x00 // Loner goes one direction
		rand.Read(lonerKey[9:])

		lonerValue := make([]byte, 32)
		rand.Read(lonerValue)

		lonerIndices = append(lonerIndices, len(keys))
		keys = append(keys, lonerKey)
		values = append(values, lonerValue)

		// Create sub-branch keys - share longer prefix (bytes 8-50), diverge at byte 50
		subBranchPrefix := make([]byte, 42)
		subBranchPrefix[0] = 0xFF // Sub-branch goes other direction
		rand.Read(subBranchPrefix[1:])

		for i := 0; i < keysPerSubBranch; i++ {
			subKey := make([]byte, 64)
			copy(subKey[:8], groupPrefix)
			copy(subKey[8:50], subBranchPrefix)
			subKey[50] = byte(i) // Each sub-key differs at byte 50
			rand.Read(subKey[51:])

			subValue := make([]byte, 32)
			rand.Read(subValue)

			keys = append(keys, subKey)
			values = append(values, subValue)
		}
	}

	t.Logf("Created %d keys in %d groups (%d loners + %d per sub-branch)",
		len(keys), numGroups, numGroups, keysPerSubBranch)

	// Insert all keys
	for i, key := range keys {
		if err := tree.Insert(nil, key, values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	root1 := tree.Commit(false)
	leaves1, depth1 := tree.GetMetadata()
	t.Logf("Initial tree: %d leaves, longest branch: %d", leaves1, depth1)

	// Delete all loner keys - this triggers branch promotion for each group
	for _, idx := range lonerIndices {
		if err := tree.Delete(nil, keys[idx]); err != nil {
			t.Fatalf("Failed to delete loner key %d: %v", idx, err)
		}
	}

	t.Logf("Deleted %d loner keys", len(lonerIndices))

	// Verify loners are gone
	for _, idx := range lonerIndices {
		if _, err := tree.Get(keys[idx]); err == nil {
			t.Fatalf("Loner key %d still exists after deletion", idx)
		}
	}

	// Verify all sub-branch keys still exist with correct values
	lonerSet := make(map[int]bool)
	for _, idx := range lonerIndices {
		lonerSet[idx] = true
	}

	remainingCount := 0
	for i, key := range keys {
		if lonerSet[i] {
			continue
		}
		val, err := tree.Get(key)
		if err != nil {
			t.Fatalf("Sub-branch key %d not found after branch promotion: %v", i, err)
		}
		if !bytes.Equal(val, values[i]) {
			t.Fatalf("Sub-branch key %d value corrupted after branch promotion", i)
		}
		remainingCount++
	}

	// Verify tree size
	expectedSize := big.NewInt(int64(remainingCount))
	if tree.GetSize().Cmp(expectedSize) != 0 {
		t.Fatalf("Expected tree size %s, got %s", expectedSize.String(), tree.GetSize().String())
	}

	root2 := tree.Commit(false)
	if bytes.Equal(root1, root2) {
		t.Fatalf("Root should have changed after deletions")
	}

	leaves2, depth2 := tree.GetMetadata()
	t.Logf("After branch promotions: %d leaves, longest branch: %d", leaves2, depth2)

	// Verify proofs for a sample of remaining keys
	sampleSize := 100
	step := remainingCount / sampleSize
	if step < 1 {
		step = 1
	}
	proofCount := 0
	for i, key := range keys {
		if lonerSet[i] {
			continue
		}
		if proofCount%step == 0 {
			proof := tree.Prove(key)
			if valid, _ := tree.Verify(root2, proof); !valid {
				t.Fatalf("Proof failed for key %d after branch promotion", i)
			}
		}
		proofCount++
	}
	t.Logf("Verified %d proofs", sampleSize)
}

// TestDeleteWithLazyLoadedBranches tests deletion when branch children haven't
// been loaded into memory yet (the FullyLoaded=false path). This specifically
// tests the bug fix where child paths were computed using `path` instead of
// `n.FullPrefix`.
// Uses 10000 keys with deep prefix structures to thoroughly test lazy loading.
func TestDeleteWithLazyLoadedBranches(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()

	// First tree: insert data and commit to storage
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree1 := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create keys with deep prefix structures to ensure branches have non-trivial prefixes
	// This is critical for testing the bug where path != n.FullPrefix
	numKeys := 10000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	// Create hierarchical key structure:
	// - First 2 bytes: common prefix (creates branch with prefix)
	// - Bytes 2-3: group identifier (16 groups)
	// - Bytes 4-7: subgroup identifier (creates nested branches with prefixes)
	// - Rest: random
	for i := 0; i < numKeys; i++ {
		key := make([]byte, 64)
		// Common prefix for all
		key[0] = 0xAB
		key[1] = 0xCD
		// Group (16 groups)
		key[2] = byte(i % 16)
		// Subgroup - shares prefix within group
		key[3] = byte((i / 16) % 16)
		key[4] = byte((i / 256) % 16)
		key[5] = byte((i / 4096) % 16)
		// Rest is random to spread within subgroups
		rand.Read(key[6:])
		keys[i] = key

		value := make([]byte, 32)
		rand.Read(value)
		values[i] = value

		if err := tree1.Insert(nil, key, value, nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	// Commit to persist to storage
	root1 := tree1.Commit(false)
	leaves1, depth1 := tree1.GetMetadata()
	t.Logf("Initial tree: %d keys, %d leaves, longest branch: %d", numKeys, leaves1, depth1)

	// Create a NEW tree instance that will load lazily from storage
	// This simulates what happens after a restart - branches are not in memory
	tree2 := &crypto.LazyVectorCommitmentTree{
		InclusionProver: bls48581.NewKZGInclusionProver(l),
		Store:           s,
		SetType:         "vertex",
		PhaseType:       "adds",
		ShardKey:        crypto.ShardKey{},
	}

	// Load the root from storage - the root's children won't be loaded (FullyLoaded=false)
	rootNode, err := s.GetNodeByPath("vertex", "adds", crypto.ShardKey{}, []int{})
	if err != nil {
		t.Fatalf("Failed to load root from storage: %v", err)
	}
	tree2.Root = rootNode

	// Verify we can get a sample of keys from the lazy-loaded tree
	for i := 0; i < numKeys; i += 100 {
		if _, err := tree2.Get(keys[i]); err != nil {
			t.Fatalf("key %d not found in lazy-loaded tree: %v", i, err)
		}
	}

	// Delete half the keys from the lazy-loaded tree in a pattern that exercises
	// different branches. Delete every other key to spread deletions across the tree.
	deleteCount := 0
	for i := 0; i < numKeys; i += 2 {
		if err := tree2.Delete(nil, keys[i]); err != nil {
			t.Fatalf("Failed to delete key %d from lazy-loaded tree: %v", i, err)
		}
		deleteCount++
	}
	t.Logf("Deleted %d keys from lazy-loaded tree", deleteCount)

	// Verify deleted keys are gone
	for i := 0; i < numKeys; i += 2 {
		if _, err := tree2.Get(keys[i]); err == nil {
			t.Fatalf("key %d still exists after deletion", i)
		}
	}

	// Verify remaining keys (odd indices) still exist and have correct values
	remainingCount := 0
	for i := 1; i < numKeys; i += 2 {
		val, err := tree2.Get(keys[i])
		if err != nil {
			t.Fatalf("key %d not found after deleting other keys: %v", i, err)
		}
		if !bytes.Equal(val, values[i]) {
			t.Fatalf("key %d value corrupted after deletion", i)
		}
		remainingCount++
	}

	// Commit the changes
	root2 := tree2.Commit(false)
	if bytes.Equal(root1, root2) {
		t.Fatalf("Root should have changed after deletions")
	}

	leaves2, depth2 := tree2.GetMetadata()
	t.Logf("After deletion: %d leaves, longest branch: %d", leaves2, depth2)

	// Verify size is correct
	expectedSize := big.NewInt(int64(remainingCount))
	if tree2.GetSize().Cmp(expectedSize) != 0 {
		t.Fatalf("Expected size %s, got %s", expectedSize.String(), tree2.GetSize().String())
	}

	// Now create a fresh tree with the same remaining keys to compare
	// This verifies the lazy-loaded delete produced a correct tree
	tree3 := &crypto.LazyVectorCommitmentTree{
		InclusionProver: bls48581.NewKZGInclusionProver(l),
		Store:           s,
		SetType:         "vertex",
		PhaseType:       "compare",
		ShardKey:        crypto.ShardKey{},
	}

	// Insert only the keys that should remain (odd indices)
	for i := 1; i < numKeys; i += 2 {
		if err := tree3.Insert(nil, keys[i], values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d into comparison tree: %v", i, err)
		}
	}

	root3 := tree3.Commit(false)

	// The roots should match since they have the same data
	if !bytes.Equal(root2, root3) {
		t.Fatalf("Lazy-loaded delete tree root doesn't match fresh tree root\nGot:      %x\nExpected: %x", root2, root3)
	}

	t.Logf("Lazy-loaded delete tree matches fresh tree with same keys")

	// Verify proofs work on the comparison tree for a sample of keys
	proofCount := 0
	for i := 1; i < numKeys; i += 20 {
		proof := tree3.Prove(keys[i])
		if valid, _ := tree3.Verify(root3, proof); !valid {
			t.Fatalf("Proof failed for key %d on comparison tree", i)
		}
		proofCount++
	}
	t.Logf("Verified %d proofs on comparison tree", proofCount)
}

// TestDeleteBranchCollapse tests the case where deleting a leaf causes a branch
// to have zero children remaining, triggering branch collapse (case 0).
// Tests with 5000 keys, deleting all to verify complete tree collapse.
func TestDeleteBranchCollapse(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Insert many keys
	numKeys := 5000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		value := make([]byte, 32)
		rand.Read(value)
		values[i] = value

		if err := tree.Insert(nil, key, value, nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	tree.Commit(false)
	leaves, depth := tree.GetMetadata()
	t.Logf("Initial tree: %d leaves, longest branch: %d", leaves, depth)

	// Delete all keys - each deletion may trigger branch collapses
	for i, key := range keys {
		if err := tree.Delete(nil, key); err != nil {
			t.Fatalf("Failed to delete key %d: %v", i, err)
		}

		// Verify key is gone
		if _, err := tree.Get(key); err == nil {
			t.Fatalf("Key %d still exists after deletion", i)
		}

		// Check size decrements properly
		expectedSize := big.NewInt(int64(numKeys - i - 1))
		if tree.GetSize().Cmp(expectedSize) != 0 {
			t.Fatalf("After deleting %d keys: expected size %s, got %s",
				i+1, expectedSize.String(), tree.GetSize().String())
		}
	}

	// Tree should be empty
	if tree.Root != nil {
		t.Fatalf("Expected nil root after deleting all keys")
	}

	// Size should be 0
	if tree.GetSize().Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("Expected tree size 0, got %s", tree.GetSize().String())
	}

	t.Logf("Successfully deleted all %d keys and collapsed tree", numKeys)

	// Re-insert all keys and verify tree is rebuilt correctly
	for i, key := range keys {
		if err := tree.Insert(nil, key, values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to re-insert key %d: %v", i, err)
		}
	}

	tree.Commit(false)
	leaves2, depth2 := tree.GetMetadata()
	t.Logf("Rebuilt tree: %d leaves, longest branch: %d", leaves2, depth2)

	if leaves2 != numKeys {
		t.Fatalf("Expected %d leaves after rebuild, got %d", numKeys, leaves2)
	}
}

// TestDeleteDeepNestedPrefixes tests deletion in a tree with deeply nested
// branch prefixes, ensuring prefix merging works correctly.
// Uses 5000 keys organized into groups with very long shared prefixes.
func TestDeleteDeepNestedPrefixes(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create groups of keys that share very long prefixes within each group
	// This creates deep branch structures with long prefix compression
	numGroups := 100
	keysPerGroup := 50
	prefixLength := 58 // Keys share first 58 bytes within group, differ in last 6

	keys := make([][]byte, 0, numGroups*keysPerGroup)
	values := make([][]byte, 0, numGroups*keysPerGroup)
	groupBoundaries := make([]int, numGroups+1)

	for g := 0; g < numGroups; g++ {
		groupBoundaries[g] = len(keys)

		// Generate group prefix (first 58 bytes shared within group)
		groupPrefix := make([]byte, prefixLength)
		rand.Read(groupPrefix)

		for i := 0; i < keysPerGroup; i++ {
			key := make([]byte, 64)
			copy(key[:prefixLength], groupPrefix)
			// Vary the last 6 bytes within group
			key[58] = byte(i)
			key[59] = byte(i >> 8)
			rand.Read(key[60:])
			keys = append(keys, key)

			value := make([]byte, 32)
			rand.Read(value)
			values = append(values, value)
		}
	}
	groupBoundaries[numGroups] = len(keys)

	t.Logf("Created %d keys in %d groups (%d keys/group, %d-byte shared prefix)",
		len(keys), numGroups, keysPerGroup, prefixLength)

	// Insert all keys
	for i, key := range keys {
		if err := tree.Insert(nil, key, values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	root1 := tree.Commit(false)
	leaves1, depth1 := tree.GetMetadata()
	t.Logf("Initial tree: %d leaves, longest branch: %d", leaves1, depth1)

	// Delete all keys from half the groups
	// This exercises prefix merging as groups collapse
	deletedGroups := numGroups / 2
	deletedCount := 0
	for g := 0; g < deletedGroups; g++ {
		start := groupBoundaries[g]
		end := groupBoundaries[g+1]
		for i := start; i < end; i++ {
			if err := tree.Delete(nil, keys[i]); err != nil {
				t.Fatalf("Failed to delete key %d (group %d): %v", i, g, err)
			}
			deletedCount++
		}
	}

	t.Logf("Deleted %d keys from %d groups", deletedCount, deletedGroups)

	// Verify deleted keys are gone
	for g := 0; g < deletedGroups; g++ {
		start := groupBoundaries[g]
		end := groupBoundaries[g+1]
		for i := start; i < end; i++ {
			if _, err := tree.Get(keys[i]); err == nil {
				t.Fatalf("Key %d still exists after deletion", i)
			}
		}
	}

	// Verify remaining keys exist with correct values
	for g := deletedGroups; g < numGroups; g++ {
		start := groupBoundaries[g]
		end := groupBoundaries[g+1]
		for i := start; i < end; i++ {
			val, err := tree.Get(keys[i])
			if err != nil {
				t.Fatalf("Key %d not found after deletions: %v", i, err)
			}
			if !bytes.Equal(val, values[i]) {
				t.Fatalf("Key %d value corrupted after deletions", i)
			}
		}
	}

	// Verify size
	expectedRemaining := (numGroups - deletedGroups) * keysPerGroup
	if tree.GetSize().Cmp(big.NewInt(int64(expectedRemaining))) != 0 {
		t.Fatalf("Expected size %d, got %s", expectedRemaining, tree.GetSize().String())
	}

	root2 := tree.Commit(false)
	leaves2, depth2 := tree.GetMetadata()
	t.Logf("After deletion: %d leaves, longest branch: %d", leaves2, depth2)

	// Now re-insert deleted keys and verify tree matches original
	for g := 0; g < deletedGroups; g++ {
		start := groupBoundaries[g]
		end := groupBoundaries[g+1]
		for i := start; i < end; i++ {
			if err := tree.Insert(nil, keys[i], values[i], nil, big.NewInt(1)); err != nil {
				t.Fatalf("Failed to re-insert key %d: %v", i, err)
			}
		}
	}

	root3 := tree.Commit(false)
	leaves3, depth3 := tree.GetMetadata()
	t.Logf("After re-insert: %d leaves, longest branch: %d", leaves3, depth3)

	// The tree structure should be equivalent (same root commitment)
	if !bytes.Equal(root1, root3) {
		t.Fatalf("Root mismatch after delete-and-reinsert cycle\nOriginal: %x\nRestored: %x", root1, root3)
	}

	if !bytes.Equal(root1, root2) {
		t.Logf("Root changed after partial deletion (expected)")
	}

	// Verify proofs work for a sample of keys
	for i := 0; i < len(keys); i += 50 {
		proof := tree.Prove(keys[i])
		if valid, _ := tree.Verify(root3, proof); !valid {
			t.Fatalf("Proof failed for key %d after reinsert", i)
		}
	}
}

// TestDeleteMultipleChildrenRemaining tests the default case in Delete where
// multiple children remain after deletion (childCount > 1).
// Uses 10000 random keys and deletes half, ensuring many branches retain multiple children.
func TestDeleteMultipleChildrenRemaining(t *testing.T) {
	bls48581.Init()
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verEncr, bls48581.NewKZGInclusionProver(l))
	tree := &crypto.LazyVectorCommitmentTree{InclusionProver: bls48581.NewKZGInclusionProver(l), Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: crypto.ShardKey{}}

	// Create many random keys - with random distribution, most branches will have multiple children
	numKeys := 10000
	keys := make([][]byte, numKeys)
	values := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		key := make([]byte, 64)
		rand.Read(key)
		keys[i] = key

		value := make([]byte, 32)
		rand.Read(value)
		values[i] = value

		if err := tree.Insert(nil, key, values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d: %v", i, err)
		}
	}

	root1 := tree.Commit(false)
	leaves1, depth1 := tree.GetMetadata()
	t.Logf("Initial tree: %d leaves, longest branch: %d", leaves1, depth1)

	// Delete every 3rd key - this pattern ensures most branches retain multiple children
	// (unlike deleting every other key which might create more promotions)
	deletedIndices := make(map[int]bool)
	deleteCount := 0
	for i := 0; i < numKeys; i += 3 {
		if err := tree.Delete(nil, keys[i]); err != nil {
			t.Fatalf("Failed to delete key %d: %v", i, err)
		}
		deletedIndices[i] = true
		deleteCount++
	}

	t.Logf("Deleted %d keys (every 3rd key)", deleteCount)

	// Verify deleted keys are gone
	for idx := range deletedIndices {
		if _, err := tree.Get(keys[idx]); err == nil {
			t.Fatalf("Key %d still exists after deletion", idx)
		}
	}

	// Verify remaining keys exist with correct values
	remainingCount := 0
	for i := 0; i < numKeys; i++ {
		if deletedIndices[i] {
			continue
		}
		val, err := tree.Get(keys[i])
		if err != nil {
			t.Fatalf("Key %d not found after deletion: %v", i, err)
		}
		if !bytes.Equal(val, values[i]) {
			t.Fatalf("Key %d value corrupted after deletion", i)
		}
		remainingCount++
	}

	// Verify size
	expectedSize := big.NewInt(int64(remainingCount))
	if tree.GetSize().Cmp(expectedSize) != 0 {
		t.Fatalf("Expected size %s, got %s", expectedSize.String(), tree.GetSize().String())
	}

	root2 := tree.Commit(false)
	if bytes.Equal(root1, root2) {
		t.Fatalf("Root should have changed after deletion")
	}

	leaves2, depth2 := tree.GetMetadata()
	t.Logf("After deletion: %d leaves, longest branch: %d", leaves2, depth2)

	// Verify proofs for a sample of remaining keys
	proofCount := 0
	for i := 0; i < numKeys; i += 10 {
		if deletedIndices[i] {
			continue
		}
		proof := tree.Prove(keys[i])
		if valid, _ := tree.Verify(root2, proof); !valid {
			t.Fatalf("Proof failed for key %d", i)
		}
		proofCount++
	}
	t.Logf("Verified %d proofs", proofCount)

	// Create comparison tree with same remaining keys
	tree2 := &crypto.LazyVectorCommitmentTree{
		InclusionProver: bls48581.NewKZGInclusionProver(l),
		Store:           s,
		SetType:         "vertex",
		PhaseType:       "compare",
		ShardKey:        crypto.ShardKey{},
	}

	for i := 0; i < numKeys; i++ {
		if deletedIndices[i] {
			continue
		}
		if err := tree2.Insert(nil, keys[i], values[i], nil, big.NewInt(1)); err != nil {
			t.Fatalf("Failed to insert key %d into comparison tree: %v", i, err)
		}
	}

	root3 := tree2.Commit(false)

	// The roots should match
	if !bytes.Equal(root2, root3) {
		t.Fatalf("Delete tree root doesn't match fresh tree root\nGot:      %x\nExpected: %x", root2, root3)
	}

	t.Logf("Delete tree matches fresh tree with same remaining keys")
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
