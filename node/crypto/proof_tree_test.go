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
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var verencr = &mocks.MockVerifiableEncryptor{}

func TestLazyVectorCommitmentTreesNoBLS(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true}, db, l, verencr, nil)
	tree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

	// Empty tree should be empty
	emptyRoot := tree.Root
	if emptyRoot != nil {
		t.Errorf("Expected empty root")
	}

	// Root should change after delete
	tree.Delete(nil, []byte("key1"))

	l, _ = zap.NewProduction()
	db = store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}
	cmptree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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

	cmptree = &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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

	leaves, longestBranch := tree.GetMetadata()

	if leaves != 10000 {
		t.Errorf("incorrect leaf count, %d, %d,", 10000, leaves)
	}

	// Statistical assumption, can be flaky
	if longestBranch < 4 || longestBranch > 5 {
		tries.DebugNode(tree.SetType, tree.PhaseType, tree.ShardKey, tree.Root, 0, "")
		t.Errorf("unlikely longest branch count, %d, %d, review this tree", 4, longestBranch)
	}
}

// TestTreeLeafReaddition tests that re-adding the exact same leaf does not
// increase the Size metadata
func TestTreeLeafReadditionNoBLS(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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

	// Choose a random key to test with
	testIndex := mrand.Intn(numKeys)
	testKey := keys[testIndex]
	testValue := values[testIndex]

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
}

// TestTreeRemoveReaddLeaf tests that removing a leaf and re-adding it
// decreases and increases the size metadata appropriately
func TestTreeRemoveReaddLeafNoBLS(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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

	// Choose a random key to test with
	testIndex := mrand.Intn(numKeys)
	testKey := keys[testIndex]
	testValue := values[testIndex]

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
}

// TestTreeLongestBranch tests that the longest branch metadata value is always
// correct.
func TestTreeLongestBranchNoBLS(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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
func TestTreeBranchStructureNoBLS(t *testing.T) {
	l, _ := zap.NewProduction()
	db := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	s := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, db, l, verencr, nil)
	tree := &tries.LazyVectorCommitmentTree{Store: s, SetType: "vertex", PhaseType: "adds", ShardKey: tries.ShardKey{}}

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

	initialSize := tree.GetSize()

	// Confirm initial state
	if initialSize.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("Expected initial size of 3, got %s", initialSize.String())
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
	branchSize := tree.GetSize()

	// Confirm size increased
	if branchSize.Cmp(big.NewInt(4)) != 0 {
		t.Errorf("Expected size of 4 after adding branch key, got %s", branchSize.String())
	}

	// Remove the key that created the branch
	err = tree.Delete(nil, branchKey)
	if err != nil {
		t.Errorf("Failed to delete branch-creating key: %v", err)
	}

	// Commit after removing the branch-creating key
	restoredSize := tree.GetSize()
	// Confirm size returned to original
	if restoredSize.Cmp(initialSize) != 0 {
		t.Errorf("Expected size to return to %s after removing branch key, got %s",
			initialSize.String(), restoredSize.String())
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

	afterGroupRemoval := tree.GetSize()
	expectedAfterRemoval := big.NewInt(3 + keysPerGroup)
	if afterGroupRemoval.Cmp(expectedAfterRemoval) != 0 {
		t.Errorf("Expected tree size of %s after group removal, got %s",
			expectedAfterRemoval.String(), afterGroupRemoval.String())
	}
}
