package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

func TestMDBXDB(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "mdbx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create DB config
	dbConfig := &config.DBConfig{
		Path: tempDir,
	}

	// Create DB instance
	db := NewMDBXDB(dbConfig)
	defer db.Close()

	// Test basic operations
	t.Run("BasicOperations", func(t *testing.T) {
		// Test Set and Get
		key := []byte("test-key")
		value := []byte("test-value")

		if err := db.Set(key, value); err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}

		result, closer, err := db.Get(key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		defer closer.Close()

		if !bytes.Equal(result, value) {
			t.Errorf("Expected %v, got %v", value, result)
		}

		// Test Delete
		if err := db.Delete(key); err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		_, _, err = db.Get(key)
		if err == nil {
			t.Errorf("Expected error for deleted key")
		}
	})

	// Test transactions
	t.Run("Transactions", func(t *testing.T) {
		// Create a non-indexed transaction
		tx := db.NewTransaction()

		// Set some values in the transaction
		key1 := []byte("tx-key-1")
		value1 := []byte("tx-value-1")
		key2 := []byte("tx-key-2")
		value2 := []byte("tx-value-2")

		if err := tx.Set(key1, value1); err != nil {
			t.Fatalf("Failed to set value in transaction: %v", err)
		}
		if err := tx.Set(key2, value2); err != nil {
			t.Fatalf("Failed to set value in transaction: %v", err)
		}

		// Values should not be visible outside the transaction yet
		_, _, err := db.Get(key1)
		if err == nil {
			t.Errorf("Key should not be visible outside transaction before commit")
		}

		// Values should be visible inside the transaction
		result, closer, err := tx.Get(key1)
		if err != nil {
			t.Fatalf("Failed to get value from transaction: %v", err)
		}
		defer closer.Close()
		if !bytes.Equal(result, value1) {
			t.Errorf("Expected %v, got %v", value1, result)
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			t.Fatalf("Failed to commit transaction: %v", err)
		}

		// Values should now be visible outside the transaction
		result, closer, err = db.Get(key1)
		if err != nil {
			t.Fatalf("Failed to get value after commit: %v", err)
		}
		defer closer.Close()
		if !bytes.Equal(result, value1) {
			t.Errorf("Expected %v, got %v", value1, result)
		}

		// Test transaction abort
		tx = db.NewBatch(false)
		abortKey := []byte("abort-key")
		abortValue := []byte("abort-value")

		if err := tx.Set(abortKey, abortValue); err != nil {
			t.Fatalf("Failed to set value in transaction: %v", err)
		}

		if err := tx.Abort(); err != nil {
			t.Fatalf("Failed to abort transaction: %v", err)
		}

		// Value should not be visible after abort
		_, _, err = db.Get(abortKey)
		if err == nil {
			t.Errorf("Key should not be visible after transaction abort")
		}

		// Test transaction DeleteRange
		tx = db.NewTransaction()

		// Set up some keys for the range delete
		for i := 1; i <= 5; i++ {
			key := []byte(filepath.Join("tx-range", "key", "prefix", "key-"+string(rune('0'+i))))
			value := []byte("tx-value-" + string(rune('0'+i)))
			if err := tx.Set(key, value); err != nil {
				t.Fatalf("Failed to set value in transaction: %v", err)
			}
		}

		// Delete a range within the transaction
		startKey := []byte(filepath.Join("tx-range", "key", "prefix", "key-2"))
		endKey := []byte(filepath.Join("tx-range", "key", "prefix", "key-4"))
		fmt.Println("---")
		if err := tx.DeleteRange(startKey, endKey); err != nil {
			t.Fatalf("Failed to delete range in transaction: %v", err)
		}
		fmt.Println("---")

		// Check that keys in the range are deleted within the transaction
		for i := 2; i < 4; i++ {
			key := []byte(filepath.Join("tx-range", "key", "prefix", "key-"+string(rune('0'+i))))
			_, _, err := tx.Get(key)
			if err == nil {
				t.Errorf("Key %s should be deleted in transaction", key)
			}
		}

		// Check that keys outside the range still exist within the transaction
		txKey1 := []byte(filepath.Join("tx-range", "key", "prefix", "key-1"))
		txResult, txCloser, txErr := tx.Get(txKey1)
		if txErr != nil {
			t.Errorf("Key %s should still exist in transaction: %v", txKey1, txErr)
		} else {
			defer txCloser.Close()
			if !bytes.Equal(txResult, []byte("tx-value-1")) {
				t.Errorf("Expected %v, got %v", []byte("tx-value-1"), txResult)
			}
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			t.Fatalf("Failed to commit transaction: %v", err)
		}

		// Verify the changes are visible outside the transaction
		for i := 2; i < 4; i++ {
			key := []byte(filepath.Join("tx-range", "key", "prefix", "key-"+string(rune('0'+i))))
			_, _, err := db.Get(key)
			if err == nil {
				t.Errorf("Key %s should be deleted after commit", key)
			}
		}

		txKey5 := []byte(filepath.Join("tx-range", "key", "prefix", "key-5"))
		txResult2, txCloser2, txErr2 := db.Get(txKey5)
		if txErr2 != nil {
			t.Errorf("Key %s should still exist after commit: %v", txKey5, txErr2)
		} else {
			defer txCloser2.Close()
			if !bytes.Equal(txResult2, []byte("tx-value-5")) {
				t.Errorf("Expected %v, got %v", []byte("tx-value-5"), txResult2)
			}
		}
	})

	// Test iterators
	t.Run("Iterators", func(t *testing.T) {
		// Insert some test data
		testData := map[string]string{
			"iter-key-1": "iter-value-1",
			"iter-key-2": "iter-value-2",
			"iter-key-3": "iter-value-3",
			"iter-key-4": "iter-value-4",
			"iter-key-5": "iter-value-5",
		}

		for k, v := range testData {
			if err := db.Set([]byte(k), []byte(v)); err != nil {
				t.Fatalf("Failed to set value: %v", err)
			}
		}

		// Test full range iterator
		iter, err := db.NewIter([]byte("iter-key-1"), []byte("iter-key-6"))
		if err != nil {
			t.Fatalf("Failed to create iterator: %v", err)
		}
		defer iter.Close()

		count := 0
		for iter.First(); iter.Valid(); iter.Next() {
			key := string(iter.Key())
			value := string(iter.Value())
			expectedValue, ok := testData[key]
			if !ok {
				t.Errorf("Unexpected key: %s", key)
			} else if expectedValue != value {
				t.Errorf("Expected value %s for key %s, got %s", expectedValue, key, value)
			}
			count++
		}

		if count != len(testData) {
			t.Errorf("Expected %d items, got %d", len(testData), count)
		}

		// Test partial range iterator
		iter, err = db.NewIter([]byte("iter-key-2"), []byte("iter-key-4"))
		if err != nil {
			t.Fatalf("Failed to create iterator: %v", err)
		}
		defer iter.Close()

		expectedKeys := []string{"iter-key-2", "iter-key-3"}
		count = 0
		for iter.First(); iter.Valid(); iter.Next() {
			key := string(iter.Key())
			if count >= len(expectedKeys) || key != expectedKeys[count] {
				t.Errorf("Expected key %s, got %s", expectedKeys[count], key)
			}
			count++
		}

		if count != len(expectedKeys) {
			t.Errorf("Expected %d items in range, got %d", len(expectedKeys), count)
		}

		// Test Last and Prev
		iter, err = db.NewIter([]byte("iter-key-1"), []byte("iter-key-6"))
		if err != nil {
			t.Fatalf("Failed to create iterator: %v", err)
		}
		defer iter.Close()

		if !iter.Last() {
			t.Errorf("Last() should return true")
		}

		if string(iter.Key()) != "iter-key-5" {
			t.Errorf("Expected last key to be iter-key-5, got %s", string(iter.Key()))
		}

		count = 0
		expectedReverseKeys := []string{"iter-key-5", "iter-key-4", "iter-key-3", "iter-key-2", "iter-key-1"}
		for ; iter.Valid(); iter.Prev() {
			key := string(iter.Key())
			if count >= len(expectedReverseKeys) || key != expectedReverseKeys[count] {
				t.Errorf("Expected key %s, got %s", expectedReverseKeys[count], key)
			}
			count++
		}

		if count != len(expectedReverseKeys) {
			t.Errorf("Expected %d items in reverse range, got %d", len(expectedReverseKeys), count)
		}

		// Test SeekLT
		iter, err = db.NewIter([]byte("iter-key-1"), []byte("iter-key-6"))
		if err != nil {
			t.Fatalf("Failed to create iterator: %v", err)
		}
		defer iter.Close()

		if !iter.SeekLT([]byte("iter-key-4")) {
			t.Errorf("SeekLT() should return true")
		}

		if string(iter.Key()) != "iter-key-3" {
			t.Errorf("Expected key after SeekLT to be iter-key-3, got %s", string(iter.Key()))
		}

		// Test SeekLT with a key that doesn't exist but is in range
		if !iter.SeekLT([]byte("iter-key-3.5")) {
			t.Errorf("SeekLT() should return true")
		}

		if string(iter.Key()) != "iter-key-3" {
			t.Errorf("Expected key after SeekLT to be iter-key-3, got %s", string(iter.Key()))
		}
	})

	// Test DeleteRange
	t.Run("DeleteRange", func(t *testing.T) {
		// Insert some test data
		for i := 1; i <= 5; i++ {
			key := []byte(filepath.Join("range", "key", "prefix", "key-"+string(rune('0'+i))))
			value := []byte("value-" + string(rune('0'+i)))
			if err := db.Set(key, value); err != nil {
				t.Fatalf("Failed to set value: %v", err)
			}
		}

		// Delete a range of keys
		startKey := []byte(filepath.Join("range", "key", "prefix", "key-2"))
		endKey := []byte(filepath.Join("range", "key", "prefix", "key-4"))
		if err := db.DeleteRange(startKey, endKey); err != nil {
			t.Fatalf("Failed to delete range: %v", err)
		}

		// Check that keys in the range are deleted
		for i := 2; i < 4; i++ {
			key := []byte(filepath.Join("range", "key", "prefix", "key-"+string(rune('0'+i))))
			_, _, err := db.Get(key)
			if err == nil {
				t.Errorf("Key %s should be deleted", key)
			}
		}

		// Check that keys outside the range still exist
		key1 := []byte(filepath.Join("range", "key", "prefix", "key-1"))
		result, closer, err := db.Get(key1)
		if err != nil {
			t.Errorf("Key %s should still exist: %v", key1, err)
		} else {
			defer closer.Close()
			if !bytes.Equal(result, []byte("value-1")) {
				t.Errorf("Expected %v, got %v", []byte("value-1"), result)
			}
		}

		key5 := []byte(filepath.Join("range", "key", "prefix", "key-5"))
		result, closer, err = db.Get(key5)
		if err != nil {
			t.Errorf("Key %s should still exist: %v", key5, err)
		} else {
			defer closer.Close()
			if !bytes.Equal(result, []byte("value-5")) {
				t.Errorf("Expected %v, got %v", []byte("value-5"), result)
			}
		}
	})

	t.Run("Batch", func(t *testing.T) {
		// Insert some test data
		for i := 1; i <= 5; i++ {
			key := []byte("key-" + string(rune('0'+i)))
			value := []byte("value-" + string(rune('0'+i)))
			if err := db.Set(key, value); err != nil {
				t.Fatalf("Failed to set value: %v", err)
			}
		}

		batch := db.NewBatch(false)
		batch.Set([]byte("key-1"), []byte("potato"))
		batch.Set([]byte("key-5"), []byte("tomato"))
		batch.Delete([]byte("key-2"))
		batch.DeleteRange([]byte("key-3"), []byte("key-5"))
		if batch.Commit() != nil {
			t.Errorf("commit failed")
			t.Fail()
		}

		for i := 1; i <= 5; i++ {
			key := []byte("key-" + string(rune('0'+i)))
			val, _, err := db.Get(key)
			if err != nil && !errors.Is(err, pebble.ErrNotFound) {
				t.Fatalf("Failed to get value: %v", err)
				t.Fail()
			}
			switch i {
			case 1:
				if !bytes.Equal(val, []byte("potato")) {
					t.Errorf("wrong key-1")
				}
			case 5:
				if !bytes.Equal(val, []byte("tomato")) {
					t.Errorf("wrong key-5")
				}
			default:
				if err != nil && errors.Is(err, ErrNotFound) {
					t.Errorf("key-%d should be deleted, but we got (%s)", i, val)
				}
			}
		}
	})

	t.Run("OpenDB", func(t *testing.T) {
		names := []string{DEFAULT_TABLE, "table1", "table2"}
		var dbs []MDBXDB
		for _, name := range names {
			newdb, err := db.OpenDB(name)
			if err != nil {
				t.Errorf("error opening db: %v", err)
				t.Fail()
			}
			dbs = append(dbs, *newdb)
		}
		for j, currentDB := range dbs {
			for i := 1; i <= 5; i++ {
				name := names[j]
				key := []byte("key-" + string(rune('0'+i)))
				value := []byte(name + string(rune('0'+i)))
				if err := currentDB.Set(key, value); err != nil {
					t.Fatalf("Failed to set value: %v", err)
				}
			}
		}

		// Check that values under the same key on different dbs were not overwritten
		for j, currentDB := range dbs {
			for i := 1; i <= 5; i++ {
				name := names[j]
				key := []byte("key-" + string(rune('0'+i)))
				expectedValue := []byte(name + string(rune('0'+i)))
				value, _, err := currentDB.Get(key)
				if !bytes.Equal(value, expectedValue) {
					t.Errorf("%s was overwritten by %s on db %s", expectedValue, value, name)
					t.Fail()
				}
				if err != nil {
					t.Errorf("Error getting value: %v", err)
				}
			}
		}

	})

}
