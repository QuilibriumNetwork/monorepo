package store

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

func setupTestInboxStore(t *testing.T) *PebbleInboxStore {
	logger, _ := zap.NewDevelopment()
	tempDB := NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	return NewPebbleInboxStore(tempDB, logger)
}

func createTestMessage(address []byte, timestamp uint64, content string) *protobufs.InboxMessage {
	return &protobufs.InboxMessage{
		Address:            address,
		Timestamp:          timestamp,
		EphemeralPublicKey: []byte("ephemeral_key"),
		Message:            []byte(content),
	}
}

func createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey []byte) *protobufs.HubAddInboxMessage {
	return &protobufs.HubAddInboxMessage{
		Address:        hubAddress,
		InboxPublicKey: inboxPubKey,
		HubPublicKey:   hubPubKey,
		HubSignature:   bytes.Repeat([]byte{0xAA}, 114), // Mock signature
		InboxSignature: bytes.Repeat([]byte{0xBB}, 114), // Mock signature
	}
}

func createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey []byte) *protobufs.HubDeleteInboxMessage {
	return &protobufs.HubDeleteInboxMessage{
		Address:        hubAddress,
		InboxPublicKey: inboxPubKey,
		HubPublicKey:   hubPubKey,
		HubSignature:   bytes.Repeat([]byte{0xCC}, 114), // Mock signature
		InboxSignature: bytes.Repeat([]byte{0xDD}, 114), // Mock signature
	}
}

func TestCRDTMessageOperations(t *testing.T) {
	store := setupTestInboxStore(t)

	address1 := bytes.Repeat([]byte{0xAA}, 32)
	address2 := bytes.Repeat([]byte{0xBB}, 32)
	timestamp1 := uint64(time.Now().UnixMilli())
	timestamp2 := timestamp1 + 1000

	msg1 := createTestMessage(address1, timestamp1, "Hello World 1")
	msg2 := createTestMessage(address1, timestamp2, "Hello World 2")
	msg3 := createTestMessage(address2, timestamp1, "Hello World 3")

	t.Run("AddMessage_GrowOnlySet", func(t *testing.T) {
		// Add messages to the grow-only set
		err := store.AddMessage(msg1)
		require.NoError(t, err)

		err = store.AddMessage(msg2)
		require.NoError(t, err)

		err = store.AddMessage(msg3)
		require.NoError(t, err)

		// Adding the same message again should not error (grow-only set)
		err = store.AddMessage(msg1)
		require.NoError(t, err)
	})

	t.Run("GetMessagesByFilter", func(t *testing.T) {
		filter1 := up2p.GetBloomFilterIndices(address1, 256, 3)
		filter2 := up2p.GetBloomFilterIndices(address2, 256, 3)

		// Get messages for address1's filter
		messages, err := store.GetMessagesByFilter([3]byte(filter1))
		require.NoError(t, err)

		// Should contain at least msg1 and msg2 (might have duplicates from previous test)
		assert.True(t, len(messages) >= 2)

		// Verify messages are sorted by timestamp
		for i := 1; i < len(messages); i++ {
			assert.True(t, messages[i-1].Timestamp <= messages[i].Timestamp)
		}

		// Get messages for address2's filter
		messages, err = store.GetMessagesByFilter([3]byte(filter2))
		require.NoError(t, err)
		assert.True(t, len(messages) >= 1)
	})

	t.Run("GetMessagesByAddress", func(t *testing.T) {
		filter1 := up2p.GetBloomFilterIndices(address1, 256, 3)

		messages, err := store.GetMessagesByAddress([3]byte(filter1), address1)
		require.NoError(t, err)

		// All messages should be for address1
		for _, msg := range messages {
			assert.Equal(t, address1, msg.Address)
		}
	})

	t.Run("GetMessagesByTimeRange", func(t *testing.T) {
		filter1 := up2p.GetBloomFilterIndices(address1, 256, 3)

		// Get messages in a specific time range
		messages, err := store.GetMessagesByTimeRange([3]byte(filter1), address1, timestamp1, timestamp2)
		require.NoError(t, err)

		// All messages should be within the time range
		for _, msg := range messages {
			assert.True(t, msg.Timestamp >= timestamp1)
			assert.True(t, msg.Timestamp <= timestamp2)
		}

		// Test open-ended range (toTimestamp = 0)
		messages, err = store.GetMessagesByTimeRange([3]byte(filter1), address1, timestamp1, 0)
		require.NoError(t, err)

		for _, msg := range messages {
			assert.True(t, msg.Timestamp >= timestamp1)
		}
	})
}

func TestCRDTMessageReaping(t *testing.T) {
	store := setupTestInboxStore(t)

	address := bytes.Repeat([]byte{0xCC}, 32)
	filter := up2p.GetBloomFilterIndices(address, 256, 3)

	// Add messages at different timestamps
	timestamps := []uint64{1000, 2000, 3000, 4000, 5000}
	for i, ts := range timestamps {
		msg := createTestMessage(address, ts, "Message "+string(rune('A'+i)))
		err := store.AddMessage(msg)
		require.NoError(t, err)
	}

	// Verify all messages exist
	messages, err := store.GetMessagesByFilter([3]byte(filter))
	require.NoError(t, err)
	assert.True(t, len(messages) >= 5)

	// Reap messages older than 3500 (should remove messages at 1000, 2000, 3000)
	err = store.ReapMessages([3]byte(filter), 3500)
	require.NoError(t, err)

	// Verify remaining messages
	messages, err = store.GetMessagesByFilter([3]byte(filter))
	require.NoError(t, err)

	// Should only have messages with timestamps >= 3500
	for _, msg := range messages {
		assert.True(t, msg.Timestamp >= 3500)
	}
}

func TestCRDTHubAssociations(t *testing.T) {
	store := setupTestInboxStore(t)

	hubAddress := bytes.Repeat([]byte{0xDD}, 32)
	inboxPubKey1 := bytes.Repeat([]byte{0x11}, 57) // Ed448 key size
	inboxPubKey2 := bytes.Repeat([]byte{0x22}, 57)
	hubPubKey := bytes.Repeat([]byte{0xAA}, 57)
	filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)

	t.Run("AddHubInboxAssociation_2PSet", func(t *testing.T) {
		// Add first association
		add1 := createTestHubAddMessage(hubAddress, inboxPubKey1, hubPubKey)
		err := store.AddHubInboxAssociation(add1)
		require.NoError(t, err)

		// Add second association
		add2 := createTestHubAddMessage(hubAddress, inboxPubKey2, hubPubKey)
		err = store.AddHubInboxAssociation(add2)
		require.NoError(t, err)

		// Adding the same association again should not error (2P-Set allows re-adds)
		err = store.AddHubInboxAssociation(add1)
		require.NoError(t, err)
	})

	t.Run("GetHubAssociations_EffectiveState", func(t *testing.T) {
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)

		// Should have 2 effective associations
		assert.Len(t, response.Adds, 2)
		assert.Len(t, response.Deletes, 0)

		// Verify the associations
		foundKeys := make(map[string]bool)
		for _, add := range response.Adds {
			key := string(add.InboxPublicKey)
			foundKeys[key] = true
		}
		assert.True(t, foundKeys[string(inboxPubKey1)])
		assert.True(t, foundKeys[string(inboxPubKey2)])
	})

	t.Run("DeleteHubInboxAssociation_2PSet", func(t *testing.T) {
		// Delete first association
		delete1 := createTestHubDeleteMessage(hubAddress, inboxPubKey1, hubPubKey)
		err := store.DeleteHubInboxAssociation(delete1)
		require.NoError(t, err)

		// Verify effective state
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)

		// Should have 1 effective add and 1 delete
		assert.Len(t, response.Adds, 1)
		assert.Len(t, response.Deletes, 1)

		// The remaining add should be for inboxPubKey2
		assert.Equal(t, inboxPubKey2, response.Adds[0].InboxPublicKey)
		assert.Equal(t, inboxPubKey1, response.Deletes[0].InboxPublicKey)
	})

	t.Run("GetHubAddHistory_CRDTSync", func(t *testing.T) {
		// Get all add operations (never deleted)
		adds, err := store.GetHubAddHistory([3]byte(filter), hubAddress)
		require.NoError(t, err)

		// Should have all add operations ever performed
		assert.True(t, len(adds) >= 2) // At least the original 2 adds

		// Verify operations are preserved
		foundKeys := make(map[string]int)
		for _, add := range adds {
			key := string(add.InboxPublicKey)
			foundKeys[key]++
		}
		assert.True(t, foundKeys[string(inboxPubKey1)] >= 1)
		assert.True(t, foundKeys[string(inboxPubKey2)] >= 1)
	})

	t.Run("GetHubDeleteHistory_CRDTSync", func(t *testing.T) {
		// Get all delete operations (never deleted)
		deletes, err := store.GetHubDeleteHistory([3]byte(filter), hubAddress)
		require.NoError(t, err)

		// Should have 1 delete operation
		assert.Len(t, deletes, 1)
		assert.Equal(t, inboxPubKey1, deletes[0].InboxPublicKey)
	})

	t.Run("2PSet_Idempotency", func(t *testing.T) {
		// Re-add a deleted association
		add1Again := createTestHubAddMessage(hubAddress, inboxPubKey1, hubPubKey)
		err := store.AddHubInboxAssociation(add1Again)
		require.NoError(t, err)

		// It should still be considered deleted (2P-Set semantics)
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)

		// Should still have 1 effective add and 1 delete
		assert.Len(t, response.Adds, 1)
		assert.Len(t, response.Deletes, 1)
		assert.Equal(t, inboxPubKey2, response.Adds[0].InboxPublicKey)

		// Re-delete the same association (should be idempotent)
		delete1Again := createTestHubDeleteMessage(hubAddress, inboxPubKey1, hubPubKey)
		err = store.DeleteHubInboxAssociation(delete1Again)
		require.NoError(t, err)

		// State should remain the same
		response, err = store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)
		assert.Len(t, response.Adds, 1)
		assert.Len(t, response.Deletes, 1)
	})
}

func TestCRDTSynchronization(t *testing.T) {
	store := setupTestInboxStore(t)

	// Set up test data
	address1 := bytes.Repeat([]byte{0xAA}, 32)
	address2 := bytes.Repeat([]byte{0xBB}, 32)
	filter1 := up2p.GetBloomFilterIndices(address1, 256, 3)
	filter2 := up2p.GetBloomFilterIndices(address2, 256, 3)

	// Add messages
	msg1 := createTestMessage(address1, 1000, "Message 1")
	msg2 := createTestMessage(address2, 2000, "Message 2")

	err := store.AddMessage(msg1)
	require.NoError(t, err)
	err = store.AddMessage(msg2)
	require.NoError(t, err)

	// Add hub associations
	hubAddress := bytes.Repeat([]byte{0xCC}, 32)
	inboxPubKey := bytes.Repeat([]byte{0x11}, 57)
	hubPubKey := bytes.Repeat([]byte{0xAA}, 57)

	add := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
	err = store.AddHubInboxAssociation(add)
	require.NoError(t, err)

	t.Run("GetAllMessagesCRDT", func(t *testing.T) {
		filters := [][3]byte{[3]byte(filter1), [3]byte(filter2)}
		messages, err := store.GetAllMessagesCRDT(filters)
		require.NoError(t, err)

		assert.True(t, len(messages) >= 2)

		// Verify we have messages from both filters
		foundAddresses := make(map[string]bool)
		for _, msg := range messages {
			foundAddresses[string(msg.Address)] = true
		}
		assert.True(t, foundAddresses[string(address1)])
		assert.True(t, foundAddresses[string(address2)])
	})

	t.Run("GetAllHubAssociations", func(t *testing.T) {
		hubFilter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)
		filters := [][3]byte{[3]byte(hubFilter)}

		hubs, err := store.GetAllHubAssociations(filters)
		require.NoError(t, err)

		assert.True(t, len(hubs) >= 1)

		// Find our hub
		var foundHub *protobufs.HubResponse
		for _, hub := range hubs {
			if len(hub.Adds) > 0 && bytes.Equal(hub.Adds[0].Address, hubAddress) {
				foundHub = hub
				break
			}
		}

		require.NotNil(t, foundHub)
		assert.Len(t, foundHub.Adds, 1)
		assert.Equal(t, inboxPubKey, foundHub.Adds[0].InboxPublicKey)
	})

	t.Run("GetAllHubsCRDT", func(t *testing.T) {
		hubFilter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)
		filters := [][3]byte{[3]byte(hubFilter)}

		hubs, err := store.GetAllHubsCRDT(filters)
		require.NoError(t, err)

		assert.True(t, len(hubs) >= 1)
	})
}

func TestCRDTMaterializedViews(t *testing.T) {
	store := setupTestInboxStore(t)

	hubAddress := bytes.Repeat([]byte{0xEE}, 32)
	inboxPubKey1 := bytes.Repeat([]byte{0x11}, 57)
	inboxPubKey2 := bytes.Repeat([]byte{0x22}, 57)
	hubPubKey := bytes.Repeat([]byte{0xAA}, 57)
	filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)

	t.Run("MaterializedView_UpdatesOnAdd", func(t *testing.T) {
		// Add association
		add1 := createTestHubAddMessage(hubAddress, inboxPubKey1, hubPubKey)
		err := store.AddHubInboxAssociation(add1)
		require.NoError(t, err)

		// Materialized view should be updated
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)
		assert.Len(t, response.Adds, 1)
	})

	t.Run("MaterializedView_UpdatesOnDelete", func(t *testing.T) {
		// Add another association
		add2 := createTestHubAddMessage(hubAddress, inboxPubKey2, hubPubKey)
		err := store.AddHubInboxAssociation(add2)
		require.NoError(t, err)

		// Delete first association
		delete1 := createTestHubDeleteMessage(hubAddress, inboxPubKey1, hubPubKey)
		err = store.DeleteHubInboxAssociation(delete1)
		require.NoError(t, err)

		// Materialized view should reflect the deletion
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)
		assert.Len(t, response.Adds, 1)
		assert.Len(t, response.Deletes, 1)
		assert.Equal(t, inboxPubKey2, response.Adds[0].InboxPublicKey)
		assert.Equal(t, inboxPubKey1, response.Deletes[0].InboxPublicKey)
	})
}

func TestCRDTKeyConstruction(t *testing.T) {
	address := bytes.Repeat([]byte{0xAA}, 32)
	timestamp := uint64(1234567890)
	msg := createTestMessage(address, timestamp, "Test message")

	t.Run("messageKey", func(t *testing.T) {
		key := messageKey(msg)
		// Verify key structure:
		// [INBOX][INBOX_MESSAGE][filter (3)][timestamp (8)][address_hash (32)][message_hash (32)]
		assert.Equal(t, byte(INBOX), key[0])
		assert.Equal(t, byte(INBOX_MESSAGE), key[1])

		// Extract filter (next 3 bytes starting at index 2)
		filter := up2p.GetBloomFilterIndices(address, 256, 3)
		assert.Equal(t, filter, key[2:5])

		// Verify key is deterministic
		key2 := messageKey(msg)
		assert.Equal(t, key, key2)
	})

	t.Run("HubAddKey", func(t *testing.T) {
		hubAddress := bytes.Repeat([]byte{0xBB}, 32)
		inboxPubKey := bytes.Repeat([]byte{0x11}, 57)
		hubPubKey := bytes.Repeat([]byte{0x22}, 57)

		add := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		key := hubAddKey(add)

		// Verify key structure
		assert.Equal(t, byte(INBOX), key[0])
		assert.Equal(t, byte(INBOX_HUB_ADDS), key[1])

		// Verify key is deterministic
		key2 := hubAddKey(add)
		assert.Equal(t, key, key2)
	})

	t.Run("HubDeleteKey", func(t *testing.T) {
		hubAddress := bytes.Repeat([]byte{0xBB}, 32)
		inboxPubKey := bytes.Repeat([]byte{0x11}, 57)
		hubPubKey := bytes.Repeat([]byte{0x22}, 57)

		delete := createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey)
		key := hubDeleteKey(delete)

		// Verify key structure
		assert.Equal(t, byte(INBOX), key[0])
		assert.Equal(t, byte(INBOX_HUB_DELETES), key[1])

		// Verify key is deterministic
		key2 := hubDeleteKey(delete)
		assert.Equal(t, key, key2)
	})
}

func TestCRDTErrorCases(t *testing.T) {
	store := setupTestInboxStore(t)

	t.Run("AddMessage_NilMessage", func(t *testing.T) {
		err := store.AddMessage(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "message is nil")
	})

	t.Run("AddHubInboxAssociation_NilMessage", func(t *testing.T) {
		err := store.AddHubInboxAssociation(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "add message is nil")
	})

	t.Run("DeleteHubInboxAssociation_NilMessage", func(t *testing.T) {
		err := store.DeleteHubInboxAssociation(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delete message is nil")
	})

	t.Run("GetHubAssociations_NonExistentHub", func(t *testing.T) {
		nonExistentHub := bytes.Repeat([]byte{0xFF}, 32)
		filter := up2p.GetBloomFilterIndices(nonExistentHub, 256, 3)

		response, err := store.GetHubAssociations([3]byte(filter), nonExistentHub)
		require.NoError(t, err)

		// Should return empty response, not error
		assert.Len(t, response.Adds, 0)
		assert.Len(t, response.Deletes, 0)
	})
}

func TestCRDTConcurrentScenarios(t *testing.T) {
	store := setupTestInboxStore(t)

	hubAddress := bytes.Repeat([]byte{0xFF}, 32)
	inboxPubKey := bytes.Repeat([]byte{0x11}, 57)
	hubPubKey := bytes.Repeat([]byte{0x22}, 57)
	filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)

	t.Run("AddDeleteAdd_Sequence", func(t *testing.T) {
		// Simulate concurrent operations that could arrive in different orders

		// Add
		add1 := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		err := store.AddHubInboxAssociation(add1)
		require.NoError(t, err)

		// Delete
		delete1 := createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey)
		err = store.DeleteHubInboxAssociation(delete1)
		require.NoError(t, err)

		// Add again (should not revert the delete in 2P-Set)
		add2 := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		err = store.AddHubInboxAssociation(add2)
		require.NoError(t, err)

		// Verify final state: delete wins in 2P-Set
		response, err := store.GetHubAssociations([3]byte(filter), hubAddress)
		require.NoError(t, err)
		assert.Len(t, response.Adds, 0)    // No effective adds
		assert.Len(t, response.Deletes, 1) // One delete
	})

	t.Run("MultipleAdds_SameAssociation", func(t *testing.T) {
		// Different hub for this test
		hubAddress2 := bytes.Repeat([]byte{0xEE}, 32)
		filter2 := up2p.GetBloomFilterIndices(hubAddress2, 256, 3)

		// Add the same association multiple times
		for i := 0; i < 5; i++ {
			add := createTestHubAddMessage(hubAddress2, inboxPubKey, hubPubKey)
			err := store.AddHubInboxAssociation(add)
			require.NoError(t, err)
		}

		// Should still have only one effective association
		response, err := store.GetHubAssociations([3]byte(filter2), hubAddress2)
		require.NoError(t, err)
		assert.Len(t, response.Adds, 1)
		assert.Len(t, response.Deletes, 0)

		// History should remain idempotent
		adds, err := store.GetHubAddHistory([3]byte(filter2), hubAddress2)
		require.NoError(t, err)
		assert.True(t, len(adds) == 1)
	})
}

func BenchmarkCRDTOperations(b *testing.B) {
	logger, _ := zap.NewDevelopment()
	tempDB := NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	store := NewPebbleInboxStore(tempDB, logger)

	address := bytes.Repeat([]byte{0xAA}, 32)

	b.Run("AddMessage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			msg := createTestMessage(address, uint64(i), "Benchmark message")
			err := store.AddMessage(msg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GetMessagesByFilter", func(b *testing.B) {
		// Pre-populate with some messages
		for i := 0; i < 1000; i++ {
			msg := createTestMessage(address, uint64(i), "Benchmark message")
			_ = store.AddMessage(msg)
		}

		filter := up2p.GetBloomFilterIndices(address, 256, 3)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := store.GetMessagesByFilter([3]byte(filter))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("AddHubInboxAssociation", func(b *testing.B) {
		hubAddress := bytes.Repeat([]byte{0xBB}, 32)
		hubPubKey := bytes.Repeat([]byte{0xAA}, 57)

		for i := 0; i < b.N; i++ {
			inboxPubKey := sha256.Sum256([]byte("inbox" + string(rune(i))))
			add := createTestHubAddMessage(hubAddress, inboxPubKey[:], hubPubKey)
			err := store.AddHubInboxAssociation(add)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GetHubAssociations", func(b *testing.B) {
		hubAddress := bytes.Repeat([]byte{0xCC}, 32)
		hubPubKey := bytes.Repeat([]byte{0xBB}, 57)
		filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)

		// Pre-populate with some associations
		for i := 0; i < 100; i++ {
			inboxPubKey := sha256.Sum256([]byte("inbox" + string(rune(i))))
			add := createTestHubAddMessage(hubAddress, inboxPubKey[:], hubPubKey)
			_ = store.AddHubInboxAssociation(add)
		}

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := store.GetHubAssociations([3]byte(filter), hubAddress)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
