package dispatch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tchannel "source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

var _ tchannel.EncryptedChannel = (*mockEncryptedChannel)(nil)

type mockEncryptedChannel struct{}

// DecryptTwoPartyMessage implements channel.EncryptedChannel.
func (m *mockEncryptedChannel) DecryptTwoPartyMessage(
	ratchetState string,
	envelope *tchannel.P2PChannelEnvelope,
) (newRatchetState string, message []byte, err error) {
	// We just pass through the message for testing
	return "", envelope.MessageBody.Ciphertext, nil
}

// EncryptTwoPartyMessage implements channel.EncryptedChannel.
func (m *mockEncryptedChannel) EncryptTwoPartyMessage(
	ratchetState string,
	message []byte,
) (newRatchetState string, envelope *tchannel.P2PChannelEnvelope, err error) {
	return "", &tchannel.P2PChannelEnvelope{MessageBody: tchannel.MessageCiphertext{Ciphertext: message}}, nil
}

// EstablishTwoPartyChannel implements channel.EncryptedChannel.
func (m *mockEncryptedChannel) EstablishTwoPartyChannel(
	isSender bool,
	sendingIdentityPrivateKey []byte,
	sendingSignedPrePrivateKey []byte,
	receivingIdentityKey []byte,
	receivingSignedPreKey []byte,
) (string, error) {
	return "", nil
}

func setupTestService(t *testing.T) (*DispatchService, *mocks.MockInboxStore, *mocks.MockKeyManager, *mocks.MockPubSub) {
	logger, _ := zap.NewDevelopment()
	mockStore := new(mocks.MockInboxStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockPubSub := new(mocks.MockPubSub)

	mockPubSub.On("GetPeerID").Return(make([]byte, 32))

	// Setup key manager mocks
	mockKeyManager.On("GetAgreementKey", mock.Anything).Return(nil, nil)
	mockKeyManager.On("GetRawKey", mock.Anything).Return(&keys.Key{
		Id:         "",
		Type:       crypto.KeyTypeX448,
		PrivateKey: make([]byte, 56),
		PublicKey:  make([]byte, 57),
	}, nil)

	service := NewDispatchService(
		mockStore,
		logger,
		mockKeyManager,
		mockPubSub,
	)

	// Set some default responsible filters
	service.SetResponsibleFilters([][3]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	})

	return service, mockStore, mockKeyManager, mockPubSub
}

func setupBenchService(b *testing.B) (*DispatchService, *mocks.MockInboxStore, *mocks.MockKeyManager, *mocks.MockPubSub) {
	logger, _ := zap.NewDevelopment()
	mockStore := new(mocks.MockInboxStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockPubSub := new(mocks.MockPubSub)

	mockPubSub.On("GetPeerID").Return(make([]byte, 32))

	// Setup key manager mocks
	mockKeyManager.On("GetAgreementKey", mock.Anything).Return(nil, nil)
	mockKeyManager.On("GetRawKey", mock.Anything).Return(&keys.Key{
		Id:         "",
		Type:       crypto.KeyTypeX448,
		PrivateKey: make([]byte, 56),
		PublicKey:  make([]byte, 57),
	}, nil)

	service := NewDispatchService(
		mockStore,
		logger,
		mockKeyManager,
		mockPubSub,
	)

	// Set some default responsible filters
	service.SetResponsibleFilters([][3]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	})

	return service, mockStore, mockKeyManager, mockPubSub
}

func createValidEd448Keys() ([]byte, []byte) {
	// Generate ED25519 keys for testing (ED448 is too complex for test)
	// In real tests, we'd need actual ED448 keys, but for signature verification tests
	// we'll mock the key manager
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Pad to ED448 sizes for interface compatibility
	ed448Priv := make([]byte, 114) // ED448 private key size
	ed448Pub := make([]byte, 57)   // ED448 public key size
	copy(ed448Priv, priv)
	copy(ed448Pub, pub)

	return ed448Pub, ed448Priv
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

func TestDispatchService_SetResponsibleFilters(t *testing.T) {
	service, _, _, _ := setupTestService(t)

	filters := [][3]byte{
		{0x07, 0x08, 0x09},
		{0x0A, 0x0B, 0x0C},
	}

	service.SetResponsibleFilters(filters)

	// Check that new filters are set
	assert.True(t, service.IsResponsibleForFilter([3]byte{0x07, 0x08, 0x09}))
	assert.True(t, service.IsResponsibleForFilter([3]byte{0x0A, 0x0B, 0x0C}))

	// Check that old filters are no longer set
	assert.False(t, service.IsResponsibleForFilter([3]byte{0x01, 0x02, 0x03}))
}

func TestDispatchService_AddInboxMessage(t *testing.T) {
	service, mockStore, _, _ := setupTestService(t)
	ctx := context.Background()

	address := bytes.Repeat([]byte{0xAA}, 32)
	filter := up2p.GetBloomFilterIndices(address, 256, 3)
	msg := createTestMessage(address, uint64(time.Now().UnixMilli()), "Test message")

	// Set service to be responsible for this filter
	service.SetResponsibleFilters([][3]byte{[3]byte(filter)})

	t.Run("Success", func(t *testing.T) {
		mockStore.On("AddMessage", msg).Return(nil).Once()

		err := service.AddInboxMessage(ctx, msg)
		require.NoError(t, err)

		mockStore.AssertExpectations(t)
	})

	t.Run("NotResponsibleForFilter", func(t *testing.T) {
		// Set different filter responsibility
		service.SetResponsibleFilters([][3]byte{{0xFF, 0xFE, 0xFD}})

		err := service.AddInboxMessage(ctx, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not responsible for filter")
	})

	t.Run("NilMessage", func(t *testing.T) {
		err := service.AddInboxMessage(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "message is nil")
	})
}

func TestDispatchService_GetInboxMessages(t *testing.T) {
	service, mockStore, _, _ := setupTestService(t)
	ctx := context.Background()

	filter := [3]byte{0x01, 0x02, 0x03}
	address := bytes.Repeat([]byte{0xAA}, 32)

	t.Run("GetByFilter", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{
			createTestMessage(address, 1000, "Message 1"),
			createTestMessage(address, 2000, "Message 2"),
		}

		mockStore.On("GetMessagesByFilter", filter).Return(messages, nil).Once()

		req := &protobufs.InboxMessageRequest{
			Filter: filter[:],
		}

		resp, err := service.getInboxMessages(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 2)

		mockStore.AssertExpectations(t)
	})

	t.Run("GetByAddress", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{
			createTestMessage(address, 1000, "Message 1"),
		}

		mockStore.On("GetMessagesByAddress", filter, address).Return(messages, nil).Once()

		req := &protobufs.InboxMessageRequest{
			Filter:  filter[:],
			Address: address,
		}

		resp, err := service.getInboxMessages(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 1)

		mockStore.AssertExpectations(t)
	})

	t.Run("GetByTimeRange", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{
			createTestMessage(address, 1500, "Message in range"),
		}

		mockStore.On("GetMessagesByTimeRange", filter, address, uint64(1000), uint64(2000)).Return(messages, nil).Once()

		req := &protobufs.InboxMessageRequest{
			Filter:        filter[:],
			Address:       address,
			FromTimestamp: 1000,
			ToTimestamp:   2000,
		}

		resp, err := service.getInboxMessages(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 1)

		mockStore.AssertExpectations(t)
	})

	t.Run("InvalidFilterLength", func(t *testing.T) {
		req := &protobufs.InboxMessageRequest{
			Filter: []byte{0x01, 0x02}, // Invalid length
		}

		_, err := service.getInboxMessages(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid filter length")
	})

	t.Run("NotResponsibleForFilter", func(t *testing.T) {
		service.SetResponsibleFilters([][3]byte{{0xFF, 0xFE, 0xFD}})

		req := &protobufs.InboxMessageRequest{
			Filter: filter[:],
		}

		_, err := service.getInboxMessages(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not responsible for filter")
	})
}

func TestDispatchService_HubAssociations(t *testing.T) {
	ctx := context.Background()

	hubAddress := bytes.Repeat([]byte{0xCC}, 32)
	inboxPubKey, _ := createValidEd448Keys()
	hubPubKey, _ := createValidEd448Keys()
	filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)

	// Set service to be responsible for this filter

	t.Run("AddHubInboxAssociation_Success", func(t *testing.T) {
		addMsg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		service, mockStore, mockKeyManager, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{[3]byte(filter)})
		// Mock signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)

		mockStore.On("AddHubInboxAssociation", addMsg).Return(nil).Once()

		err := service.AddHubInboxAssociation(ctx, addMsg)
		require.NoError(t, err)

		mockStore.AssertExpectations(t)
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("AddHubInboxAssociation_InvalidSignature", func(t *testing.T) {
		addMsg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		service, _, mockKeyManager, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{[3]byte(filter)})
		// Mock signature verification failure
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(false, nil)

		err := service.AddHubInboxAssociation(ctx, addMsg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("DeleteHubInboxAssociation_Success", func(t *testing.T) {
		deleteMsg := createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey)
		service, mockStore, mockKeyManager, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{[3]byte(filter)})
		// Mock signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)

		mockStore.On("DeleteHubInboxAssociation", deleteMsg).Return(nil).Once()

		err := service.DeleteHubInboxAssociation(ctx, deleteMsg)
		require.NoError(t, err)

		mockStore.AssertExpectations(t)
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("GetHub", func(t *testing.T) {
		service, mockStore, _, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{[3]byte(filter)})
		hubResponse := &protobufs.HubResponse{
			Adds: []*protobufs.HubAddInboxMessage{
				createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey),
			},
			Deletes: []*protobufs.HubDeleteInboxMessage{},
		}

		mockStore.On("GetHubAssociations", [3]byte(filter), hubAddress).Return(hubResponse, nil).Once()

		req := &protobufs.HubRequest{
			Filter:     filter,
			HubAddress: hubAddress,
		}

		resp, err := service.getHub(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Adds, 1)
		assert.Len(t, resp.Deletes, 0)

		mockStore.AssertExpectations(t)
	})

	t.Run("NilMessages", func(t *testing.T) {
		service, _, _, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{[3]byte(filter)})
		err := service.AddHubInboxAssociation(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "add message is nil")

		err = service.DeleteHubInboxAssociation(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delete message is nil")
	})
}

func TestDispatchService_Sync(t *testing.T) {
	service, mockStore, _, _ := setupTestService(t)
	ctx := context.Background()

	filter1 := [3]byte{0x01, 0x02, 0x03}
	filter2 := [3]byte{0x04, 0x05, 0x06}

	t.Run("Success", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{
			createTestMessage(bytes.Repeat([]byte{0xAA}, 32), 1000, "Message 1"),
			createTestMessage(bytes.Repeat([]byte{0xBB}, 32), 2000, "Message 2"),
		}

		hubs := []*protobufs.HubResponse{
			{
				Adds: []*protobufs.HubAddInboxMessage{
					createTestHubAddMessage(bytes.Repeat([]byte{0xCC}, 32), bytes.Repeat([]byte{0x11}, 57), bytes.Repeat([]byte{0x22}, 57)),
				},
				Deletes: []*protobufs.HubDeleteInboxMessage{},
			},
		}

		mockStore.On("GetAllMessagesCRDT", [][3]byte{filter1, filter2}).Return(messages, nil).Once()
		mockStore.On("GetAllHubsCRDT", [][3]byte{filter1, filter2}).Return(hubs, nil).Once()

		req := &protobufs.DispatchSyncRequest{
			Filters: [][]byte{filter1[:], filter2[:]},
		}

		resp, err := service.Sync(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 2)
		assert.Len(t, resp.Hubs, 1)

		mockStore.AssertExpectations(t)
	})

	t.Run("NoResponsibleFilters", func(t *testing.T) {
		// Set service to not be responsible for any of the requested filters
		service.SetResponsibleFilters([][3]byte{{0xFF, 0xFE, 0xFD}})

		req := &protobufs.DispatchSyncRequest{
			Filters: [][]byte{filter1[:], filter2[:]},
		}

		resp, err := service.Sync(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 0)
		assert.Len(t, resp.Hubs, 0)
	})

	t.Run("InvalidFilterLength", func(t *testing.T) {
		req := &protobufs.DispatchSyncRequest{
			Filters: [][]byte{{0x01, 0x02}}, // Invalid length
		}

		resp, err := service.Sync(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 0)
		assert.Len(t, resp.Hubs, 0)
	})
}

func TestDispatchService_gRPCMethods(t *testing.T) {
	service, mockStore, mockKeyManager, _ := setupTestService(t)
	ctx := context.Background()

	address := bytes.Repeat([]byte{0xAA}, 32)
	filter := up2p.GetBloomFilterIndices(address, 256, 3)
	service.SetResponsibleFilters([][3]byte{[3]byte(filter)})

	t.Run("PutInboxMessage", func(t *testing.T) {
		msg := createTestMessage(address, uint64(time.Now().UnixMilli()), "gRPC test")
		mockStore.On("AddMessage", msg).Return(nil).Once()

		req := &protobufs.InboxMessagePut{
			Message: msg,
		}

		resp, err := service.PutInboxMessage(ctx, req)
		require.NoError(t, err)
		assert.IsType(t, &emptypb.Empty{}, resp)

		mockStore.AssertExpectations(t)
	})

	t.Run("GetInboxMessages_gRPC", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{
			createTestMessage(address, 1000, "gRPC Message"),
		}

		mockStore.On("GetMessagesByFilter", [3]byte(filter)).Return(messages, nil).Once()

		req := &protobufs.InboxMessageRequest{
			Filter: filter,
		}

		resp, err := service.GetInboxMessages(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Messages, 1)

		mockStore.AssertExpectations(t)
	})

	t.Run("PutHub", func(t *testing.T) {
		hubAddress := bytes.Repeat([]byte{0xCC}, 32)
		inboxPubKey, _ := createValidEd448Keys()
		hubPubKey, _ := createValidEd448Keys()

		addMsg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		deleteMsg := createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey)

		// Mock signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)

		mockStore.On("AddHubInboxAssociation", addMsg).Return(nil).Once()
		mockStore.On("DeleteHubInboxAssociation", deleteMsg).Return(nil).Once()

		req := &protobufs.HubPut{
			Add:    addMsg,
			Delete: deleteMsg,
		}

		resp, err := service.PutHub(ctx, req)
		require.NoError(t, err)
		assert.IsType(t, &emptypb.Empty{}, resp)

		mockStore.AssertExpectations(t)
		mockKeyManager.AssertExpectations(t)
	})

	t.Run("GetHub_gRPC", func(t *testing.T) {
		hubAddress := bytes.Repeat([]byte{0xCC}, 32)
		hubResponse := &protobufs.HubResponse{
			Adds:    []*protobufs.HubAddInboxMessage{},
			Deletes: []*protobufs.HubDeleteInboxMessage{},
		}

		mockStore.On("GetHubAssociations", [3]byte(filter), hubAddress).Return(hubResponse, nil).Once()

		req := &protobufs.HubRequest{
			Filter:     filter,
			HubAddress: hubAddress,
		}

		resp, err := service.GetHub(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		mockStore.AssertExpectations(t)
	})

	t.Run("Sync_gRPC", func(t *testing.T) {
		messages := []*protobufs.InboxMessage{}
		hubs := []*protobufs.HubResponse{}

		mockStore.On("GetAllMessagesCRDT", [][3]byte{[3]byte(filter)}).Return(messages, nil).Once()
		mockStore.On("GetAllHubsCRDT", [][3]byte{[3]byte(filter)}).Return(hubs, nil).Once()

		req := &protobufs.DispatchSyncRequest{
			Filters: [][]byte{filter},
		}

		resp, err := service.Sync(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		mockStore.AssertExpectations(t)
	})
}

func TestDispatchService_SignatureVerification(t *testing.T) {
	hubAddress := bytes.Repeat([]byte{0xCC}, 32)
	inboxPubKey, _ := createValidEd448Keys()
	hubPubKey, _ := createValidEd448Keys()

	t.Run("VerifyHubAddSignatures_Success", func(t *testing.T) {
		msg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		service, _, mockKeyManager, _ := setupTestService(t)

		// Mock successful signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)

		err := service.verifyHubAddSignatures(msg)
		require.NoError(t, err)

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("VerifyHubAddSignatures_InvalidHub", func(t *testing.T) {
		msg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
		service, _, mockKeyManager, _ := setupTestService(t)

		// Mock hub signature failure
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(false, nil)

		err := service.verifyHubAddSignatures(msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hub signature")

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("VerifyHubDeleteSignatures_Success", func(t *testing.T) {
		msg := createTestHubDeleteMessage(hubAddress, inboxPubKey, hubPubKey)
		service, _, mockKeyManager, _ := setupTestService(t)

		// Mock successful signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)

		err := service.verifyHubDeleteSignatures(msg)
		require.NoError(t, err)

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("VerifyEd448Signature_InvalidKeySize", func(t *testing.T) {
		service, _, _, _ := setupTestService(t)
		// Test with invalid key sizes
		assert.False(t, service.verifyEd448Signature([]byte{0x01}, []byte("message"), []byte{0x01}))
		assert.False(t, service.verifyEd448Signature(make([]byte, 57), []byte("message"), []byte{0x01}))
		assert.False(t, service.verifyEd448Signature(make([]byte, 10), []byte("message"), make([]byte, 114)))
	})

	t.Run("VerifyEd448Signature_KeyManagerError", func(t *testing.T) {
		service, _, mockKeyManager, _ := setupTestService(t)
		validPubKey := make([]byte, 57)
		validSignature := make([]byte, 114)
		message := []byte("test message")

		// Mock key manager error
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(false, errors.New("!!!"))

		result := service.verifyEd448Signature(validPubKey, message, validSignature)
		assert.False(t, result)

		mockKeyManager.AssertExpectations(t)
	})
}

func TestDispatchService_BackgroundProcesses(t *testing.T) {
	t.Skip()
	filter1 := [3]byte{0x01, 0x02, 0x03}
	filter2 := [3]byte{0x04, 0x05, 0x06}

	t.Run("ReapMessages", func(t *testing.T) {
		service, mockStore, _, _ := setupTestService(t)
		// Set responsible filters and short retention period
		service.SetResponsibleFilters([][3]byte{filter1, filter2})
		service.SetRetentionPeriod(1 * time.Hour)

		// Calculate expected cutoff time
		expectedCutoff := time.Now().Add(-1 * time.Hour).UnixMilli()

		// Mock the ReapMessages calls for both filters
		mockStore.On("ReapMessages", mock.Anything, mock.MatchedBy(func(ts uint64) bool {
			// Allow some time variance (within 5 seconds)
			return int64(ts) >= expectedCutoff-5000 && int64(ts) <= expectedCutoff+5000
		})).Return(nil).Once()

		mockStore.On("ReapMessages", mock.Anything, mock.MatchedBy(func(ts uint64) bool {
			return int64(ts) >= expectedCutoff-5000 && int64(ts) <= expectedCutoff+5000
		})).Return(nil).Once()

		// Manually trigger reaping
		service.reapMessages()

		mockStore.AssertExpectations(t)
	})

	t.Run("ReapMessages_WithError", func(t *testing.T) {
		service, mockStore, _, _ := setupTestService(t)
		service.SetResponsibleFilters([][3]byte{filter1})
		service.SetRetentionPeriod(1 * time.Hour)

		// Mock error from store
		mockStore.On("ReapMessages", mock.Anything, mock.Anything).Return(errors.New("reap error")).Once()

		// Should not panic even with error
		service.reapMessages()

		mockStore.AssertExpectations(t)
	})

	t.Run("StartStop", func(t *testing.T) {
		// Create a fresh service for lifecycle testing
		freshService, _, _, _ := setupTestService(t)
		freshService.SetReapInterval(10 * time.Millisecond) // Fast interval for testing

		// Test that Start and Stop work correctly
		freshService.Start()

		// Give it a moment to start
		time.Sleep(50 * time.Millisecond)

		// Stop should gracefully shut down
		freshService.Stop()

		// Multiple stops should not panic
		freshService.Stop()
	})

	t.Run("ConfigurationSetters", func(t *testing.T) {
		service, _, _, _ := setupTestService(t)
		newInterval := 30 * time.Minute
		newPeriod := 3 * 24 * time.Hour

		service.SetReapInterval(newInterval)
		service.SetRetentionPeriod(newPeriod)

		// Verify configuration was set
		service.mu.RLock()
		assert.Equal(t, newInterval, service.reapInterval)
		assert.Equal(t, newPeriod, service.retentionPeriod)
		service.mu.RUnlock()
	})
}

func BenchmarkDispatchService(b *testing.B) {
	service, mockStore, mockKeyManager, _ := setupBenchService(b)
	ctx := context.Background()

	address := bytes.Repeat([]byte{0xAA}, 32)
	filter := up2p.GetBloomFilterIndices(address, 256, 3)
	service.SetResponsibleFilters([][3]byte{[3]byte(filter)})

	b.Run("AddInboxMessage", func(b *testing.B) {
		mockStore.On("AddMessage", mock.Anything).Return(nil)

		for i := 0; i < b.N; i++ {
			msg := createTestMessage(address, uint64(i), "Benchmark message")
			_ = service.AddInboxMessage(ctx, msg)
		}
	})

	b.Run("AddHubInboxAssociation", func(b *testing.B) {
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(true, nil)
		mockStore.On("AddHubInboxAssociation", mock.Anything).Return(nil)

		hubAddress := bytes.Repeat([]byte{0xCC}, 32)
		inboxPubKey := make([]byte, 57)
		hubPubKey := make([]byte, 57)

		for i := 0; i < b.N; i++ {
			msg := createTestHubAddMessage(hubAddress, inboxPubKey, hubPubKey)
			_ = service.AddHubInboxAssociation(ctx, msg)
		}
	})
}
