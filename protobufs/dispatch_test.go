package protobufs

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInboxMessage_Serialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *InboxMessage
	}{
		{
			name: "complete message",
			msg: &InboxMessage{
				Address:            []byte{0x01, 0x02, 0x03},
				Timestamp:          uint64(time.Now().UnixMilli()),
				EphemeralPublicKey: randomBytesDispatch(t, 32),
				Message:            []byte("encrypted message content"),
			},
		},
		{
			name: "minimal message",
			msg: &InboxMessage{
				Address:            []byte{0xFF, 0xFF, 0xFF},
				Timestamp:          0,
				EphemeralPublicKey: []byte{},
				Message:            []byte{0x02},
			},
		},
		{
			name: "large message",
			msg: &InboxMessage{
				Address:            []byte{0xAA, 0xBB, 0xCC},
				Timestamp:          uint64(time.Now().UnixMilli()),
				EphemeralPublicKey: randomBytesDispatch(t, 64),
				Message:            randomBytesDispatch(t, 1024),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.msg.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			msg2 := &InboxMessage{}
			err = msg2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.msg.Timestamp, msg2.Timestamp)
			assert.Equal(t, tt.msg.Address, msg2.Address)
			assert.Equal(t, tt.msg.EphemeralPublicKey, msg2.EphemeralPublicKey)
			assert.Equal(t, tt.msg.Message, msg2.Message)
		})
	}
}

func TestHubAddInboxMessage_Serialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *HubAddInboxMessage
	}{
		{
			name: "complete hub add inbox message",
			msg: &HubAddInboxMessage{
				Address:        make([]byte, 32),
				InboxPublicKey: make([]byte, 57),  // Ed448 key
				HubPublicKey:   make([]byte, 57),  // Ed448 key
				InboxSignature: make([]byte, 114), // Ed448 Signature
				HubSignature:   make([]byte, 114), // Ed448 Signature
			},
		},
		{
			name: "hub add with different keys",
			msg: &HubAddInboxMessage{
				Address:        append([]byte{0xFF}, make([]byte, 31)...),
				InboxPublicKey: append([]byte{0xAA}, make([]byte, 56)...),
				HubPublicKey:   append([]byte{0xBB}, make([]byte, 56)...),
				InboxSignature: make([]byte, 114), // Ed448 Signature
				HubSignature:   make([]byte, 114), // Ed448 Signature
			},
		},
		{
			name: "minimal hub add",
			msg: &HubAddInboxMessage{
				Address:        []byte{},
				InboxPublicKey: []byte{},
				HubPublicKey:   []byte{},
				InboxSignature: []byte{},
				HubSignature:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			msg2 := &HubAddInboxMessage{}
			err = msg2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.msg.Address, msg2.Address)
			assert.Equal(t, tt.msg.InboxPublicKey, msg2.InboxPublicKey)
			assert.Equal(t, tt.msg.HubPublicKey, msg2.HubPublicKey)
			assert.Equal(t, tt.msg.InboxSignature, msg2.InboxSignature)
			assert.Equal(t, tt.msg.HubSignature, msg2.HubSignature)
		})
	}
}

func TestHubDeleteInboxMessage_Serialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *HubDeleteInboxMessage
	}{
		{
			name: "complete hub delete inbox message",
			msg: &HubDeleteInboxMessage{
				Address:        make([]byte, 32),
				InboxPublicKey: make([]byte, 57),  // Ed448 key
				HubPublicKey:   make([]byte, 57),  // Ed448 key
				InboxSignature: make([]byte, 114), // Ed448 Signature
				HubSignature:   make([]byte, 114), // Ed448 Signature
			},
		},
		{
			name: "hub delete with different values",
			msg: &HubDeleteInboxMessage{
				Address:        append([]byte{0x12}, make([]byte, 31)...),
				InboxPublicKey: append([]byte{0x34}, make([]byte, 56)...),
				HubPublicKey:   append([]byte{0x56}, make([]byte, 56)...),
				InboxSignature: make([]byte, 114), // Ed448 Signature
				HubSignature:   make([]byte, 114), // Ed448 Signature
			},
		},
		{
			name: "minimal hub delete",
			msg: &HubDeleteInboxMessage{
				Address:        []byte{},
				InboxPublicKey: []byte{},
				HubPublicKey:   []byte{},
				InboxSignature: []byte{},
				HubSignature:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			msg2 := &HubDeleteInboxMessage{}
			err = msg2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.msg.Address, msg2.Address)
			assert.Equal(t, tt.msg.InboxPublicKey, msg2.InboxPublicKey)
			assert.Equal(t, tt.msg.HubPublicKey, msg2.HubPublicKey)
			assert.Equal(t, tt.msg.InboxSignature, msg2.InboxSignature)
			assert.Equal(t, tt.msg.HubSignature, msg2.HubSignature)
		})
	}
}

// Helper function to generate random bytes
func randomBytesDispatch(t *testing.T, size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
