package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageCiphertext_Serialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *MessageCiphertext
	}{
		{
			name: "valid message ciphertext",
			msg: &MessageCiphertext{
				InitializationVector: make([]byte, 12),
				Ciphertext:           []byte("test ciphertext data"),
				AssociatedData:       []byte("test associated data"),
			},
		},
		{
			name: "empty fields",
			msg: &MessageCiphertext{
				InitializationVector: []byte{},
				Ciphertext:           []byte{},
				AssociatedData:       []byte{},
			},
		},
		{
			name: "nil fields",
			msg:  &MessageCiphertext{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.msg.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			msg2 := &MessageCiphertext{}
			err = msg2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.True(t, equalBytes(
				tt.msg.InitializationVector,
				msg2.InitializationVector,
			))
			assert.True(t, equalBytes(tt.msg.Ciphertext, msg2.Ciphertext))
			assert.True(t, equalBytes(tt.msg.AssociatedData, msg2.AssociatedData))
		})
	}
}

func TestP2PChannelEnvelope_Serialization(t *testing.T) {
	tests := []struct {
		name string
		env  *P2PChannelEnvelope
	}{
		{
			name: "complete envelope",
			env: &P2PChannelEnvelope{
				ProtocolIdentifier: 0x01020304,
				MessageHeader: &MessageCiphertext{
					InitializationVector: make([]byte, 12),
					Ciphertext:           []byte("header ciphertext"),
					AssociatedData:       []byte("header associated data"),
				},
				MessageBody: &MessageCiphertext{
					InitializationVector: make([]byte, 12),
					Ciphertext:           []byte("body ciphertext"),
					AssociatedData:       []byte("body associated data"),
				},
			},
		},
		{
			name: "envelope without header",
			env: &P2PChannelEnvelope{
				ProtocolIdentifier: 0x05060708,
				MessageBody: &MessageCiphertext{
					InitializationVector: make([]byte, 12),
					Ciphertext:           []byte("body only"),
				},
			},
		},
		{
			name: "envelope without body",
			env: &P2PChannelEnvelope{
				ProtocolIdentifier: 0x090A0B0C,
				MessageHeader: &MessageCiphertext{
					InitializationVector: make([]byte, 12),
					Ciphertext:           []byte("header only"),
				},
			},
		},
		{
			name: "minimal envelope",
			env: &P2PChannelEnvelope{
				ProtocolIdentifier: 0x0D0E0F10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.env.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			env2 := &P2PChannelEnvelope{}
			err = env2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare fields
			assert.Equal(t, tt.env.ProtocolIdentifier, env2.ProtocolIdentifier)

			if tt.env.MessageHeader != nil {
				require.NotNil(t, env2.MessageHeader)
				assert.True(t, equalBytes(
					tt.env.MessageHeader.InitializationVector,
					env2.MessageHeader.InitializationVector,
				))
				assert.True(t, equalBytes(
					tt.env.MessageHeader.Ciphertext,
					env2.MessageHeader.Ciphertext,
				))
				assert.True(t, equalBytes(
					tt.env.MessageHeader.AssociatedData,
					env2.MessageHeader.AssociatedData,
				))
			} else {
				assert.Nil(t, env2.MessageHeader)
			}

			if tt.env.MessageBody != nil {
				require.NotNil(t, env2.MessageBody)
				assert.True(t, equalBytes(
					tt.env.MessageBody.InitializationVector,
					env2.MessageBody.InitializationVector,
				))
				assert.True(t, equalBytes(
					tt.env.MessageBody.Ciphertext,
					env2.MessageBody.Ciphertext,
				))
				assert.True(t, equalBytes(
					tt.env.MessageBody.AssociatedData,
					env2.MessageBody.AssociatedData,
				))
			} else {
				assert.Nil(t, env2.MessageBody)
			}
		})
	}
}
