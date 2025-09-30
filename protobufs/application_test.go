package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplication_Serialization(t *testing.T) {
	tests := []struct {
		name string
		app  *Application
	}{
		{
			name: "complete application",
			app: &Application{
				Address:          make([]byte, 32),
				ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
			},
		},
		{
			name: "application with extrinsic context",
			app: &Application{
				Address:          append([]byte{0x01, 0x02}, make([]byte, 30)...),
				ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
			},
		},
		{
			name: "empty address",
			app: &Application{
				Address:          []byte{},
				ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.app.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			app2 := &Application{}
			err = app2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.app.Address, app2.Address)
			assert.Equal(t, tt.app.ExecutionContext, app2.ExecutionContext)
		})
	}
}

func TestMessage_Serialization(t *testing.T) {
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "complete message",
			msg: &Message{
				Hash:    make([]byte, 32),
				Address: make([]byte, 32),
				Payload: []byte("test message payload"),
			},
		},
		{
			name: "message with custom values",
			msg: &Message{
				Hash:    append([]byte{0xFF}, make([]byte, 31)...),
				Address: append([]byte{0xAA}, make([]byte, 31)...),
				Payload: []byte("another test message"),
			},
		},
		{
			name: "message with empty payload",
			msg: &Message{
				Hash:    make([]byte, 32),
				Address: make([]byte, 32),
				Payload: []byte{},
			},
		},
		{
			name: "minimal message",
			msg: &Message{
				Hash:    []byte{},
				Address: []byte{},
				Payload: []byte{},
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
			msg2 := &Message{}
			err = msg2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.msg.Hash, msg2.Hash)
			assert.Equal(t, tt.msg.Address, msg2.Address)
			assert.Equal(t, tt.msg.Payload, msg2.Payload)
		})
	}
}
