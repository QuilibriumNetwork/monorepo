package token

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func TestSendTransaction_Success(t *testing.T) {
	client := &mockNodeServiceClient{}
	km := newMockKeyManager()
	domain := []byte("test-domain")

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: &protobufs.Transaction{},
		},
	}

	err := SendTransaction(client, domain, request, km)
	require.NoError(t, err)

	// Verify Send was called with correct structure
	require.NotNil(t, client.lastSendRequest)
	assert.Equal(t, domain, client.lastSendRequest.Domain)
	assert.NotNil(t, client.lastSendRequest.Request)
	assert.Len(t, client.lastSendRequest.Request.Requests, 1)
	assert.NotEmpty(t, client.lastSendRequest.Authentication)

	// Verify signer was called with correct domain
	expectedDomain := append([]byte("NODE_AUTHENTICATION"), domain...)
	assert.Equal(t, expectedDomain, km.signer.lastDomain)
	assert.NotEmpty(t, km.signer.lastMessage)
}

func TestSendTransaction_SignKeyError(t *testing.T) {
	client := &mockNodeServiceClient{}
	km := newMockKeyManager()
	km.signerErr = fmt.Errorf("key not found")

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: &protobufs.Transaction{},
		},
	}

	err := SendTransaction(client, []byte("d"), request, km)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get signing key")
}

func TestSendTransaction_SignError(t *testing.T) {
	client := &mockNodeServiceClient{}
	km := newMockKeyManager()
	km.signer.signErr = fmt.Errorf("signature failed")

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: &protobufs.Transaction{},
		},
	}

	err := SendTransaction(client, []byte("d"), request, km)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign")
}

func TestSendTransaction_RPCError(t *testing.T) {
	client := &mockNodeServiceClient{
		sendErr: fmt.Errorf("connection refused"),
	}
	km := newMockKeyManager()

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: &protobufs.Transaction{},
		},
	}

	err := SendTransaction(client, []byte("d"), request, km)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc")
}

func TestSendTransaction_MessageBundleStructure(t *testing.T) {
	client := &mockNodeServiceClient{}
	km := newMockKeyManager()

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: &protobufs.Transaction{},
		},
	}

	err := SendTransaction(client, []byte("d"), request, km)
	require.NoError(t, err)

	bundle := client.lastSendRequest.Request
	require.NotNil(t, bundle)
	assert.NotZero(t, bundle.Timestamp)
	assert.Len(t, bundle.Requests, 1)

	// Verify deterministic canonical bytes: calling again with same input
	// should produce the same signature payload length
	client2 := &mockNodeServiceClient{}
	km2 := newMockKeyManager()

	err = SendTransaction(client2, []byte("d"), request, km2)
	require.NoError(t, err)

	assert.Equal(t,
		len(km.signer.lastMessage),
		len(km2.signer.lastMessage),
	)
}
