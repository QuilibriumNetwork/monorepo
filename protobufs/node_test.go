package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerInfo_Serialization(t *testing.T) {
	tests := []struct {
		name string
		peer *PeerInfo
	}{
		{
			name: "complete peer info",
			peer: &PeerInfo{
				PeerId: []byte("peer-id-12345"),
				Reachability: []*Reachability{
					{
						Filter:           make([]byte, 32),
						PubsubMultiaddrs: []string{"/ip4/127.0.0.1/tcp/8080", "/ip6/::1/tcp/8080"},
						StreamMultiaddrs: []string{"/ip4/127.0.0.1/tcp/8081", "/ip6/::1/tcp/8081"},
					},
					{
						Filter:           append([]byte{0xFF}, make([]byte, 31)...),
						PubsubMultiaddrs: []string{"/ip4/192.168.1.1/tcp/9090"},
						StreamMultiaddrs: []string{"/ip4/192.168.1.1/tcp/9091"},
					},
				},
				Timestamp:    1234567890,
				Version:      []byte{1, 0, 0}, // semantic version bytes
				PatchVersion: []byte("patch-123"),
				Capabilities: []*Capability{
					{
						ProtocolIdentifier: 0x12345678,
						AdditionalMetadata: []byte("capability metadata"),
					},
					{
						ProtocolIdentifier: 0x87654321,
						AdditionalMetadata: []byte("another capability"),
					},
				},
				PublicKey: make([]byte, 57),  // Ed448 key
				Signature: make([]byte, 114), // Ed448 signature
			},
		},
		{
			name: "peer info with single reachability",
			peer: &PeerInfo{
				PeerId: []byte("peer-id-67890"),
				Reachability: []*Reachability{
					{
						Filter:           append([]byte{0xAA}, make([]byte, 31)...),
						PubsubMultiaddrs: []string{"/ip4/10.0.0.1/tcp/7070"},
						StreamMultiaddrs: []string{"/ip4/10.0.0.1/tcp/7071"},
					},
				},
				Timestamp:    9876543210,
				Version:      []byte{2, 1, 3},
				PatchVersion: []byte("patch-456"),
				Capabilities: []*Capability{
					{
						ProtocolIdentifier: 0xABCDEF12,
						AdditionalMetadata: []byte("single capability"),
					},
				},
				PublicKey: append([]byte{0xBB}, make([]byte, 56)...),
				Signature: append([]byte{0xCC}, make([]byte, 113)...),
			},
		},
		{
			name: "minimal peer info",
			peer: &PeerInfo{
				PeerId:       []byte{},
				Reachability: []*Reachability{},
				Timestamp:    0,
				Version:      []byte{},
				PatchVersion: []byte{},
				Capabilities: []*Capability{},
				PublicKey:    []byte{},
				Signature:    []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.peer.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			peer2 := &PeerInfo{}
			err = peer2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare basic fields
			assert.Equal(t, tt.peer.PeerId, peer2.PeerId)
			assert.Equal(t, tt.peer.Timestamp, peer2.Timestamp)
			assert.Equal(t, tt.peer.Version, peer2.Version)
			assert.Equal(t, tt.peer.PatchVersion, peer2.PatchVersion)
			assert.Equal(t, tt.peer.PublicKey, peer2.PublicKey)
			assert.Equal(t, tt.peer.Signature, peer2.Signature)

			// Compare reachability arrays
			assert.Equal(t, len(tt.peer.Reachability), len(peer2.Reachability))
			for i := range tt.peer.Reachability {
				assert.Equal(t, tt.peer.Reachability[i].Filter, peer2.Reachability[i].Filter)
				assert.Equal(t, tt.peer.Reachability[i].PubsubMultiaddrs, peer2.Reachability[i].PubsubMultiaddrs)
				assert.Equal(t, tt.peer.Reachability[i].StreamMultiaddrs, peer2.Reachability[i].StreamMultiaddrs)
			}

			// Compare capabilities arrays
			assert.Equal(t, len(tt.peer.Capabilities), len(peer2.Capabilities))
			for i := range tt.peer.Capabilities {
				assert.Equal(t, tt.peer.Capabilities[i].ProtocolIdentifier, peer2.Capabilities[i].ProtocolIdentifier)
				assert.Equal(t, tt.peer.Capabilities[i].AdditionalMetadata, peer2.Capabilities[i].AdditionalMetadata)
			}
		})
	}
}

func TestCapability_Serialization(t *testing.T) {
	tests := []struct {
		name string
		cap  *Capability
	}{
		{
			name: "complete capability",
			cap: &Capability{
				ProtocolIdentifier: uint32(0x12345678),
				AdditionalMetadata: []byte("capability metadata"),
			},
		},
		{
			name: "capability with max protocol id",
			cap: &Capability{
				ProtocolIdentifier: uint32(0xFFFFFFFF),
				AdditionalMetadata: []byte("max protocol capability"),
			},
		},
		{
			name: "capability with empty metadata",
			cap: &Capability{
				ProtocolIdentifier: uint32(0),
				AdditionalMetadata: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.cap.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			cap2 := &Capability{}
			err = cap2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.cap.ProtocolIdentifier, cap2.ProtocolIdentifier)
			assert.Equal(t, tt.cap.AdditionalMetadata, cap2.AdditionalMetadata)
		})
	}
}
