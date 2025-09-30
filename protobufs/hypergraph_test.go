package protobufs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHypergraphConfiguration_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		config *HypergraphConfiguration
	}{
		{
			name: "complete configuration",
			config: &HypergraphConfiguration{
				ReadPublicKey:  make([]byte, 57), // Ed448 key
				WritePublicKey: make([]byte, 57), // Ed448 key
			},
		},
		{
			name: "empty keys",
			config: &HypergraphConfiguration{
				ReadPublicKey:  []byte{},
				WritePublicKey: []byte{},
			},
		},
		{
			name: "different keys",
			config: &HypergraphConfiguration{
				ReadPublicKey:  append([]byte{0x01}, make([]byte, 56)...),
				WritePublicKey: append([]byte{0x02}, make([]byte, 56)...),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.config.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			config2 := &HypergraphConfiguration{}
			err = config2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.config.ReadPublicKey, config2.ReadPublicKey)
			assert.Equal(t, tt.config.WritePublicKey, config2.WritePublicKey)
		})
	}
}

func TestHypergraphDeploy_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		deploy *HypergraphDeploy
	}{
		{
			name: "complete deploy",
			deploy: &HypergraphDeploy{
				Config: &HypergraphConfiguration{
					ReadPublicKey:  make([]byte, 57),
					WritePublicKey: make([]byte, 57),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.deploy.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			deploy2 := &HypergraphDeploy{}
			err = deploy2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			require.NotNil(t, deploy2.Config)
			assert.Equal(t, tt.deploy.Config.ReadPublicKey, deploy2.Config.ReadPublicKey)
			assert.Equal(t, tt.deploy.Config.WritePublicKey, deploy2.Config.WritePublicKey)
		})
	}
}

func TestVertexAdd_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		vertex *VertexAdd
	}{
		{
			name: "complete vertex",
			vertex: &VertexAdd{
				Domain:      make([]byte, 32),
				DataAddress: make([]byte, 32),
				Data:        []byte("test vector commitment tree data"),
				Signature:   make([]byte, 114), // Ed448 signature
			},
		},
		{
			name: "minimal vertex",
			vertex: &VertexAdd{
				Domain:      make([]byte, 32),
				DataAddress: make([]byte, 32),
				Data:        []byte{0x01},
				Signature:   []byte{},
			},
		},
		{
			name: "large data",
			vertex: &VertexAdd{
				Domain:      make([]byte, 32),
				DataAddress: make([]byte, 32),
				Data:        make([]byte, 1024), // Large data blob
				Signature:   make([]byte, 114),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.vertex.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			vertex2 := &VertexAdd{}
			err = vertex2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.vertex.Domain, vertex2.Domain)
			assert.Equal(t, tt.vertex.DataAddress, vertex2.DataAddress)
			assert.Equal(t, tt.vertex.Data, vertex2.Data)
			assert.Equal(t, tt.vertex.Signature, vertex2.Signature)
		})
	}
}

func TestVertexRemove_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		vertex *VertexRemove
	}{
		{
			name: "complete vertex remove",
			vertex: &VertexRemove{
				Domain:      make([]byte, 32),
				DataAddress: make([]byte, 32),
				Signature:   make([]byte, 114),
			},
		},
		{
			name: "empty signature",
			vertex: &VertexRemove{
				Domain:      make([]byte, 32),
				DataAddress: make([]byte, 32),
				Signature:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.vertex.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			vertex2 := &VertexRemove{}
			err = vertex2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.vertex.Domain, vertex2.Domain)
			assert.Equal(t, tt.vertex.DataAddress, vertex2.DataAddress)
			assert.Equal(t, tt.vertex.Signature, vertex2.Signature)
		})
	}
}

func TestHyperedgeAdd_Serialization(t *testing.T) {
	tests := []struct {
		name      string
		hyperedge *HyperedgeAdd
	}{
		{
			name: "complete hyperedge",
			hyperedge: &HyperedgeAdd{
				Domain:    make([]byte, 32),
				Value:     []byte("hyperedge value data"),
				Signature: make([]byte, 114),
			},
		},
		{
			name: "minimal hyperedge",
			hyperedge: &HyperedgeAdd{
				Domain:    make([]byte, 32),
				Value:     []byte{0x01},
				Signature: []byte{},
			},
		},
		{
			name: "large value",
			hyperedge: &HyperedgeAdd{
				Domain:    make([]byte, 32),
				Value:     make([]byte, 2048),
				Signature: make([]byte, 114),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.hyperedge.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			hyperedge2 := &HyperedgeAdd{}
			err = hyperedge2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.hyperedge.Domain, hyperedge2.Domain)
			assert.Equal(t, tt.hyperedge.Value, hyperedge2.Value)
			assert.Equal(t, tt.hyperedge.Signature, hyperedge2.Signature)
		})
	}
}

func TestHyperedgeRemove_Serialization(t *testing.T) {
	tests := []struct {
		name      string
		hyperedge *HyperedgeRemove
	}{
		{
			name: "complete hyperedge remove",
			hyperedge: &HyperedgeRemove{
				Domain:    make([]byte, 32),
				Value:     []byte("hyperedge value to remove"),
				Signature: make([]byte, 114),
			},
		},
		{
			name: "minimal value",
			hyperedge: &HyperedgeRemove{
				Domain:    make([]byte, 32),
				Value:     []byte{0x01},
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.hyperedge.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			hyperedge2 := &HyperedgeRemove{}
			err = hyperedge2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.hyperedge.Domain, hyperedge2.Domain)
			assert.Equal(t, tt.hyperedge.Value, hyperedge2.Value)
			assert.Equal(t, tt.hyperedge.Signature, hyperedge2.Signature)
		})
	}
}

func TestHypergraphTypes_Validation(t *testing.T) {
	t.Run("HypergraphConfiguration validation", func(t *testing.T) {
		// Valid configuration
		config := &HypergraphConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
		}
		assert.NoError(t, config.Validate())

		// Invalid read key length
		config.ReadPublicKey = make([]byte, 56)
		assert.Error(t, config.Validate())

		// Invalid write key length
		config.ReadPublicKey = make([]byte, 57)
		config.WritePublicKey = make([]byte, 58)
		assert.Error(t, config.Validate())

		// Nil configuration
		var nilConfig *HypergraphConfiguration
		assert.Error(t, nilConfig.Validate())
	})

	t.Run("HypergraphDeploy validation", func(t *testing.T) {
		// Valid deploy
		deploy := &HypergraphDeploy{
			Config: &HypergraphConfiguration{
				ReadPublicKey:  make([]byte, 57),
				WritePublicKey: make([]byte, 57),
			},
		}
		assert.NoError(t, deploy.Validate())

		// Nil config
		deploy.Config = nil
		assert.Error(t, deploy.Validate())

		// Invalid config
		deploy.Config = &HypergraphConfiguration{
			ReadPublicKey:  make([]byte, 56),
			WritePublicKey: make([]byte, 57),
		}
		assert.Error(t, deploy.Validate())
	})

	t.Run("VertexAdd validation", func(t *testing.T) {
		// Valid vertex
		vertex := &VertexAdd{
			Domain:      make([]byte, 32),
			DataAddress: make([]byte, 32),
			Data:        []byte("test"),
			Signature:   make([]byte, 114),
		}
		assert.NoError(t, vertex.Validate())

		// Invalid domain length
		vertex.Domain = make([]byte, 31)
		assert.Error(t, vertex.Validate())

		// Invalid data address length
		vertex.Domain = make([]byte, 32)
		vertex.DataAddress = make([]byte, 33)
		assert.Error(t, vertex.Validate())

		// Empty data
		vertex.DataAddress = make([]byte, 32)
		vertex.Data = []byte{}
		assert.Error(t, vertex.Validate())

		// Empty signature
		vertex.Data = []byte("test")
		vertex.Signature = []byte{}
		assert.Error(t, vertex.Validate())
	})

	t.Run("VertexRemove validation", func(t *testing.T) {
		// Valid vertex remove
		vertex := &VertexRemove{
			Domain:      make([]byte, 32),
			DataAddress: make([]byte, 32),
			Signature:   make([]byte, 114),
		}
		assert.NoError(t, vertex.Validate())

		// Invalid domain length
		vertex.Domain = make([]byte, 31)
		assert.Error(t, vertex.Validate())

		// Empty signature
		vertex.Domain = make([]byte, 32)
		vertex.Signature = []byte{}
		assert.Error(t, vertex.Validate())
	})

	t.Run("HyperedgeAdd validation", func(t *testing.T) {
		// Valid hyperedge
		hyperedge := &HyperedgeAdd{
			Domain:    make([]byte, 32),
			Value:     []byte("test"),
			Signature: make([]byte, 114),
		}
		assert.NoError(t, hyperedge.Validate())

		// Invalid domain length
		hyperedge.Domain = make([]byte, 31)
		assert.Error(t, hyperedge.Validate())

		// Empty value
		hyperedge.Domain = make([]byte, 32)
		hyperedge.Value = []byte{}
		assert.Error(t, hyperedge.Validate())

		// Empty signature
		hyperedge.Value = []byte("test")
		hyperedge.Signature = []byte{}
		assert.Error(t, hyperedge.Validate())
	})

	t.Run("HyperedgeRemove validation", func(t *testing.T) {
		// Valid hyperedge remove
		hyperedge := &HyperedgeRemove{
			Domain:    make([]byte, 32),
			Value:     []byte("test"),
			Signature: make([]byte, 114),
		}
		assert.NoError(t, hyperedge.Validate())

		// Invalid domain length
		hyperedge.Domain = make([]byte, 31)
		assert.Error(t, hyperedge.Validate())

		// Empty value
		hyperedge.Domain = make([]byte, 32)
		hyperedge.Value = []byte{}
		assert.Error(t, hyperedge.Validate())
	})
}

func TestHypergraphSerialization_RoundTrip(t *testing.T) {
	// Test that serialize -> deserialize -> serialize produces the same bytes
	config := &HypergraphConfiguration{
		ReadPublicKey:  randomBytes(t, 57),
		WritePublicKey: randomBytes(t, 57),
	}

	// First serialization
	data1, err := config.ToCanonicalBytes()
	require.NoError(t, err)

	// Deserialize
	config2 := &HypergraphConfiguration{}
	err = config2.FromCanonicalBytes(data1)
	require.NoError(t, err)

	// Second serialization
	data2, err := config2.ToCanonicalBytes()
	require.NoError(t, err)

	// Should be identical
	assert.Equal(t, data1, data2)
}

func TestHypergraphUpdate_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		update *HypergraphUpdate
	}{
		{
			name: "complete hypergraph update",
			update: &HypergraphUpdate{
				Config: &HypergraphConfiguration{
					ReadPublicKey:  make([]byte, 57),
					WritePublicKey: make([]byte, 57),
				},
				RdfSchema: []byte("@prefix ex: <http://example.org/> . ex:Thing a ex:Class ."),
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					Signature: make([]byte, 74), // BLS48-581 aggregate signature size
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585), // BLS48-581 G2 public key size
					},
					Bitmask: make([]byte, 32),
				},
			},
		},
		{
			name: "update with config only",
			update: &HypergraphUpdate{
				Config: &HypergraphConfiguration{
					ReadPublicKey:  append([]byte{0xAA}, make([]byte, 56)...),
					WritePublicKey: append([]byte{0xBB}, make([]byte, 56)...),
				},
				RdfSchema: []byte{},
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					Signature: append([]byte{0xCC}, make([]byte, 73)...),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: append([]byte{0xDD}, make([]byte, 584)...),
					},
					Bitmask: append([]byte{0xEE}, make([]byte, 31)...),
				},
			},
		},
		{
			name: "update with schema only",
			update: &HypergraphUpdate{
				Config:    nil,
				RdfSchema: []byte("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> ."),
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					Signature: make([]byte, 74),
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
					Bitmask: make([]byte, 32),
				},
			},
		},
		{
			name: "minimal update",
			update: &HypergraphUpdate{
				Config:                     nil,
				RdfSchema:                  []byte{},
				PublicKeySignatureBls48581: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.update.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			update2 := &HypergraphUpdate{}
			err = update2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare basic fields
			assert.Equal(t, true, bytes.Equal(tt.update.RdfSchema, update2.RdfSchema))

			// Compare Config if present
			if tt.update.Config != nil {
				assert.NotNil(t, update2.Config)
				assert.Equal(t, tt.update.Config.ReadPublicKey, update2.Config.ReadPublicKey)
				assert.Equal(t, tt.update.Config.WritePublicKey, update2.Config.WritePublicKey)
			} else {
				assert.Nil(t, update2.Config)
			}

			// Compare signature if present
			if tt.update.PublicKeySignatureBls48581 != nil {
				assert.NotNil(t, update2.PublicKeySignatureBls48581)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Signature, update2.PublicKeySignatureBls48581.Signature)
				assert.Equal(t, tt.update.PublicKeySignatureBls48581.Bitmask, update2.PublicKeySignatureBls48581.Bitmask)

				if tt.update.PublicKeySignatureBls48581.PublicKey != nil {
					assert.NotNil(t, update2.PublicKeySignatureBls48581.PublicKey)
					assert.Equal(t, tt.update.PublicKeySignatureBls48581.PublicKey.KeyValue, update2.PublicKeySignatureBls48581.PublicKey.KeyValue)
				} else {
					assert.Nil(t, update2.PublicKeySignatureBls48581.PublicKey)
				}
			} else {
				assert.Nil(t, update2.PublicKeySignatureBls48581)
			}
		})
	}
}
