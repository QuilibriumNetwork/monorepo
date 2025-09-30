package hypergraph_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
)

// TODO[2.1.1]: Vertex add serialization fuzz test

// FuzzVertexRemoveSerialization tests VertexRemove serialization/deserialization
func FuzzVertexRemoveSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 114))
	f.Add(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0xbb}, 32), make([]byte, 114))

	f.Fuzz(func(t *testing.T, domain, dataAddress, signature []byte) {
		if len(domain) != 32 || len(dataAddress) != 32 {
			return
		}

		// Create vertex remove with fuzz data
		vertexRemove := &hypergraph.VertexRemove{}
		copy(vertexRemove.Domain[:], domain)
		copy(vertexRemove.DataAddress[:], dataAddress)
		vertexRemove.Signature = signature

		// Serialize
		data, err := vertexRemove.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		vertexRemove2 := &hypergraph.VertexRemove{}
		err = vertexRemove2.FromBytes(
			data,
			nil,
			nil,
			nil,
		)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			if len(vertexRemove.Domain) != 0 || len(vertexRemove2.Domain) != 0 {
				require.Equal(t, vertexRemove.Domain, vertexRemove2.Domain)
			}
			if len(vertexRemove.DataAddress) != 0 || len(vertexRemove2.DataAddress) != 0 {
				require.Equal(t, vertexRemove.DataAddress, vertexRemove2.DataAddress)
			}
			if len(vertexRemove.Signature) != 0 || len(vertexRemove2.Signature) != 0 {
				require.Equal(t, vertexRemove.Signature, vertexRemove2.Signature)
			}
		}
	})
}

// FuzzHyperedgeAddSerialization tests HyperedgeAdd serialization/deserialization
func FuzzHyperedgeAddSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 114))

	f.Fuzz(func(t *testing.T, domain, hyperedgeDomain, hyperedgeDataAddr, signature []byte) {
		if len(domain) != 32 || len(hyperedgeDomain) != 32 || len(hyperedgeDataAddr) != 32 {
			return
		}

		// Create hyperedge
		var heDomain [32]byte
		var heDataAddr [32]byte
		copy(heDomain[:], hyperedgeDomain)
		copy(heDataAddr[:], hyperedgeDataAddr)

		he := hgcrdt.NewHyperedge(heDomain, heDataAddr)

		// Add some vertices as extrinsics
		for i := 0; i < 3; i++ {
			vertexDomain := [32]byte{byte(i)}
			vertexDataAddr := [32]byte{byte(i + 10)}
			vertex := hgcrdt.NewVertex(vertexDomain, vertexDataAddr, make([]byte, 74), big.NewInt(74))
			he.AddExtrinsic(vertex)
		}

		// Create hyperedge add with fuzz data
		hyperedgeAdd := &hypergraph.HyperedgeAdd{}
		copy(hyperedgeAdd.Domain[:], domain)
		hyperedgeAdd.Value = he
		hyperedgeAdd.Signature = signature

		// Serialize
		data, err := hyperedgeAdd.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		hyperedgeAdd2 := &hypergraph.HyperedgeAdd{}
		err = hyperedgeAdd2.FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
		)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			if len(hyperedgeAdd.Domain) != 0 || len(hyperedgeAdd2.Domain) != 0 {
				require.Equal(t, hyperedgeAdd.Domain, hyperedgeAdd2.Domain)
			}
			if len(hyperedgeAdd.Signature) != 0 || len(hyperedgeAdd2.Signature) != 0 {
				require.Equal(t, hyperedgeAdd.Signature, hyperedgeAdd2.Signature)
			}
			if hyperedgeAdd.Value != nil && hyperedgeAdd2.Value != nil {
				require.Equal(t, hyperedgeAdd.Value.GetID(), hyperedgeAdd2.Value.GetID())
			}
		}
	})
}

// FuzzHyperedgeRemoveSerialization tests HyperedgeRemove serialization/deserialization
func FuzzHyperedgeRemoveSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 114))

	f.Fuzz(func(t *testing.T, domain, hyperedgeDomain, hyperedgeDataAddr, signature []byte) {
		if len(domain) != 32 || len(hyperedgeDomain) != 32 || len(hyperedgeDataAddr) != 32 {
			return
		}

		// Create hyperedge
		var heDomain [32]byte
		var heDataAddr [32]byte
		copy(heDomain[:], hyperedgeDomain)
		copy(heDataAddr[:], hyperedgeDataAddr)

		he := hgcrdt.NewHyperedge(heDomain, heDataAddr)

		// Create hyperedge remove with fuzz data
		hyperedgeRemove := &hypergraph.HyperedgeRemove{}
		copy(hyperedgeRemove.Domain[:], domain)
		hyperedgeRemove.Value = he
		hyperedgeRemove.Signature = signature

		// Serialize
		data, err := hyperedgeRemove.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		hyperedgeRemove2 := &hypergraph.HyperedgeRemove{}
		err = hyperedgeRemove2.FromBytes(
			data,
			nil,
			nil,
			nil,
		)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			if len(hyperedgeRemove.Domain) != 0 || len(hyperedgeRemove2.Domain) != 0 {
				require.Equal(t, hyperedgeRemove.Domain, hyperedgeRemove2.Domain)
			}
			if len(hyperedgeRemove.Signature) != 0 || len(hyperedgeRemove2.Signature) != 0 {
				require.Equal(t, hyperedgeRemove.Signature, hyperedgeRemove2.Signature)
			}
			if hyperedgeRemove.Value != nil && hyperedgeRemove2.Value != nil {
				require.Equal(t, hyperedgeRemove.Value.GetID(), hyperedgeRemove2.Value.GetID())
			}
		}
	})
}

// FuzzHypergraphDeployArgumentsSerialization tests HypergraphDeployArguments serialization
func FuzzHypergraphDeployArgumentsSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 57), make([]byte, 57), []byte("test schema"))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 100), make([]byte, 100), bytes.Repeat([]byte("schema"), 100))

	f.Fuzz(func(t *testing.T, readPubKey, writePubKey, rdfSchema []byte) {
		if len(rdfSchema) > 10000 { // Limit schema size
			return
		}

		// Create deploy arguments with fuzz data
		deploy := &hypergraph.HypergraphDeployArguments{
			Config: &hypergraph.HypergraphIntrinsicConfiguration{
				ReadPublicKey:  readPubKey,
				WritePublicKey: writePubKey,
			},
			RDFSchema: rdfSchema,
		}

		// Serialize
		data, err := deploy.DeployToBytes()
		if err != nil {
			return
		}

		// Deserialize
		deploy2, err := hypergraph.DeployFromBytes(data)

		// If deserialization succeeds, verify round-trip
		if err == nil && deploy2 != nil && deploy2.Config != nil {
			require.Equal(t, deploy.Config.ReadPublicKey, deploy2.Config.ReadPublicKey)
			require.Equal(t, deploy.Config.WritePublicKey, deploy2.Config.WritePublicKey)
			require.Equal(t, deploy.RDFSchema, deploy2.RDFSchema)
		}
	})
}

// FuzzHypergraphOperationTypeDetection tests operation type detection
func FuzzHypergraphOperationTypeDetection(f *testing.F) {
	// Add various type prefixes
	f.Add(uint32(hypergraph.HypergraphDeployType), []byte{})
	f.Add(uint32(hypergraph.VertexAddType), []byte{})
	f.Add(uint32(hypergraph.VertexRemoveType), []byte{})
	f.Add(uint32(hypergraph.HyperedgeAddType), []byte{})
	f.Add(uint32(hypergraph.HyperedgeRemoveType), []byte{})
	f.Add(uint32(999999), []byte{}) // Invalid type
	f.Add(uint32(0), make([]byte, 100))

	f.Fuzz(func(t *testing.T, typePrefix uint32, additionalData []byte) {
		// Create data with type prefix
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, typePrefix)
		buf.Write(additionalData)
		data := buf.Bytes()

		// Try deserializing based on type
		switch typePrefix {
		case hypergraph.HypergraphDeployType:
			_, _ = hypergraph.DeployFromBytes(data)
		case hypergraph.VertexAddType:
			obj := &hypergraph.VertexAdd{}
			_ = obj.FromBytes(
				data,
				nil,
				nil,
				nil,
				nil,
				nil,
			)
		case hypergraph.VertexRemoveType:
			obj := &hypergraph.VertexRemove{}
			_ = obj.FromBytes(
				data,
				nil,
				nil,
				nil,
			)
		case hypergraph.HyperedgeAddType:
			obj := &hypergraph.HyperedgeAdd{}
			_ = obj.FromBytes(
				data,
				nil,
				nil,
				nil,
				nil,
			)
		case hypergraph.HyperedgeRemoveType:
			obj := &hypergraph.HyperedgeRemove{}
			_ = obj.FromBytes(
				data,
				nil,
				nil,
				nil,
			)
		}

		// Test that wrong types fail appropriately
		if typePrefix != hypergraph.VertexAddType && len(data) >= 4 {
			obj := &hypergraph.VertexAdd{}
			err := obj.FromBytes(
				data,
				nil,
				nil,
				nil,
				nil,
				nil,
			)
			if typePrefix >= hypergraph.VertexAddType && typePrefix <= hypergraph.HyperedgeRemoveType {
				// Should fail for wrong but valid type
				require.Error(t, err)
			}
		}
	})
}

// FuzzDeserializationRobustness tests deserialization with completely random data
func FuzzDeserializationRobustness(f *testing.F) {
	// Add various malformed inputs
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01}) // Just type prefix
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // Invalid type
	f.Add(bytes.Repeat([]byte{0x00}, 1000))
	f.Add(bytes.Repeat([]byte{0xff}, 1000))

	// Add some structured but potentially malformed data
	for i := uint32(1); i <= 5; i++ {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, i)
		buf.Write(bytes.Repeat([]byte{0x41}, 100))
		f.Add(buf.Bytes())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test all deserialization functions with random data
		// They should either succeed or fail gracefully without panicking

		// Test deploy
		_, _ = hypergraph.DeployFromBytes(data)

		// Test vertex operations
		vertexAdd := &hypergraph.VertexAdd{}
		_ = vertexAdd.FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
			nil,
		)

		vertexRemove := &hypergraph.VertexRemove{}
		_ = vertexRemove.FromBytes(
			data,
			nil,
			nil,
			nil,
		)

		// Test hyperedge operations
		hyperedgeAdd := &hypergraph.HyperedgeAdd{}
		_ = hyperedgeAdd.FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
		)

		hyperedgeRemove := &hypergraph.HyperedgeRemove{}
		_ = hyperedgeRemove.FromBytes(
			data,
			nil,
			nil,
			nil,
		)
	})
}

func FuzzVertexRemove_Deserialization(f *testing.F) {
	// Add valid case
	validVertexRemove := &hypergraph.VertexRemove{
		Domain:      [32]byte{1, 2, 3},
		DataAddress: [32]byte{4, 5, 6},
		Signature:   make([]byte, 114),
	}
	validData, _ := validVertexRemove.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		vertexRemove := &hypergraph.VertexRemove{}
		_ = vertexRemove.FromBytes(
			data,
			nil,
			nil,
			nil,
		) // Should not panic
	})
}

func FuzzHyperedgeAdd_Deserialization(f *testing.F) {
	// Add valid case
	he := hgcrdt.NewHyperedge([32]byte{1}, [32]byte{2})
	validHyperedgeAdd := &hypergraph.HyperedgeAdd{
		Domain:    [32]byte{3, 4, 5},
		Value:     he,
		Signature: make([]byte, 114),
	}
	validData, _ := validHyperedgeAdd.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		hyperedgeAdd := &hypergraph.HyperedgeAdd{}
		_ = hyperedgeAdd.FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
		) // Should not panic
	})
}

func FuzzHyperedgeRemove_Deserialization(f *testing.F) {
	// Add valid case
	he := hgcrdt.NewHyperedge([32]byte{1}, [32]byte{2})
	validHyperedgeRemove := &hypergraph.HyperedgeRemove{
		Domain:    [32]byte{3, 4, 5},
		Value:     he,
		Signature: make([]byte, 114),
	}
	validData, _ := validHyperedgeRemove.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		hyperedgeRemove := &hypergraph.HyperedgeRemove{}
		_ = hyperedgeRemove.FromBytes(
			data,
			nil,
			nil,
			nil,
		) // Should not panic
	})
}

func FuzzHypergraphDeploy_Deserialization(f *testing.F) {
	// Add valid case
	validDeploy := &hypergraph.HypergraphDeployArguments{
		Config: &hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
		},
		RDFSchema: []byte("test schema"),
	}
	validData, _ := validDeploy.DeployToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	// Add invalid key lengths
	f.Add([]byte{0x00, 0x00, 0x00, 0x04, // Type prefix
		0x00, 0x00, 0x00, 0x10, // Invalid read key length (16 instead of 57)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}) // 16 bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		_, _ = hypergraph.DeployFromBytes(data) // Should not panic
	})
}

func FuzzMixedTypeDeserialization(f *testing.F) {
	// Add valid prefixes for each type
	types := []uint32{
		hypergraph.HypergraphDeployType,
		hypergraph.VertexAddType,
		hypergraph.VertexRemoveType,
		hypergraph.HyperedgeAddType,
		hypergraph.HyperedgeRemoveType,
	}

	for _, typ := range types {
		data := make([]byte, 4)
		data[0] = byte(typ >> 24)
		data[1] = byte(typ >> 16)
		data[2] = byte(typ >> 8)
		data[3] = byte(typ)
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		// Try deserializing as each type - should handle gracefully
		_, _ = hypergraph.DeployFromBytes(data)
		_ = (&hypergraph.VertexAdd{}).FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
			nil,
		)
		_ = (&hypergraph.VertexRemove{}).FromBytes(
			data,
			nil,
			nil,
			nil,
		)
		_ = (&hypergraph.HyperedgeAdd{}).FromBytes(
			data,
			nil,
			nil,
			nil,
			nil,
		)
		_ = (&hypergraph.HyperedgeRemove{}).FromBytes(
			data,
			nil,
			nil,
			nil,
		)
	})
}

func FuzzTreeDataHandling(f *testing.F) {
	// Add various tree data sizes
	f.Add([]byte{}, uint32(0))
	f.Add(make([]byte, 100), uint32(100))
	f.Add(make([]byte, 1000), uint32(1000))
	f.Add(make([]byte, 100), uint32(1000000)) // Length mismatch

	f.Fuzz(func(t *testing.T, treeData []byte, declaredLength uint32) {
		// Create vertex add with potentially mismatched tree data
		buf := new(bytes.Buffer)

		// Write type
		binary.Write(buf, binary.BigEndian, uint32(hypergraph.VertexAddType))

		// Write domain and data address
		buf.Write(make([]byte, 32))
		buf.Write(make([]byte, 32))

		// Write tree data with declared length
		binary.Write(buf, binary.BigEndian, declaredLength)
		buf.Write(treeData) // May not match declared length

		// Write signature length and data
		binary.Write(buf, binary.BigEndian, uint32(114))
		buf.Write(make([]byte, 114))

		// Try to deserialize
		vertexAdd := &hypergraph.VertexAdd{}
		_ = vertexAdd.FromBytes(
			buf.Bytes(),
			nil,
			nil,
			nil,
			nil,
			nil,
		)
	})
}

func FuzzHyperedgeExtrinsicsHandling(f *testing.F) {
	// Add various numbers of extrinsics
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(1), uint32(100))
	f.Add(uint32(10), uint32(1000))
	f.Add(uint32(1000), uint32(100)) // Many extrinsics, small data

	f.Fuzz(func(t *testing.T, numExtrinsics, extrinsicDataSize uint32) {
		// Limit to reasonable values
		if numExtrinsics > 1000 || extrinsicDataSize > 10000 {
			return
		}

		// Create hyperedge with fuzz number of extrinsics
		buf := new(bytes.Buffer)

		// Write type
		binary.Write(buf, binary.BigEndian, uint32(hypergraph.HyperedgeAddType))

		// Write domain
		buf.Write(make([]byte, 32))

		// Write hyperedge data
		// This would include the extrinsics tree serialization
		// For fuzzing, we'll write simplified data
		binary.Write(buf, binary.BigEndian, numExtrinsics)
		for i := uint32(0); i < min32(numExtrinsics, 100); i++ {
			buf.Write(make([]byte, min32(extrinsicDataSize, 1000)))
		}

		// Write signature
		binary.Write(buf, binary.BigEndian, uint32(114))
		buf.Write(make([]byte, 114))

		// Try to deserialize
		hyperedgeAdd := &hypergraph.HyperedgeAdd{}
		_ = hyperedgeAdd.FromBytes(
			buf.Bytes(),
			nil,
			nil,
			nil,
			nil,
		)
	})
}

func FuzzLengthOverflows(f *testing.F) {
	// Add cases with large length values
	f.Add(uint32(0xFFFFFFFF), uint32(0xFFFFFFFF))
	f.Add(uint32(1<<31), uint32(1<<31))
	f.Add(uint32(1000000), uint32(1000000))

	f.Fuzz(func(t *testing.T, len1, len2 uint32) {
		// Create data with potentially overflowing lengths
		buf := new(bytes.Buffer)

		// Write type prefix
		binary.Write(buf, binary.BigEndian, uint32(hypergraph.VertexAddType))

		// Write domain and data address
		buf.Write(make([]byte, 32))
		buf.Write(make([]byte, 32))

		// Write tree data with large length
		binary.Write(buf, binary.BigEndian, len1)
		// Don't actually write that much data
		buf.Write(make([]byte, min(int(len1), 100)))

		// Write signature length
		binary.Write(buf, binary.BigEndian, len2)
		buf.Write(make([]byte, min(int(len2), 100)))

		// Try to deserialize - should handle gracefully
		vertexAdd := &hypergraph.VertexAdd{}
		_ = vertexAdd.FromBytes(
			buf.Bytes(),
			nil,
			nil,
			nil,
			nil,
			nil,
		)
	})
}

func FuzzInvalidPublicKeyLengths(f *testing.F) {
	// Add cases with invalid public key lengths
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(1), uint32(57))
	f.Add(uint32(57), uint32(1))
	f.Add(uint32(100), uint32(100))
	f.Add(uint32(0xFFFFFFFF), uint32(57))

	f.Fuzz(func(t *testing.T, readKeyLen, writeKeyLen uint32) {
		// Create deploy data with invalid key lengths
		buf := new(bytes.Buffer)

		// Write type prefix
		binary.Write(buf, binary.BigEndian, uint32(hypergraph.HypergraphDeployType))

		// Write read public key with invalid length
		binary.Write(buf, binary.BigEndian, readKeyLen)
		buf.Write(make([]byte, min(int(readKeyLen), 1000)))

		// Write write public key with invalid length
		binary.Write(buf, binary.BigEndian, writeKeyLen)
		buf.Write(make([]byte, min(int(writeKeyLen), 1000)))

		// Write schema
		binary.Write(buf, binary.BigEndian, uint32(10))
		buf.Write([]byte("test schema"))

		// Try to deserialize - should handle gracefully
		_, _ = hypergraph.DeployFromBytes(buf.Bytes())
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
