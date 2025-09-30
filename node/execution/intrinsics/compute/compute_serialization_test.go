package compute

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestComputeDeploySerialization(t *testing.T) {
	tests := []struct {
		name string
		args *ComputeDeploy
	}{
		{
			name: "Full arguments",
			args: &ComputeDeploy{
				Config: &ComputeIntrinsicConfiguration{
					ReadPublicKey:  bytes.Repeat([]byte{0x01}, 57),
					WritePublicKey: bytes.Repeat([]byte{0x02}, 57),
					OwnerPublicKey: bytes.Repeat([]byte{0x03}, 585),
				},
				RDFSchema: []byte("@prefix : <http://example.org/> ."),
			},
		},
		{
			name: "Empty keys",
			args: &ComputeDeploy{
				Config: &ComputeIntrinsicConfiguration{
					ReadPublicKey:  []byte{},
					WritePublicKey: []byte{},
					OwnerPublicKey: []byte{},
				},
				RDFSchema: []byte("schema"),
			},
		},
		{
			name: "Nil keys",
			args: &ComputeDeploy{
				Config: &ComputeIntrinsicConfiguration{
					ReadPublicKey:  nil,
					WritePublicKey: nil,
					OwnerPublicKey: nil,
				},
				RDFSchema: []byte("schema"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := tt.args.DeployToBytes()
			if err != nil {
				t.Fatalf("DeployToBytes() error = %v", err)
			}

			// Deserialize
			result, err := DeployFromBytes(data)
			if err != nil {
				t.Fatalf("DeployFromBytes() error = %v", err)
			}

			// Compare
			if !bytes.Equal(result.Config.ReadPublicKey, tt.args.Config.ReadPublicKey) {
				t.Errorf("ReadPublicKey mismatch: got %v, want %v", result.Config.ReadPublicKey, tt.args.Config.ReadPublicKey)
			}
			if !bytes.Equal(result.Config.WritePublicKey, tt.args.Config.WritePublicKey) {
				t.Errorf("WritePublicKey mismatch: got %v, want %v", result.Config.WritePublicKey, tt.args.Config.WritePublicKey)
			}
			if !bytes.Equal(result.Config.OwnerPublicKey, tt.args.Config.OwnerPublicKey) {
				t.Errorf("OwnerPublicKey mismatch: got %v, want %v", result.Config.OwnerPublicKey, tt.args.Config.OwnerPublicKey)
			}
			if !bytes.Equal(result.RDFSchema, tt.args.RDFSchema) {
				t.Errorf("RDFSchema mismatch: got %v, want %v", result.RDFSchema, tt.args.RDFSchema)
			}
		})
	}
}

func TestComputeDeployInvalidType(t *testing.T) {
	// Create data with wrong type prefix
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(999)) // Invalid type

	_, err := DeployFromBytes(buf.Bytes())
	if err == nil {
		t.Error("Expected error for invalid type prefix, got nil")
	}
}

func TestComputeDeployEmptySchema(t *testing.T) {
	args := &ComputeDeploy{
		Config: &ComputeIntrinsicConfiguration{
			ReadPublicKey:  bytes.Repeat([]byte{0x01}, 57),
			WritePublicKey: bytes.Repeat([]byte{0x02}, 57),
			OwnerPublicKey: bytes.Repeat([]byte{0x03}, 585),
		},
		RDFSchema: []byte{}, // Empty schema
	}

	data, err := args.DeployToBytes()
	if err != nil {
		t.Fatalf("DeployToBytes() error = %v", err)
	}

	_, err = DeployFromBytes(data)
	if err == nil {
		t.Error("Expected error for empty schema, got nil")
	}
}
