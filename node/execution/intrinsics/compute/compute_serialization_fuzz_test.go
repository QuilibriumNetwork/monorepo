package compute_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// FuzzComputeDeploySerialization tests ComputeDeploy serialization
func FuzzComputeDeploySerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 57), make([]byte, 57), make([]byte, 585), []byte(`BASE <https://types.quilibrium.com/schema-repository/>
	PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
	PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
	PREFIX qcl: <https://types.quilibrium.com/qcl/>
	PREFIX req: <https://types.quilibrium.com/schema-repository/example/a/>
	
	req:Request a rdfs:Class.
	req:A a rdfs:Property;
		rdfs:domain qcl:Uint;
		qcl:size 1;
		qcl:order 0;
		rdfs:range req:Request.
	`))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 100), make([]byte, 100), make([]byte, 100), []byte("bananaphone"))
	f.Add(make([]byte, 57), make([]byte, 57), make([]byte, 585), bytes.Repeat([]byte("code"), 100))

	f.Fuzz(func(t *testing.T, readPubKey, writePubKey, ownerPubKey, rdfSchema []byte) {
		// Limit sizes to avoid memory issues
		if len(rdfSchema) > 100000 {
			return
		}

		// Create deploy arguments with fuzz data
		deploy := &compute.ComputeDeploy{
			Config: &compute.ComputeIntrinsicConfiguration{
				ReadPublicKey:  readPubKey,
				WritePublicKey: writePubKey,
				OwnerPublicKey: ownerPubKey,
			},
			RDFSchema: rdfSchema,
		}

		// Serialize
		data, err := deploy.DeployToBytes()
		if err != nil {
			return
		}

		// Deserialize
		deploy2, err := compute.DeployFromBytes(data)

		// If deserialization succeeds, verify round-trip
		if err == nil && deploy2 != nil {
			if len(deploy.Config.ReadPublicKey) != 0 || len(deploy2.Config.ReadPublicKey) != 0 {
				require.Equal(t, deploy.Config.ReadPublicKey, deploy2.Config.ReadPublicKey)
			}
			if len(deploy.Config.WritePublicKey) != 0 || len(deploy2.Config.WritePublicKey) != 0 {
				require.Equal(t, deploy.Config.WritePublicKey, deploy2.Config.WritePublicKey)
			}
			if len(deploy.Config.OwnerPublicKey) != 0 || len(deploy2.Config.OwnerPublicKey) != 0 {
				require.Equal(t, deploy.Config.OwnerPublicKey, deploy2.Config.OwnerPublicKey)
			}
			if len(deploy.RDFSchema) != 0 || len(deploy2.RDFSchema) != 0 {
				require.Equal(t, deploy.RDFSchema, deploy2.RDFSchema)
			}
		}
	})
}

// FuzzCodeDeploymentSerialization tests CodeDeployment serialization
func FuzzCodeDeploymentSerialization(f *testing.F) {
	// Add seed corpus
	// simple 32-byte width xor circuit:
	xor, _ := hex.DecodeString("63726300000001030000014300000002000000010000000464617461000000075b5d75696e74380000002000000000000000056f74686572000000075b5d75696e743800000020000000000000001225726574307b312c317d736c696365323536000000075b5d75696e74380000010000000000040000000000000040000000000000000020000000430000000001000000210000004400000000020000002200000045000000000300000023000000460000000004000000240000004700000000050000002500000048000000000600000026000000490000000007000000270000004a0000000008000000280000004b0000000009000000290000004c000000000a0000002a0000004d000000000b0000002b0000004e000000000c0000002c0000004f000000000d0000002d00000050000000000e0000002e00000051000000000f0000002f00000052000000001000000030000000530000000011000000310000005400000000120000003200000055000000001300000033000000560000000014000000340000005700000000150000003500000058000000001600000036000000590000000017000000370000005a0000000018000000380000005b0000000019000000390000005c000000001a0000003a0000005d000000001b0000003b0000005e000000001c0000003c0000005f000000001d0000003d00000060000000001e0000003e00000061000000001f0000003f000000620200000000000000400000004103000000000000004000000042000000004100000041000000630000000041000000410000006400000000410000004100000065000000004100000041000000660000000041000000410000006700000000410000004100000068000000004100000041000000690000000041000000410000006a0000000041000000410000006b0000000041000000410000006c0000000041000000410000006d0000000041000000410000006e0000000041000000410000006f000000004100000041000000700000000041000000410000007100000000410000004100000072000000004100000041000000730000000041000000410000007400000000410000004100000075000000004100000041000000760000000041000000410000007700000000410000004100000078000000004100000041000000790000000041000000410000007a0000000041000000410000007b0000000041000000410000007c0000000041000000410000007d0000000041000000410000007e0000000041000000410000007f000000004100000041000000800000000041000000410000008100000000410000004100000082000000004100000041000000830000000041000000410000008400000000410000004100000085000000004100000041000000860000000041000000410000008700000000410000004100000088000000004100000041000000890000000041000000410000008a0000000041000000410000008b0000000041000000410000008c0000000041000000410000008d0000000041000000410000008e0000000041000000410000008f000000004100000041000000900000000041000000410000009100000000410000004100000092000000004100000041000000930000000041000000410000009400000000410000004100000095000000004100000041000000960000000041000000410000009700000000410000004100000098000000004100000041000000990000000041000000410000009a0000000041000000410000009b0000000041000000410000009c0000000041000000410000009d0000000041000000410000009e0000000041000000410000009f000000004100000041000000a0000000004100000041000000a1000000004100000041000000a2000000004100000041000000a3000000004100000041000000a4000000004100000041000000a5000000004100000041000000a6000000004100000041000000a7000000004100000041000000a8000000004100000041000000a9000000004100000041000000aa000000004100000041000000ab000000004100000041000000ac000000004100000041000000ad000000004100000041000000ae000000004100000041000000af000000004100000041000000b0000000004100000041000000b1000000004100000041000000b2000000004100000041000000b3000000004100000041000000b4000000004100000041000000b5000000004100000041000000b6000000004100000041000000b7000000004100000041000000b8000000004100000041000000b9000000004100000041000000ba000000004100000041000000bb000000004100000041000000bc000000004100000041000000bd000000004100000041000000be000000004100000041000000bf000000004100000041000000c0000000004100000041000000c1000000004100000041000000c2000000004100000041000000c3000000004100000041000000c4000000004100000041000000c5000000004100000041000000c6000000004100000041000000c7000000004100000041000000c8000000004100000041000000c9000000004100000041000000ca000000004100000041000000cb000000004100000041000000cc000000004100000041000000cd000000004100000041000000ce000000004100000041000000cf000000004100000041000000d0000000004100000041000000d1000000004100000041000000d2000000004100000041000000d3000000004100000041000000d4000000004100000041000000d5000000004100000041000000d6000000004100000041000000d7000000004100000041000000d8000000004100000041000000d9000000004100000041000000da000000004100000041000000db000000004100000041000000dc000000004100000041000000dd000000004100000041000000de000000004100000041000000df000000004100000041000000e0000000004100000041000000e1000000004100000041000000e2000000004100000041000000e3000000004100000041000000e4000000004100000041000000e5000000004100000041000000e6000000004100000041000000e7000000004100000041000000e8000000004100000041000000e9000000004100000041000000ea000000004100000041000000eb000000004100000041000000ec000000004100000041000000ed000000004100000041000000ee000000004100000041000000ef000000004100000041000000f0000000004100000041000000f1000000004100000041000000f2000000004100000041000000f3000000004100000041000000f4000000004100000041000000f5000000004100000041000000f6000000004100000041000000f7000000004100000041000000f8000000004100000041000000f9000000004100000041000000fa000000004100000041000000fb000000004100000041000000fc000000004100000041000000fd000000004100000041000000fe000000004100000041000000ff000000004100000041000001000000000041000000410000010100000000410000004100000102000000004100000041000001030000000041000000410000010400000000410000004100000105000000004100000041000001060000000041000000410000010700000000410000004100000108000000004100000041000001090000000041000000410000010a0000000041000000410000010b0000000041000000410000010c0000000041000000410000010d0000000041000000410000010e0000000041000000410000010f000000004100000041000001100000000041000000410000011100000000410000004100000112000000004100000041000001130000000041000000410000011400000000410000004100000115000000004100000041000001160000000041000000410000011700000000410000004100000118000000004100000041000001190000000041000000410000011a0000000041000000410000011b0000000041000000410000011c0000000041000000410000011d0000000041000000410000011e0000000041000000410000011f000000004100000041000001200000000041000000410000012100000000410000004100000122000000004100000041000001230000000041000000410000012400000000410000004100000125000000004100000041000001260000000041000000410000012700000000410000004100000128000000004100000041000001290000000041000000410000012a0000000041000000410000012b0000000041000000410000012c0000000041000000410000012d0000000041000000410000012e0000000041000000410000012f000000004100000041000001300000000041000000410000013100000000410000004100000132000000004100000041000001330000000041000000410000013400000000410000004100000135000000004100000041000001360000000041000000410000013700000000410000004100000138000000004100000041000001390000000041000000410000013a0000000041000000410000013b0000000041000000410000013c0000000041000000410000013d0000000041000000410000013e0000000041000000410000013f000000004100000041000001400000000041000000410000014100000000410000004100000142")
	f.Add(make([]byte, 32), xor, "qcl:ByteArray;qcl:ByteArray", "qcl:ByteArray")
	f.Add(make([]byte, 32), []byte{}, "waffleiron", "waffleiron")
	f.Add(bytes.Repeat([]byte{0xaa}, 32), bytes.Repeat([]byte("aa"), 500), "", "")

	f.Fuzz(func(t *testing.T, domain, circuit []byte, inputTypes string, outputTypes string) {
		if len(domain) != 32 {
			return
		}
		if len(circuit) > 100000 { // Limit code size
			return
		}

		// Create code deployment with fuzz data
		deployment := &compute.CodeDeployment{}
		copy(deployment.Domain[:], domain)
		deployment.Circuit = circuit
		// Handle InputTypes split
		inputParts := strings.Split(inputTypes, ";")
		if len(inputParts) >= 2 {
			deployment.InputTypes[0] = inputParts[0]
			deployment.InputTypes[1] = inputParts[1]
		} else if len(inputParts) == 1 {
			deployment.InputTypes[0] = inputParts[0]
			deployment.InputTypes[1] = ""
		}

		deployment.OutputTypes = strings.Split(outputTypes, ";")

		// Serialize
		data, err := deployment.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		deployment2 := &compute.CodeDeployment{}
		err = deployment2.FromBytes(data, nil)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			require.Equal(t, deployment.Domain, deployment2.Domain)
			// Handle nil vs empty slice for Circuit
			if len(deployment.Circuit) == 0 && len(deployment2.Circuit) == 0 {
				// Both empty, OK
			} else {
				require.Equal(t, deployment.Circuit, deployment2.Circuit)
			}
			require.Equal(t, deployment.InputTypes, deployment2.InputTypes)
			require.Equal(t, deployment.OutputTypes, deployment2.OutputTypes)
		}
	})
}

// FuzzCodeExecuteSerialization tests CodeExecute serialization
func FuzzCodeExecuteSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 100), make([]byte, 100))
	f.Add(make([]byte, 32), make([]byte, 32), []byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0xaa}, 32), make([]byte, 200), make([]byte, 200))

	f.Fuzz(func(t *testing.T, domain, rendezvous, pop0, pop1 []byte) {
		if len(domain) != 32 || len(rendezvous) != 32 {
			return
		}
		if len(pop0) > 100000 || len(pop1) > 100000 { // Limit sizes
			return
		}

		// Create code execute with fuzz data
		execute := &compute.CodeExecute{}
		copy(execute.Domain[:], domain)
		copy(execute.Rendezvous[:], rendezvous)
		execute.ProofOfPayment = [2][]byte{pop0, pop1}
		execute.ExecuteOperations = []*compute.ExecuteOperation{}

		// Serialize
		data, err := execute.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		execute2 := &compute.CodeExecute{}
		err = execute2.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			require.Equal(t, execute.Domain, execute2.Domain)
			require.Equal(t, execute.Rendezvous, execute2.Rendezvous)
			require.Equal(t, execute.ProofOfPayment, execute2.ProofOfPayment)
			require.Equal(t, len(execute.ExecuteOperations), len(execute2.ExecuteOperations))
		}
	})
}

// FuzzComputeOperationTypeDetection tests operation type detection
func FuzzComputeOperationTypeDetection(f *testing.F) {
	// Add various type prefixes
	f.Add(uint32(protobufs.ComputeDeploymentType), []byte{})
	f.Add(uint32(protobufs.CodeDeploymentType), []byte{})
	f.Add(uint32(protobufs.CodeExecuteType), []byte{})
	f.Add(uint32(999999), []byte{}) // Invalid type
	f.Add(uint32(0), make([]byte, 100))
	f.Add(uint32(^uint32(0)), make([]byte, 50))

	f.Fuzz(func(t *testing.T, typePrefix uint32, additionalData []byte) {
		// Create data with type prefix
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, typePrefix)
		buf.Write(additionalData)
		data := buf.Bytes()

		// Try deserializing based on type
		switch typePrefix {
		case protobufs.ComputeDeploymentType:
			_, _ = compute.DeployFromBytes(data)
		case protobufs.CodeDeploymentType:
			obj := &compute.CodeDeployment{}
			_ = obj.FromBytes(data, nil)
		case protobufs.CodeExecuteType:
			obj := &compute.CodeExecute{}
			_ = obj.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)
		}

		// Test that wrong types fail appropriately
		if typePrefix != protobufs.CodeDeploymentType && len(data) >= 4 {
			obj := &compute.CodeDeployment{}
			err := obj.FromBytes(data, nil)
			if typePrefix >= protobufs.ComputeDeploymentType && typePrefix <= protobufs.CodeExecuteType && typePrefix != protobufs.CodeFinalizeType {
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
	for i := uint32(1); i <= 3; i++ {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, i)
		buf.Write(bytes.Repeat([]byte{0x41}, 100))
		f.Add(buf.Bytes())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test all deserialization functions with random data
		// They should either succeed or fail gracefully without panicking

		// Test deploy
		_, _ = compute.DeployFromBytes(data)

		// Test code deployment
		deployment := &compute.CodeDeployment{}
		_ = deployment.FromBytes(data, nil)

		// Test code execute
		execute := &compute.CodeExecute{}
		_ = execute.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)
	})
}

// FuzzLengthOverflows tests handling of length field overflows
func FuzzLengthOverflows(f *testing.F) {
	// Add cases with large length values
	f.Add(uint32(0xFFFFFFFF), uint32(0xFFFFFFFF), uint32(0xFFFFFFFF))
	f.Add(uint32(1<<31), uint32(1<<31), uint32(1<<31))
	f.Add(uint32(1000000), uint32(1000000), uint32(1000000))
	f.Add(uint32(1), uint32(2), uint32(3))

	f.Fuzz(func(t *testing.T, codeLen, invocationLen, contextLen uint32) {
		// Create CodeExecute with potentially overflowing lengths
		buf := new(bytes.Buffer)

		// Write type prefix
		binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeExecuteType))

		// Write domain
		buf.Write(make([]byte, 32))

		// Write rendezvous
		buf.Write(make([]byte, 32))

		// Write ProofOfPayment[0] with large length
		binary.Write(buf, binary.BigEndian, invocationLen)
		// Don't actually write that much data
		buf.Write(make([]byte, min(int(invocationLen), 100)))

		// Write ProofOfPayment[1] with large length
		binary.Write(buf, binary.BigEndian, contextLen)
		buf.Write(make([]byte, min(int(contextLen), 100)))

		// Write ExecuteOperations count
		binary.Write(buf, binary.BigEndian, uint32(0))

		// Try to deserialize - should handle gracefully
		execute := &compute.CodeExecute{}
		_ = execute.FromBytes(buf.Bytes(), nil, nil, nil, nil, nil, nil, nil)
	})
}

// FuzzCodeDataValidation tests various code data patterns
func FuzzCodeDataValidation(f *testing.F) {
	// Add various code patterns
	f.Add([]byte("function() {}"), []byte("{}"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("\x00\x00\x00\x00"), []byte("\xff\xff\xff\xff"))
	f.Add([]byte("import os; os.system('bad')"), []byte("{}"))
	f.Add(bytes.Repeat([]byte("A"), 1000), []byte("null"))

	f.Fuzz(func(t *testing.T, code, context []byte) {
		if len(code) > 100000 || len(context) > 100000 {
			return
		}

		// Test with CodeDeployment
		deployment := &compute.CodeDeployment{
			Circuit:     code,
			InputTypes:  [2]string{"test", "test"},
			OutputTypes: []string{"test"},
		}
		copy(deployment.Domain[:], make([]byte, 32))

		data, err := deployment.ToBytes()
		if err == nil {
			deployment2 := &compute.CodeDeployment{}
			err2 := deployment2.FromBytes(data, nil)
			if err2 == nil {
				// Handle nil vs empty slice for Circuit
				if len(deployment.Circuit) == 0 && len(deployment2.Circuit) == 0 {
					// Both empty, OK
				} else {
					require.Equal(t, deployment.Circuit, deployment2.Circuit)
				}
			}
		}

		// Test with CodeExecute
		execute := &compute.CodeExecute{
			ProofOfPayment:    [2][]byte{code, context},
			ExecuteOperations: []*compute.ExecuteOperation{},
		}
		copy(execute.Domain[:], make([]byte, 32))
		copy(execute.Rendezvous[:], make([]byte, 32))

		data, err = execute.ToBytes()
		if err == nil {
			execute2 := &compute.CodeExecute{}
			err2 := execute2.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)
			if err2 == nil {
				require.Equal(t, execute.ProofOfPayment[0], execute2.ProofOfPayment[0])
				require.Equal(t, execute.ProofOfPayment[1], execute2.ProofOfPayment[1])
			}
		}
	})
}

// FuzzNilFieldHandling tests handling of nil/empty fields
func FuzzNilFieldHandling(f *testing.F) {
	// Add cases with various nil/empty combinations
	f.Add(true, true, true, true)
	f.Add(true, true, true, false)
	f.Add(true, true, false, true)
	f.Add(true, true, false, false)
	f.Add(true, false, true, true)
	f.Add(true, false, true, false)
	f.Add(true, false, false, true)
	f.Add(true, false, false, false)
	f.Add(false, true, true, true)
	f.Add(false, true, true, false)
	f.Add(false, true, false, true)
	f.Add(false, true, false, false)
	f.Add(false, false, true, true)
	f.Add(false, false, true, false)
	f.Add(false, false, false, true)
	f.Add(false, false, false, false)

	f.Fuzz(func(t *testing.T, hasReadKey, hasWriteKey, hasOwnerKey, hasSchema bool) {
		deploy := &compute.ComputeDeploy{
			Config: &compute.ComputeIntrinsicConfiguration{},
		}

		if hasReadKey {
			deploy.Config.ReadPublicKey = make([]byte, 57)
		}
		if hasWriteKey {
			deploy.Config.WritePublicKey = make([]byte, 57)
		}
		if hasOwnerKey {
			deploy.Config.OwnerPublicKey = make([]byte, 585)
		}
		if hasSchema {
			deploy.RDFSchema = []byte("test schema")
		} else {
			// RDFSchema is required to be non-empty
			deploy.RDFSchema = []byte("x")
		}

		// Serialize
		data, err := deploy.DeployToBytes()
		if err != nil {
			return
		}

		// Deserialize
		deploy2, err := compute.DeployFromBytes(data)
		if err == nil && deploy2 != nil {
			if hasReadKey {
				require.Equal(t, deploy.Config.ReadPublicKey, deploy2.Config.ReadPublicKey)
			}
			if hasWriteKey {
				require.Equal(t, deploy.Config.WritePublicKey, deploy2.Config.WritePublicKey)
			}
			if hasOwnerKey {
				require.Equal(t, deploy.Config.OwnerPublicKey, deploy2.Config.OwnerPublicKey)
			}
			require.Equal(t, deploy.RDFSchema, deploy2.RDFSchema)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FuzzComputeDeployDeserialization specifically tests DeployFromBytes robustness
func FuzzComputeDeployDeserialization(f *testing.F) {
	// Add valid cases
	validDeploy := &compute.ComputeDeploy{
		Config: &compute.ComputeIntrinsicConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
			OwnerPublicKey: make([]byte, 585),
		},
		RDFSchema: []byte("test schema"),
	}
	validData, _ := validDeploy.DeployToBytes()
	f.Add(validData)

	// Add truncated valid data at various points
	for i := 0; i < len(validData) && i < 20; i++ {
		f.Add(validData[:i])
	}

	// Add malformed type prefix cases
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(99999)) // Invalid type
	buf.Write(make([]byte, 100))
	f.Add(buf.Bytes())

	// Add cases with invalid lengths
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.ComputeDeploymentType))
	binary.Write(buf, binary.BigEndian, uint32(0xFFFFFFFF)) // Huge length for read key
	f.Add(buf.Bytes())

	// Add empty schema case
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.ComputeDeploymentType))
	binary.Write(buf, binary.BigEndian, uint32(57))
	buf.Write(make([]byte, 57))
	binary.Write(buf, binary.BigEndian, uint32(57))
	buf.Write(make([]byte, 57))
	binary.Write(buf, binary.BigEndian, uint32(0)) // Empty schema
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := compute.DeployFromBytes(data)

		// If it succeeds, verify the result is valid
		if err == nil && result != nil {
			// Verify keys are either nil/empty or 57 bytes
			if len(result.Config.ReadPublicKey) > 0 {
				require.Equal(t, 57, len(result.Config.ReadPublicKey))
			}
			if len(result.Config.WritePublicKey) > 0 {
				require.Equal(t, 57, len(result.Config.WritePublicKey))
			}
			if len(result.Config.OwnerPublicKey) > 0 {
				require.Equal(t, 585, len(result.Config.OwnerPublicKey))
			}
			// Schema must not be empty
			require.NotEmpty(t, result.RDFSchema)

			// Verify round-trip works
			data2, err2 := result.DeployToBytes()
			require.NoError(t, err2)
			result2, err3 := compute.DeployFromBytes(data2)
			require.NoError(t, err3)
			require.Equal(t, result.Config.ReadPublicKey, result2.Config.ReadPublicKey)
			require.Equal(t, result.Config.WritePublicKey, result2.Config.WritePublicKey)
			require.Equal(t, result.Config.OwnerPublicKey, result2.Config.OwnerPublicKey)
			require.Equal(t, result.RDFSchema, result2.RDFSchema)
		}
	})
}

// FuzzCodeDeploymentDeserialization specifically tests CodeDeployment.FromBytes robustness
func FuzzCodeDeploymentDeserialization(f *testing.F) {
	// Add valid case
	validDeployment := &compute.CodeDeployment{
		Circuit:     []byte("test circuit"),
		InputTypes:  [2]string{"type1", "type2"},
		OutputTypes: []string{"output1", "output2"},
	}
	copy(validDeployment.Domain[:], make([]byte, 32))
	validData, _ := validDeployment.ToBytes()
	f.Add(validData)

	// Add truncated valid data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	// Add wrong type prefix
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeExecuteType)) // Wrong type
	buf.Write(make([]byte, 100))
	f.Add(buf.Bytes())

	// Add cases with huge string lengths
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeDeploymentType))
	buf.Write(make([]byte, 32))                     // Domain
	binary.Write(buf, binary.BigEndian, uint32(10)) // Circuit length
	buf.Write([]byte("circuit123"))
	binary.Write(buf, binary.BigEndian, uint32(0xFFFFFFFF)) // Huge InputTypes[0] length
	f.Add(buf.Bytes())

	// Add case with many output types
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeDeploymentType))
	buf.Write(make([]byte, 32))                        // Domain
	binary.Write(buf, binary.BigEndian, uint32(0))     // Empty circuit
	binary.Write(buf, binary.BigEndian, uint32(0))     // Empty InputTypes[0]
	binary.Write(buf, binary.BigEndian, uint32(0))     // Empty InputTypes[1]
	binary.Write(buf, binary.BigEndian, uint32(10000)) // Many output types
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		deployment := &compute.CodeDeployment{}
		err := deployment.FromBytes(data, nil)

		// If it succeeds, verify the result is valid
		if err == nil {
			// Domain should be 32 bytes
			require.Equal(t, 32, len(deployment.Domain))

			// Verify round-trip works
			data2, err2 := deployment.ToBytes()
			require.NoError(t, err2)
			deployment2 := &compute.CodeDeployment{}
			err3 := deployment2.FromBytes(data2, nil)
			require.NoError(t, err3)
			require.Equal(t, deployment.Domain, deployment2.Domain)

			// Handle nil vs empty slice
			if len(deployment.Circuit) == 0 && len(deployment2.Circuit) == 0 {
				// Both empty, OK
			} else {
				require.Equal(t, deployment.Circuit, deployment2.Circuit)
			}
			require.Equal(t, deployment.InputTypes, deployment2.InputTypes)
			require.Equal(t, deployment.OutputTypes, deployment2.OutputTypes)
		}
	})
}

// FuzzCodeExecuteDeserialization specifically tests CodeExecute.FromBytes robustness
func FuzzCodeExecuteDeserialization(f *testing.F) {
	// Add valid case
	validExecute := &compute.CodeExecute{
		ProofOfPayment: [2][]byte{[]byte("proof1"), []byte("proof2")},
		ExecuteOperations: []*compute.ExecuteOperation{
			{
				Application: compute.Application{
					Address:          []byte("app1"),
					ExecutionContext: compute.ExecutionContextIntrinsic,
				},
				Identifier:   []byte("id1"),
				Dependencies: [][]byte{[]byte("dep1"), []byte("dep2")},
			},
		},
	}
	copy(validExecute.Domain[:], make([]byte, 32))
	copy(validExecute.Rendezvous[:], make([]byte, 32))
	validData, _ := validExecute.ToBytes()
	f.Add(validData)

	// Add truncated valid data
	for i := 0; i < len(validData) && i < 100; i += 5 {
		f.Add(validData[:i])
	}

	// Add wrong type prefix
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeDeploymentType)) // Wrong type
	buf.Write(make([]byte, 100))
	f.Add(buf.Bytes())

	// Add case with huge ProofOfPayment lengths
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeExecuteType))
	buf.Write(make([]byte, 32))                             // Domain
	buf.Write(make([]byte, 32))                             // Rendezvous
	binary.Write(buf, binary.BigEndian, uint32(0xFFFFFFFF)) // Huge ProofOfPayment[0]
	f.Add(buf.Bytes())

	// Add case with many operations
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeExecuteType))
	buf.Write(make([]byte, 32))                        // Domain
	buf.Write(make([]byte, 32))                        // Rendezvous
	binary.Write(buf, binary.BigEndian, uint32(0))     // Empty ProofOfPayment[0]
	binary.Write(buf, binary.BigEndian, uint32(0))     // Empty ProofOfPayment[1]
	binary.Write(buf, binary.BigEndian, uint32(10000)) // Many operations
	f.Add(buf.Bytes())

	// Add case with malformed operation
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(protobufs.CodeExecuteType))
	buf.Write(make([]byte, 32))                             // Domain
	buf.Write(make([]byte, 32))                             // Rendezvous
	binary.Write(buf, binary.BigEndian, uint32(0))          // Empty ProofOfPayment[0]
	binary.Write(buf, binary.BigEndian, uint32(0))          // Empty ProofOfPayment[1]
	binary.Write(buf, binary.BigEndian, uint32(1))          // One operation
	binary.Write(buf, binary.BigEndian, uint32(0xFFFFFFFF)) // Huge address length
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		execute := &compute.CodeExecute{}
		err := execute.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)

		// If it succeeds, verify the result is valid
		if err == nil {
			// Domain and Rendezvous should be 32 bytes
			require.Equal(t, 32, len(execute.Domain))
			require.Equal(t, 32, len(execute.Rendezvous))

			// ProofOfPayment should have exactly 2 elements
			require.Equal(t, 2, len(execute.ProofOfPayment))

			// Verify operations are valid
			for _, op := range execute.ExecuteOperations {
				require.NotNil(t, op)
				require.NotNil(t, op.Application.Address)
				// ExecutionContext should be valid (0-2)
				require.LessOrEqual(t, uint8(op.Application.ExecutionContext), uint8(2))
			}

			// Verify round-trip works
			data2, err2 := execute.ToBytes()
			require.NoError(t, err2)
			execute2 := &compute.CodeExecute{}
			err3 := execute2.FromBytes(data2, nil, nil, nil, nil, nil, nil, nil)
			require.NoError(t, err3)
			require.Equal(t, execute.Domain, execute2.Domain)
			require.Equal(t, execute.Rendezvous, execute2.Rendezvous)
			require.Equal(t, execute.ProofOfPayment, execute2.ProofOfPayment)
			require.Equal(t, len(execute.ExecuteOperations), len(execute2.ExecuteOperations))
		}
	})
}

// FuzzMixedTypeDeserialization tests deserialization with data that could be any type
func FuzzMixedTypeDeserialization(f *testing.F) {
	// Add valid data for each type
	deploy := &compute.ComputeDeploy{
		Config: &compute.ComputeIntrinsicConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
			OwnerPublicKey: make([]byte, 585),
		},
		RDFSchema: []byte("schema"),
	}
	deployData, _ := deploy.DeployToBytes()
	f.Add(deployData)

	deployment := &compute.CodeDeployment{
		Circuit:     []byte("circuit"),
		InputTypes:  [2]string{"in1", "in2"},
		OutputTypes: []string{"out1"},
	}
	copy(deployment.Domain[:], make([]byte, 32))
	deploymentData, _ := deployment.ToBytes()
	f.Add(deploymentData)

	execute := &compute.CodeExecute{
		ProofOfPayment:    [2][]byte{[]byte("p1"), []byte("p2")},
		ExecuteOperations: []*compute.ExecuteOperation{},
	}
	copy(execute.Domain[:], make([]byte, 32))
	copy(execute.Rendezvous[:], make([]byte, 32))
	executeData, _ := execute.ToBytes()
	f.Add(executeData)

	// Add random data
	f.Add([]byte{})
	f.Add(make([]byte, 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to determine type and deserialize appropriately
		if len(data) >= 4 {
			typePrefix := binary.BigEndian.Uint32(data[:4])

			switch typePrefix {
			case protobufs.ComputeDeploymentType:
				result, err := compute.DeployFromBytes(data)
				if err == nil {
					// Should be able to serialize back
					_, err2 := result.DeployToBytes()
					require.NoError(t, err2)
				}

			case protobufs.CodeDeploymentType:
				deployment := &compute.CodeDeployment{}
				err := deployment.FromBytes(data, nil)
				if err == nil {
					// Should be able to serialize back
					_, err2 := deployment.ToBytes()
					require.NoError(t, err2)
				}

			case protobufs.CodeExecuteType:
				execute := &compute.CodeExecute{}
				err := execute.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)
				if err == nil {
					// Should be able to serialize back
					_, err2 := execute.ToBytes()
					require.NoError(t, err2)
				}
			}
		}

		// Also try deserializing as each type regardless of prefix
		// This ensures invalid type prefixes are handled properly
		_, _ = compute.DeployFromBytes(data)

		deployment := &compute.CodeDeployment{}
		_ = deployment.FromBytes(data, nil)

		execute := &compute.CodeExecute{}
		_ = execute.FromBytes(data, nil, nil, nil, nil, nil, nil, nil)
	})
}
