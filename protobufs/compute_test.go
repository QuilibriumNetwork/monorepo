package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeConfiguration_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		config *ComputeConfiguration
	}{
		{
			name: "complete configuration",
			config: &ComputeConfiguration{
				ReadPublicKey:  make([]byte, 57),  // Ed448 key
				WritePublicKey: make([]byte, 57),  // Ed448 key
				OwnerPublicKey: make([]byte, 585), // BLS48-581 key
			},
		},
		{
			name: "different keys",
			config: &ComputeConfiguration{
				ReadPublicKey:  append([]byte{0x01}, make([]byte, 56)...),
				WritePublicKey: append([]byte{0x02}, make([]byte, 56)...),
				OwnerPublicKey: append([]byte{0x03}, make([]byte, 584)...),
			},
		},
		{
			name: "minimal configuration",
			config: &ComputeConfiguration{
				ReadPublicKey:  []byte{},
				WritePublicKey: []byte{},
				OwnerPublicKey: []byte{},
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
			config2 := &ComputeConfiguration{}
			err = config2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.config.ReadPublicKey, config2.ReadPublicKey)
			assert.Equal(t, tt.config.WritePublicKey, config2.WritePublicKey)
			assert.Equal(t, tt.config.OwnerPublicKey, config2.OwnerPublicKey)
		})
	}
}

func TestCodeDeployment_Serialization(t *testing.T) {
	tests := []struct {
		name       string
		deployment *CodeDeployment
	}{
		{
			name: "complete deployment",
			deployment: &CodeDeployment{
				Circuit:     []byte("test QCL circuit code"),
				InputTypes:  []string{"garbler_type", "evaluator_type"},
				OutputTypes: []string{"output1", "output2", "output3"},
				Domain:      make([]byte, 32),
			},
		},
		{
			name: "minimal deployment",
			deployment: &CodeDeployment{
				Circuit:     []byte("minimal circuit"),
				InputTypes:  []string{"type1", "type2"},
				OutputTypes: []string{},
				Domain:      make([]byte, 32),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.deployment.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			deployment2 := &CodeDeployment{}
			err = deployment2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.deployment.Circuit, deployment2.Circuit)
			assert.Equal(t, tt.deployment.InputTypes, deployment2.InputTypes)
			assert.Equal(t, tt.deployment.OutputTypes, deployment2.OutputTypes)
			assert.Equal(t, tt.deployment.Domain, deployment2.Domain)
		})
	}
}

// Note: Application serialization is tested in application_test.go

func TestExecuteOperation_Serialization(t *testing.T) {
	tests := []struct {
		name string
		op   *ExecuteOperation
	}{
		{
			name: "operation with dependencies",
			op: &ExecuteOperation{
				Application: &Application{
					Address:          make([]byte, 32),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
				},
				Identifier:   []byte("op-123"),
				Dependencies: [][]byte{[]byte("dep-1"), []byte("dep-2"), []byte("dep-3")},
			},
		},
		{
			name: "operation without dependencies",
			op: &ExecuteOperation{
				Application: &Application{
					Address:          []byte("app-address"),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
				},
				Identifier:   []byte("standalone-op"),
				Dependencies: [][]byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.op.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			op2 := &ExecuteOperation{}
			err = op2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.op.Application.Address, op2.Application.Address)
			assert.Equal(t, tt.op.Application.ExecutionContext, op2.Application.ExecutionContext)
			assert.Equal(t, tt.op.Identifier, op2.Identifier)
			assert.Equal(t, tt.op.Dependencies, op2.Dependencies)
		})
	}
}

func TestCodeExecute_Serialization(t *testing.T) {
	tests := []struct {
		name    string
		execute *CodeExecute
	}{
		{
			name: "complete execute",
			execute: &CodeExecute{
				ProofOfPayment: [][]byte{
					[]byte("payment proof 1"),
					[]byte("payment proof 2"),
				},
				Domain:     make([]byte, 32),
				Rendezvous: make([]byte, 32),
				ExecuteOperations: []*ExecuteOperation{
					{
						Application: &Application{
							Address:          make([]byte, 32),
							ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
						},
						Identifier:   []byte("op1"),
						Dependencies: [][]byte{},
					},
					{
						Application: &Application{
							Address:          make([]byte, 32),
							ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
						},
						Identifier:   []byte("op2"),
						Dependencies: [][]byte{[]byte("op1")},
					},
				},
			},
		},
		{
			name: "single operation",
			execute: &CodeExecute{
				ProofOfPayment: [][]byte{
					make([]byte, 100),
					make([]byte, 100),
				},
				Domain:     make([]byte, 32),
				Rendezvous: append([]byte{0xFF}, make([]byte, 31)...),
				ExecuteOperations: []*ExecuteOperation{
					{
						Application: &Application{
							Address:          []byte("single-app"),
							ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
						},
						Identifier:   []byte("single-op"),
						Dependencies: [][]byte{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.execute.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			execute2 := &CodeExecute{}
			err = execute2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.execute.ProofOfPayment, execute2.ProofOfPayment)
			assert.Equal(t, tt.execute.Domain, execute2.Domain)
			assert.Equal(t, tt.execute.Rendezvous, execute2.Rendezvous)
			assert.Equal(t, len(tt.execute.ExecuteOperations), len(execute2.ExecuteOperations))

			for i, op := range tt.execute.ExecuteOperations {
				assert.Equal(t, op.Application.Address, execute2.ExecuteOperations[i].Application.Address)
				assert.Equal(t, op.Application.ExecutionContext, execute2.ExecuteOperations[i].Application.ExecutionContext)
				assert.Equal(t, op.Identifier, execute2.ExecuteOperations[i].Identifier)
				assert.Equal(t, op.Dependencies, execute2.ExecuteOperations[i].Dependencies)
			}
		})
	}
}

func TestStateTransition_Serialization(t *testing.T) {
	tests := []struct {
		name       string
		transition *StateTransition
	}{
		{
			name: "complete transition",
			transition: &StateTransition{
				Domain:   make([]byte, 32),
				Address:  []byte("state-address"),
				OldValue: []byte("old state value"),
				NewValue: []byte("new state value"),
				Proof:    make([]byte, 128),
			},
		},
		{
			name: "empty values",
			transition: &StateTransition{
				Domain:   make([]byte, 32),
				Address:  []byte("addr"),
				OldValue: []byte{},
				NewValue: []byte{},
				Proof:    []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.transition.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			transition2 := &StateTransition{}
			err = transition2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.transition.Domain, transition2.Domain)
			assert.Equal(t, tt.transition.Address, transition2.Address)
			assert.Equal(t, tt.transition.OldValue, transition2.OldValue)
			assert.Equal(t, tt.transition.NewValue, transition2.NewValue)
			assert.Equal(t, tt.transition.Proof, transition2.Proof)
		})
	}
}

func TestExecutionResult_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		result *ExecutionResult
	}{
		{
			name: "successful result",
			result: &ExecutionResult{
				OperationId: []byte("op-123"),
				Success:     true,
				Output:      []byte("operation output data"),
				Error:       []byte{},
			},
		},
		{
			name: "failed result",
			result: &ExecutionResult{
				OperationId: []byte("op-failed"),
				Success:     false,
				Output:      []byte{},
				Error:       []byte("operation failed: invalid input"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.result.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			result2 := &ExecutionResult{}
			err = result2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.result.OperationId, result2.OperationId)
			assert.Equal(t, tt.result.Success, result2.Success)
			assert.Equal(t, tt.result.Output, result2.Output)
			assert.Equal(t, tt.result.Error, result2.Error)
		})
	}
}

func TestCodeFinalize_Serialization(t *testing.T) {
	tests := []struct {
		name     string
		finalize *CodeFinalize
	}{
		{
			name: "complete finalize",
			finalize: &CodeFinalize{
				Rendezvous: make([]byte, 32),
				Results: []*ExecutionResult{
					{
						OperationId: []byte("op1"),
						Success:     true,
						Output:      []byte("result1"),
						Error:       []byte{},
					},
					{
						OperationId: []byte("op2"),
						Success:     false,
						Output:      []byte{},
						Error:       []byte("error2"),
					},
				},
				StateChanges: []*StateTransition{
					{
						Domain:   make([]byte, 32),
						Address:  []byte("addr1"),
						OldValue: []byte("old1"),
						NewValue: []byte("new1"),
						Proof:    make([]byte, 64),
					},
				},
				ProofOfExecution: make([]byte, 256),
				MessageOutput:    []byte("final output message"),
			},
		},
		{
			name: "minimal finalize",
			finalize: &CodeFinalize{
				Rendezvous:       make([]byte, 32),
				Results:          []*ExecutionResult{},
				StateChanges:     []*StateTransition{},
				ProofOfExecution: []byte{},
				MessageOutput:    []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.finalize.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			finalize2 := &CodeFinalize{}
			err = finalize2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.finalize.Rendezvous, finalize2.Rendezvous)
			assert.Equal(t, len(tt.finalize.Results), len(finalize2.Results))
			assert.Equal(t, len(tt.finalize.StateChanges), len(finalize2.StateChanges))
			assert.Equal(t, tt.finalize.ProofOfExecution, finalize2.ProofOfExecution)
			assert.Equal(t, tt.finalize.MessageOutput, finalize2.MessageOutput)

			// Compare results
			for i, result := range tt.finalize.Results {
				assert.Equal(t, result.OperationId, finalize2.Results[i].OperationId)
				assert.Equal(t, result.Success, finalize2.Results[i].Success)
				assert.Equal(t, result.Output, finalize2.Results[i].Output)
				assert.Equal(t, result.Error, finalize2.Results[i].Error)
			}

			// Compare state changes
			for i, change := range tt.finalize.StateChanges {
				assert.Equal(t, change.Domain, finalize2.StateChanges[i].Domain)
				assert.Equal(t, change.Address, finalize2.StateChanges[i].Address)
				assert.Equal(t, change.OldValue, finalize2.StateChanges[i].OldValue)
				assert.Equal(t, change.NewValue, finalize2.StateChanges[i].NewValue)
				assert.Equal(t, change.Proof, finalize2.StateChanges[i].Proof)
			}
		})
	}
}

func TestComputeDeploy_Serialization(t *testing.T) {
	tests := []struct {
		name string
		args *ComputeDeploy
	}{
		{
			name: "complete arguments",
			args: &ComputeDeploy{
				Config: &ComputeConfiguration{
					ReadPublicKey:  make([]byte, 57),
					WritePublicKey: make([]byte, 57),
					OwnerPublicKey: make([]byte, 585),
				},
				RdfSchema: []byte("RDF schema definition content"),
			},
		},
		{
			name: "large schema",
			args: &ComputeDeploy{
				Config: &ComputeConfiguration{
					ReadPublicKey:  append([]byte{0xAA}, make([]byte, 56)...),
					WritePublicKey: append([]byte{0xBB}, make([]byte, 56)...),
					OwnerPublicKey: append([]byte{0xCC}, make([]byte, 584)...),
				},
				RdfSchema: make([]byte, 1024), // Large schema
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := tt.args.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test deserialization
			args2 := &ComputeDeploy{}
			err = args2.FromCanonicalBytes(data)
			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.args.Config.ReadPublicKey, args2.Config.ReadPublicKey)
			assert.Equal(t, tt.args.Config.WritePublicKey, args2.Config.WritePublicKey)
			assert.Equal(t, tt.args.Config.OwnerPublicKey, args2.Config.OwnerPublicKey)
			assert.Equal(t, tt.args.RdfSchema, args2.RdfSchema)
		})
	}
}

func TestComputeTypes_Validation(t *testing.T) {
	t.Run("ComputeConfiguration validation", func(t *testing.T) {
		// Valid configuration
		config := &ComputeConfiguration{
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
		var nilConfig *ComputeConfiguration
		assert.Error(t, nilConfig.Validate())
	})

	t.Run("CodeDeployment validation", func(t *testing.T) {
		// Valid deployment
		deployment := &CodeDeployment{
			Circuit:     []byte("circuit"),
			InputTypes:  []string{"type1", "type2"},
			OutputTypes: []string{"output"},
			Domain:      make([]byte, 32),
		}
		assert.NoError(t, deployment.Validate())

		// Empty circuit
		deployment.Circuit = []byte{}
		assert.Error(t, deployment.Validate())

		// Wrong number of input types
		deployment.Circuit = []byte("circuit")
		deployment.InputTypes = []string{"type1"}
		assert.Error(t, deployment.Validate())

		// Invalid domain length
		deployment.InputTypes = []string{"type1", "type2"}
		deployment.Domain = make([]byte, 31)
		assert.Error(t, deployment.Validate())
	})

	t.Run("CodeExecute validation", func(t *testing.T) {
		// Valid execute
		execute := &CodeExecute{
			ProofOfPayment: [][]byte{
				[]byte("proof1"),
				[]byte("proof2"),
			},
			Domain:     make([]byte, 32),
			Rendezvous: make([]byte, 32),
			ExecuteOperations: []*ExecuteOperation{
				{
					Application: &Application{
						Address:          []byte("app"),
						ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
					},
					Identifier: []byte("op1"),
				},
			},
		}
		assert.NoError(t, execute.Validate())

		// Wrong number of payment proofs
		execute.ProofOfPayment = [][]byte{[]byte("proof1")}
		assert.Error(t, execute.Validate())

		// Invalid domain length
		execute.ProofOfPayment = [][]byte{[]byte("proof1"), []byte("proof2")}
		execute.Domain = make([]byte, 31)
		assert.Error(t, execute.Validate())

		// No operations
		execute.Domain = make([]byte, 32)
		execute.ExecuteOperations = []*ExecuteOperation{}
		assert.Error(t, execute.Validate())
	})

	t.Run("CodeFinalize validation", func(t *testing.T) {
		// Valid finalize
		finalize := &CodeFinalize{
			Rendezvous: make([]byte, 32),
			Results:    []*ExecutionResult{},
		}
		assert.NoError(t, finalize.Validate())

		// Invalid rendezvous length
		finalize.Rendezvous = make([]byte, 31)
		assert.Error(t, finalize.Validate())

		// Nil finalize
		var nilFinalize *CodeFinalize
		assert.Error(t, nilFinalize.Validate())
	})

	t.Run("ComputeDeployArguments validation", func(t *testing.T) {
		// Valid arguments
		args := &ComputeDeploy{
			Config: &ComputeConfiguration{
				ReadPublicKey:  make([]byte, 57),
				WritePublicKey: make([]byte, 57),
				OwnerPublicKey: make([]byte, 585),
			},
			RdfSchema: []byte("schema"),
		}
		assert.NoError(t, args.Validate())

		// Invalid key lengths
		args.Config.ReadPublicKey = make([]byte, 56)
		assert.Error(t, args.Validate())

		// Empty schema
		args.Config.ReadPublicKey = make([]byte, 57)
		args.RdfSchema = []byte{}
		assert.NoError(t, args.Validate())
	})
}

func TestExecutionContext_Values(t *testing.T) {
	// Test that enum values match expected constants
	assert.Equal(t, ExecutionContext(0), ExecutionContext_EXECUTION_CONTEXT_INTRINSIC)
	assert.Equal(t, ExecutionContext(1), ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH)
	assert.Equal(t, ExecutionContext(2), ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC)
}

func TestComputeSerialization_RoundTrip(t *testing.T) {
	// Test that serialize -> deserialize -> serialize produces the same bytes
	config := &ComputeConfiguration{
		ReadPublicKey:  randomBytes(t, 57),
		WritePublicKey: randomBytes(t, 57),
	}

	// First serialization
	data1, err := config.ToCanonicalBytes()
	require.NoError(t, err)

	// Deserialize
	config2 := &ComputeConfiguration{}
	err = config2.FromCanonicalBytes(data1)
	require.NoError(t, err)

	// Second serialization
	data2, err := config2.ToCanonicalBytes()
	require.NoError(t, err)

	// Should be identical
	assert.Equal(t, data1, data2)
}

func TestCodeExecute_ComplexDAG(t *testing.T) {
	// Test a complex execution DAG
	execute := &CodeExecute{
		ProofOfPayment: [][]byte{
			randomBytes(t, 100),
			randomBytes(t, 100),
		},
		Domain:     randomBytes(t, 32),
		Rendezvous: randomBytes(t, 32),
		ExecuteOperations: []*ExecuteOperation{
			{
				Application: &Application{
					Address:          randomBytes(t, 32),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
				},
				Identifier:   []byte("root"),
				Dependencies: [][]byte{},
			},
			{
				Application: &Application{
					Address:          randomBytes(t, 32),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
				},
				Identifier:   []byte("child1"),
				Dependencies: [][]byte{[]byte("root")},
			},
			{
				Application: &Application{
					Address:          randomBytes(t, 32),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
				},
				Identifier:   []byte("child2"),
				Dependencies: [][]byte{[]byte("root")},
			},
			{
				Application: &Application{
					Address:          randomBytes(t, 32),
					ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
				},
				Identifier:   []byte("grandchild"),
				Dependencies: [][]byte{[]byte("child1"), []byte("child2")},
			},
		},
	}

	// Serialize
	data, err := execute.ToCanonicalBytes()
	require.NoError(t, err)

	// Deserialize
	execute2 := &CodeExecute{}
	err = execute2.FromCanonicalBytes(data)
	require.NoError(t, err)

	// Verify complex structure is preserved
	assert.Equal(t, len(execute.ExecuteOperations), len(execute2.ExecuteOperations))
	assert.Equal(t, execute.ExecuteOperations[3].Dependencies, execute2.ExecuteOperations[3].Dependencies)
}

func TestComputeUpdate_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		update *ComputeUpdate
	}{
		{
			name: "complete compute update",
			update: &ComputeUpdate{
				Config: &ComputeConfiguration{
					ReadPublicKey:  make([]byte, 57),
					WritePublicKey: make([]byte, 57),
					OwnerPublicKey: make([]byte, 585),
				},
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: make([]byte, 585),
					},
					Signature: make([]byte, 74),
					Bitmask:   []byte{0xFF, 0xFF},
				},
			},
		},
		{
			name: "update with different keys",
			update: &ComputeUpdate{
				Config: &ComputeConfiguration{
					ReadPublicKey:  append([]byte{0x01}, make([]byte, 56)...),
					WritePublicKey: append([]byte{0x02}, make([]byte, 56)...),
					OwnerPublicKey: append([]byte{0x03}, make([]byte, 584)...),
				},
				PublicKeySignatureBls48581: &BLS48581AggregateSignature{
					PublicKey: &BLS48581G2PublicKey{
						KeyValue: append([]byte{0xAA}, make([]byte, 584)...),
					},
					Signature: append([]byte{0xBB}, make([]byte, 73)...),
					Bitmask:   []byte{0x0F},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.update.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			update2 := &ComputeUpdate{}
			err = update2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.update.Config.ReadPublicKey, update2.Config.ReadPublicKey)
			assert.Equal(t, tt.update.Config.WritePublicKey, update2.Config.WritePublicKey)
			assert.Equal(t, tt.update.Config.OwnerPublicKey, update2.Config.OwnerPublicKey)
			assert.Equal(t, tt.update.PublicKeySignatureBls48581.PublicKey.KeyValue, update2.PublicKeySignatureBls48581.PublicKey.KeyValue)
			assert.Equal(t, tt.update.PublicKeySignatureBls48581.Signature, update2.PublicKeySignatureBls48581.Signature)
			assert.Equal(t, tt.update.PublicKeySignatureBls48581.Bitmask, update2.PublicKeySignatureBls48581.Bitmask)
		})
	}
}

func TestIntrinsicExecutionInput_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		input *IntrinsicExecutionInput
	}{
		{
			name: "complete intrinsic input",
			input: &IntrinsicExecutionInput{
				Address: make([]byte, 32),
				Input:   []byte("intrinsic input data"),
			},
		},
		{
			name: "empty input",
			input: &IntrinsicExecutionInput{
				Address: append([]byte{0xFF}, make([]byte, 31)...),
				Input:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			input2 := &IntrinsicExecutionInput{}
			err = input2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.input.Address, input2.Address)
			assert.Equal(t, tt.input.Input, input2.Input)
		})
	}
}

func TestIntrinsicExecutionOutput_Serialization(t *testing.T) {
	tests := []struct {
		name   string
		output *IntrinsicExecutionOutput
	}{
		{
			name: "complete intrinsic output",
			output: &IntrinsicExecutionOutput{
				Address: make([]byte, 32),
				Output:  []byte("intrinsic output data"),
				Proof:   make([]byte, 128),
			},
		},
		{
			name: "output with different data",
			output: &IntrinsicExecutionOutput{
				Address: append([]byte{0xAA}, make([]byte, 31)...),
				Output:  []byte("different output"),
				Proof:   append([]byte{0xFF}, make([]byte, 127)...),
			},
		},
		{
			name: "minimal output",
			output: &IntrinsicExecutionOutput{
				Address: []byte{},
				Output:  []byte{},
				Proof:   []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.output.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			output2 := &IntrinsicExecutionOutput{}
			err = output2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.output.Address, output2.Address)
			assert.Equal(t, tt.output.Output, output2.Output)
			assert.Equal(t, tt.output.Proof, output2.Proof)
		})
	}
}

func TestExecutionDependency_Serialization(t *testing.T) {
	tests := []struct {
		name string
		dep  *ExecutionDependency
	}{
		{
			name: "complete dependency",
			dep: &ExecutionDependency{
				Identifier: []byte("operation-12345"),
				ReadSet:    [][]byte{[]byte("read-addr-1"), []byte("read-addr-2")},
				WriteSet:   [][]byte{[]byte("write-addr-1")},
				Stage:      2,
			},
		},
		{
			name: "dependency with no read/write sets",
			dep: &ExecutionDependency{
				Identifier: []byte("standalone-op"),
				ReadSet:    [][]byte{},
				WriteSet:   [][]byte{},
				Stage:      0,
			},
		},
		{
			name: "dependency with large sets",
			dep: &ExecutionDependency{
				Identifier: []byte("complex-op"),
				ReadSet: [][]byte{
					[]byte("read1"), []byte("read2"), []byte("read3"),
				},
				WriteSet: [][]byte{
					[]byte("write1"), []byte("write2"),
				},
				Stage: uint32(1<<31 - 1),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.dep.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			dep2 := &ExecutionDependency{}
			err = dep2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.dep.Identifier, dep2.Identifier)
			assert.Equal(t, tt.dep.ReadSet, dep2.ReadSet)
			assert.Equal(t, tt.dep.WriteSet, dep2.WriteSet)
			assert.Equal(t, tt.dep.Stage, dep2.Stage)
		})
	}
}

func TestExecutionNode_Serialization(t *testing.T) {
	tests := []struct {
		name string
		node *ExecutionNode
	}{
		{
			name: "complete execution node",
			node: &ExecutionNode{
				Operation: &ExecuteOperation{
					Application: &Application{
						Address:          make([]byte, 32),
						ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
					},
					Identifier:   []byte("op-99999"),
					Dependencies: [][]byte{[]byte("dep-1"), []byte("dep-2")},
				},
				ReadSet:    [][]byte{[]byte("read-addr-1"), []byte("read-addr-2")},
				WriteSet:   [][]byte{[]byte("write-addr-1")},
				Stage:      2,
				Visited:    true,
				InProgress: false,
			},
		},
		{
			name: "node in progress",
			node: &ExecutionNode{
				Operation: &ExecuteOperation{
					Application: &Application{
						Address:          append([]byte{0xAA}, make([]byte, 31)...),
						ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
					},
					Identifier:   []byte("in-progress-op"),
					Dependencies: [][]byte{},
				},
				ReadSet:    [][]byte{[]byte("read-only")},
				WriteSet:   [][]byte{},
				Stage:      0,
				Visited:    false,
				InProgress: true,
			},
		},
		{
			name: "minimal node",
			node: &ExecutionNode{
				Operation: &ExecuteOperation{
					Application: &Application{
						Address:          []byte{},
						ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
					},
					Identifier:   []byte{},
					Dependencies: [][]byte{},
				},
				ReadSet:    [][]byte{},
				WriteSet:   [][]byte{},
				Stage:      0,
				Visited:    false,
				InProgress: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.node.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			node2 := &ExecutionNode{}
			err = node2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.node.Operation.Application.Address, node2.Operation.Application.Address)
			assert.Equal(t, tt.node.Operation.Application.ExecutionContext, node2.Operation.Application.ExecutionContext)
			assert.Equal(t, tt.node.Operation.Identifier, node2.Operation.Identifier)
			assert.Equal(t, tt.node.Operation.Dependencies, node2.Operation.Dependencies)
			assert.Equal(t, tt.node.ReadSet, node2.ReadSet)
			assert.Equal(t, tt.node.WriteSet, node2.WriteSet)
			assert.Equal(t, tt.node.Stage, node2.Stage)
			assert.Equal(t, tt.node.Visited, node2.Visited)
			assert.Equal(t, tt.node.InProgress, node2.InProgress)
		})
	}
}

func TestExecutionStage_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		stage *ExecutionStage
	}{
		{
			name: "complete execution stage",
			stage: &ExecutionStage{
				OperationIds: []string{"op-1", "op-2", "op-3", "op-4", "op-5"},
			},
		},
		{
			name: "single operation stage",
			stage: &ExecutionStage{
				OperationIds: []string{"standalone-op"},
			},
		},
		{
			name: "empty stage",
			stage: &ExecutionStage{
				OperationIds: []string{},
			},
		},
		{
			name: "stage with complex operation names",
			stage: &ExecutionStage{
				OperationIds: []string{"compute-123", "transform-abc", "aggregate-xyz"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.stage.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			stage2 := &ExecutionStage{}
			err = stage2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, tt.stage.OperationIds, stage2.OperationIds)
		})
	}
}

func TestExecutionDAG_Serialization(t *testing.T) {
	tests := []struct {
		name string
		dag  *ExecutionDAG
	}{
		{
			name: "complete DAG",
			dag: &ExecutionDAG{
				Operations: map[string]*ExecutionNode{
					"op-1": {
						Operation: &ExecuteOperation{
							Application: &Application{
								Address:          make([]byte, 32),
								ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
							},
							Identifier:   []byte("op-1"),
							Dependencies: [][]byte{},
						},
						ReadSet:    [][]byte{[]byte("read1")},
						WriteSet:   [][]byte{[]byte("write1")},
						Stage:      0,
						Visited:    false,
						InProgress: false,
					},
					"op-2": {
						Operation: &ExecuteOperation{
							Application: &Application{
								Address:          append([]byte{0xAA}, make([]byte, 31)...),
								ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
							},
							Identifier:   []byte("op-2"),
							Dependencies: [][]byte{[]byte("op-1")},
						},
						ReadSet:    [][]byte{[]byte("write1")},
						WriteSet:   [][]byte{[]byte("write2")},
						Stage:      1,
						Visited:    true,
						InProgress: false,
					},
				},
				Stages: []*ExecutionStage{
					{OperationIds: []string{"op-1"}},
					{OperationIds: []string{"op-2"}},
				},
			},
		},
		{
			name: "DAG with parallel execution",
			dag: &ExecutionDAG{
				Operations: map[string]*ExecutionNode{
					"parallel-1": {
						Operation: &ExecuteOperation{
							Application: &Application{
								Address:          []byte("app1"),
								ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
							},
							Identifier:   []byte("parallel-1"),
							Dependencies: [][]byte{},
						},
						ReadSet:    [][]byte{},
						WriteSet:   [][]byte{[]byte("output1")},
						Stage:      0,
						Visited:    false,
						InProgress: false,
					},
					"parallel-2": {
						Operation: &ExecuteOperation{
							Application: &Application{
								Address:          []byte("app2"),
								ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC,
							},
							Identifier:   []byte("parallel-2"),
							Dependencies: [][]byte{},
						},
						ReadSet:    [][]byte{},
						WriteSet:   [][]byte{[]byte("output2")},
						Stage:      0,
						Visited:    false,
						InProgress: false,
					},
					"merge": {
						Operation: &ExecuteOperation{
							Application: &Application{
								Address:          []byte("merge-app"),
								ExecutionContext: ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
							},
							Identifier:   []byte("merge"),
							Dependencies: [][]byte{[]byte("parallel-1"), []byte("parallel-2")},
						},
						ReadSet:    [][]byte{[]byte("output1"), []byte("output2")},
						WriteSet:   [][]byte{[]byte("final-output")},
						Stage:      1,
						Visited:    false,
						InProgress: false,
					},
				},
				Stages: []*ExecutionStage{
					{OperationIds: []string{"parallel-1", "parallel-2"}},
					{OperationIds: []string{"merge"}},
				},
			},
		},
		{
			name: "empty DAG",
			dag: &ExecutionDAG{
				Operations: map[string]*ExecutionNode{},
				Stages:     []*ExecutionStage{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.dag.ToCanonicalBytes()
			require.NoError(t, err)
			require.NotNil(t, data)

			dag2 := &ExecutionDAG{}
			err = dag2.FromCanonicalBytes(data)
			require.NoError(t, err)

			assert.Equal(t, len(tt.dag.Operations), len(dag2.Operations))
			assert.Equal(t, len(tt.dag.Stages), len(dag2.Stages))

			for key, node := range tt.dag.Operations {
				assert.Contains(t, dag2.Operations, key)
				node2 := dag2.Operations[key]
				assert.Equal(t, node.Operation.Identifier, node2.Operation.Identifier)
				assert.Equal(t, node.ReadSet, node2.ReadSet)
				assert.Equal(t, node.WriteSet, node2.WriteSet)
				assert.Equal(t, node.Stage, node2.Stage)
				assert.Equal(t, node.Visited, node2.Visited)
				assert.Equal(t, node.InProgress, node2.InProgress)
			}

			for i := range tt.dag.Stages {
				assert.Equal(t, tt.dag.Stages[i].OperationIds, dag2.Stages[i].OperationIds)
			}
		})
	}
}
