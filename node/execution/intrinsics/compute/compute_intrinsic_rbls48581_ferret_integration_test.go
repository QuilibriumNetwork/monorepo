//go:build integrationtest
// +build integrationtest

package compute_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func generateRDFPrelude(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) string {
	appAddressHex := hex.EncodeToString(appAddress)

	prelude := "BASE <https://types.quilibrium.com/schema-repository/>\n" +
		"PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
		"PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n" +
		"PREFIX qcl: <https://types.quilibrium.com/qcl/>\n" +
		"PREFIX coin: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/coin/>\n"

	if config.Behavior&token.Acceptable != 0 {
		prelude += "PREFIX pending: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/pending/>\n"
	}

	prelude += "\n"

	return prelude
}

func prepareRDFSchemaFromConfig(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) (string, error) {
	schema := generateRDFPrelude(appAddress, config)

	schema += "coin:Coin a rdfs:Class.\n" +
		"coin:FrameNumber a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 8;\n" +
		"  qcl:order 0;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Commitment a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 1;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:OneTimeKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 2;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:VerificationKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 3;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:CoinBalance a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 4;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Mask a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 5;\n" +
		"  rdfs:range coin:Coin.\n"

	if config.Behavior&token.Divisible == 0 {
		schema += "coin:AdditionalReference a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 64;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range coin:Coin.\n"
		schema += "coin:AdditionalReferenceKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range coin:Coin.\n"
	}

	if config.Behavior&token.Acceptable != 0 {
		schema += "\npending:PendingTransaction a rdfs:Class;\n" +
			"  rdfs:label \"a pending transaction\".\n" +
			"pending:FrameNumber a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 8;\n" +
			"  qcl:order 0;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:Commitment a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 1;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 2;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 3;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 4;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 5;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 8;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 9;\n" +
			"  rdfs:range pending:PendingTransaction.\n"

		if config.Behavior&token.Divisible == 0 {
			schema += "pending:ToAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 10;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:ToAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 11;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 12;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 13;\n" +
				"  rdfs:range pending:PendingTransaction.\n"
		}

		if config.Behavior&token.Expirable != 0 {
			schema += "pending:Expiration a rdfs:Property;\n" +
				"  rdfs:domain qcl:Uint;\n" +
				"  qcl:size 8;\n"

			if config.Behavior&token.Divisible == 0 {
				schema += "  qcl:order 14;\n"
			} else {
				schema += "  qcl:order 10;\n"
			}

			schema += "  rdfs:range pending:PendingTransaction.\n"
		}
	}

	schema += "\n"

	return schema, nil
}

// Integration test that uses BLS48581 and Ferret with hypergraph
func TestComputeIntrinsic_Integration(t *testing.T) {
	// Create a key manager with BLS48581 keys
	keyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})
	signer, popk, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, popk)

	// Create a hypergrpah
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)

	// Create compute intrinsic
	bp := &bulletproofs.Decaf448BulletproofProver{}
	decaf := &bulletproofs.Decaf448KeyConstructor{}
	computeIntrinsic, err := compute.NewComputeIntrinsic(
		&compute.ComputeIntrinsicConfiguration{ReadPublicKey: make([]byte, 57), WritePublicKey: make([]byte, 57)},
		hg,
		ip,
		bp,
		ve,
		decaf,
		keyManager,
		compiler.NewBedlamCompiler(),
	)
	require.NoError(t, err)
	require.NotNil(t, computeIntrinsic)

	// Test data
	creator := signer.Public().([]byte)
	fee := big.NewInt(100000)

	// Test Deploy
	t.Run("Deploy", func(t *testing.T) {
		var state state.State = hgstate.NewHypergraphState(hg)
		state, err = computeIntrinsic.Deploy(
			compute.COMPUTE_INTRINSIC_DOMAIN,
			[][]byte{creator}, // provers
			creator,
			fee,
			[]byte(`BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX req: <https://types.quilibrium.com/schema-repository/example/a>

req:Request a rdfs:Class.
req:A a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 0;
  rdfs:range req:Request.
`),
			1,
			state,
		)
		require.NoError(t, err)
		require.NotNil(t, state)

		// Verify the intrinsic address was set
		assert.NotEqual(t, compute.COMPUTE_INTRINSIC_DOMAIN, computeIntrinsic.Address())

		// Verify the state was initialized
		err = state.Commit()
		require.NoError(t, err)
	})

	// Test InvokeStep with CodeDeployment
	t.Run("InvokeStep_CodeDeployment", func(t *testing.T) {
		// Valid QCL code
		sourceCode := []byte(`package main

func main(a, b int) int {
	return a + b
}
`)

		frameNumber := uint64(123456)
		domain := [32]byte(computeIntrinsic.Address())

		// Create code deployment with input sizes
		inputSizes := [2][]int{{32}, {32}} // Example input sizes for garbler and evaluator
		codeDeployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, inputSizes, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		// Call Prove() before serialization
		err = codeDeployment.Prove(frameNumber)
		require.NoError(t, err)

		// Serialize the code deployment
		deploymentData, err := codeDeployment.ToBytes()
		require.NoError(t, err)

		// Create hypergraph state
		state := hgstate.NewHypergraphState(hg)

		// Invoke step
		resultState, err := computeIntrinsic.InvokeStep(frameNumber, deploymentData, fee, big.NewInt(1), state)
		require.NoError(t, err)
		require.NotNil(t, resultState)

		// Verify the state was updated
		err = resultState.Commit()
		require.NoError(t, err)

		// Verify the code was materialized
		codeAddressBI, err := poseidon.HashBytes(
			slices.Concat(
				domain[:],
				codeDeployment.Circuit,
			),
		)
		require.NoError(t, err)
		codeAddress := codeAddressBI.FillBytes(make([]byte, 32))

		// Check that the vertex was created
		vertexAddress := slices.Concat(domain[:], codeAddress)
		vertex, err := hg.GetVertex([64]byte(vertexAddress))
		require.NoError(t, err)
		require.NotNil(t, vertex)

		// Check that the code was stored
		tree, err := hg.GetVertexData([64]byte(vertexAddress))
		require.NoError(t, err)
		require.NotNil(t, tree)

		// Verify source code at index 0
		sourceData, err := tree.Get([]byte{0 << 2})
		require.NoError(t, err)
		assert.Equal(t, codeDeployment.Circuit, sourceData)
	})

	// Test InvokeStep with invalid code
	t.Run("InvokeStep_InvalidCode", func(t *testing.T) {
		// Invalid QCL code
		sourceCode := []byte("invalid syntax { not valid QCL }")
		frameNumber := uint64(123456)
		domain := [32]byte(computeIntrinsic.Address())

		// Create code deployment with input sizes
		inputSizes := [2][]int{{32}, {32}} // Example input sizes for garbler and evaluator
		codeDeployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, inputSizes, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		// Call Prove() before serialization
		err = codeDeployment.Prove(frameNumber)
		require.Error(t, err)

		// Serialize the code deployment
		deploymentData, err := codeDeployment.ToBytes()
		require.NoError(t, err)

		// Create hypergraph state
		state := hgstate.NewHypergraphState(hg)

		// Invoke step should fail due to invalid code
		resultState, err := computeIntrinsic.InvokeStep(frameNumber, deploymentData, fee, big.NewInt(1), state)
		assert.Error(t, err)
		assert.Nil(t, resultState)
		assert.Contains(t, err.Error(), "invoke step")
	})

	// Test InvokeStep with invalid type prefix
	t.Run("InvokeStep_InvalidType", func(t *testing.T) {
		// Create invalid data with unknown type prefix
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint32(99)) // Invalid type
		buf.Write(make([]byte, 100))                    // Some dummy data

		frameNumber := uint64(123)
		state := hgstate.NewHypergraphState(hg)

		// Should fail with unknown operation type
		resultState, err := computeIntrinsic.InvokeStep(frameNumber, buf.Bytes(), fee, big.NewInt(1), state)
		assert.Error(t, err)
		assert.Nil(t, resultState)
		assert.Contains(t, err.Error(), "unknown operation type: 99")
	})

	// Test Lock/Unlock mechanism
	t.Run("LockUnlock", func(t *testing.T) {
		// Test addresses
		writeAddr1 := []byte("write_address_1")
		writeAddr2 := []byte("write_address_2")
		readAddr1 := []byte("read_address_1")
		readAddr2 := []byte("read_address_2")

		// Lock addresses
		err := computeIntrinsic.Lock([][]byte{writeAddr1}, [][]byte{readAddr1})
		require.NoError(t, err)

		// Try to lock same write address again - should fail
		err = computeIntrinsic.Lock([][]byte{writeAddr1}, [][]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already locked for writing")

		// Try to lock for reading an address that's locked for writing - should fail
		err = computeIntrinsic.Lock([][]byte{}, [][]byte{writeAddr1})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already locked for writing")

		// Lock additional addresses
		err = computeIntrinsic.Lock([][]byte{writeAddr2}, [][]byte{readAddr2})
		require.NoError(t, err)

		// Unlock first set
		err = computeIntrinsic.Unlock([][]byte{writeAddr1}, [][]byte{readAddr1})
		require.NoError(t, err)

		// Now we should be able to lock writeAddr1 again
		err = computeIntrinsic.Lock([][]byte{writeAddr1}, [][]byte{})
		require.NoError(t, err)

		// Unlock all
		err = computeIntrinsic.Unlock([][]byte{writeAddr1, writeAddr2}, [][]byte{readAddr2})
		require.NoError(t, err)
	})

	// Test LoadComputeIntrinsic
	t.Run("LoadComputeIntrinsic", func(t *testing.T) {
		var state state.State = hgstate.NewHypergraphState(hg)
		// First deploy a compute intrinsic
		state, err := computeIntrinsic.Deploy(
			compute.COMPUTE_INTRINSIC_DOMAIN,
			[][]byte{creator},
			creator,
			fee,
			[]byte(`BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX req: <https://types.quilibrium.com/schema-repository/example/a>

req:Request a rdfs:Class.
req:A a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 0;
  rdfs:range req:Request.
`),
			1,
			state,
		)
		require.NoError(t, err)

		err = state.Commit()
		require.NoError(t, err)

		// Get the deployed address
		appAddress := computeIntrinsic.Address()

		// Load the compute intrinsic
		loadedIntrinsic, err := compute.LoadComputeIntrinsic(appAddress, hg, hgstate.NewHypergraphState(hg), ip, bulletproofs.NewBulletproofProver(), verenc.NewMPCitHVerifiableEncryptor(1), &bulletproofs.Decaf448KeyConstructor{}, keyManager, compiler.NewBedlamCompiler())
		require.NoError(t, err)
		require.NotNil(t, loadedIntrinsic)

		// Verify the address matches
		assert.Equal(t, appAddress, loadedIntrinsic.Address())
	})

	// Test complex multi-step computation scenario
	t.Run("ComplexComputation", func(t *testing.T) {
		// Deploy multiple code modules
		modules := []struct {
			name string
			code []byte
		}{
			{
				name: "math_module",
				code: []byte(`package main

func main(a, b int) int {
	return a * b
}

func power(base, exp int) int {
	result := 1
	for i := 0; i < exp; i++ {
		result = multiply(result, base)
	}
	return result
}`),
			},
			{
				name: "crypto_module",
				code: []byte(`package main

func main(data []byte, other []byte) []byte {
	// Simple xor function
	result := make([]byte, 32)
	for i, b := range data {
		if i < 32 {
			result[i] = b ^ other[i]
		}
	}
	return result
}`),
			},
		}

		domain := [32]byte(computeIntrinsic.Address())
		state := hgstate.NewHypergraphState(hg)

		for _, module := range modules {
			t.Run("Deploy_"+module.name, func(t *testing.T) {
				frameNumber := uint64(1000)

				// Create deployment with input sizes
				inputSizes := [2][]int{{32, 32}, {32}} // Different input sizes for different modules
				deployment, err := compute.NewCodeDeployment(domain, module.code, [2]string{"qcl:Int", "qcl:Int"}, inputSizes, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
				require.NoError(t, err)

				// Prove the deployment
				err = deployment.Prove(frameNumber)
				require.NoError(t, err)

				// Serialize
				data, err := deployment.ToBytes()
				require.NoError(t, err)

				// Deploy via InvokeStep
				resultState, err := computeIntrinsic.InvokeStep(frameNumber, data, fee, big.NewInt(1), state)
				require.NoError(t, err)

				state = resultState.(*hgstate.HypergraphState)
			})
		}

		// Commit all deployments
		err = state.Commit()
		require.NoError(t, err)
	})

	// Test error scenarios
	t.Run("ErrorScenarios", func(t *testing.T) {
		// Test InvokeStep with invalid data
		invalidData := []byte("not a valid code deployment")
		state := hgstate.NewHypergraphState(hg)
		resultState, err := computeIntrinsic.InvokeStep(123, invalidData, fee, big.NewInt(1), state)
		assert.Error(t, err)
		assert.Nil(t, resultState)

		// Test LoadComputeIntrinsic with non-existent address
		nonExistentAddr := make([]byte, 32)
		for i := range nonExistentAddr {
			nonExistentAddr[i] = 0xFF
		}
		loadedIntrinsic, err := compute.LoadComputeIntrinsic(nonExistentAddr, hg, hgstate.NewHypergraphState(hg), ip, bulletproofs.NewBulletproofProver(), verenc.NewMPCitHVerifiableEncryptor(1), &bulletproofs.Decaf448KeyConstructor{}, keyManager, compiler.NewBedlamCompiler())
		assert.Error(t, err)
		assert.Nil(t, loadedIntrinsic)
	})

	// Test performance with larger code deployments
	t.Run("PerformanceTest", func(t *testing.T) {
		// Generate a large code module
		largeCode := []byte(`package main

func main(a, b int) int {
	return function0(a+b)
}
`)
		// Add many functions
		for i := 0; i < 100; i++ {
			largeCode = append(largeCode, []byte(
				`
func function`+fmt.Sprintf("%d", i)+`(x int) int {
	return x * 2
}

`)...)
		}

		frameNumber := uint64(2000)
		domain := [32]byte(computeIntrinsic.Address())

		// Create deployment with input sizes
		inputSizes := [2][]int{{32}, {32}}
		deployment, err := compute.NewCodeDeployment(domain, largeCode, [2]string{"qcl:Int", "qcl:Int"}, inputSizes, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		// Prove the deployment
		err = deployment.Prove(frameNumber)
		require.NoError(t, err)

		// Verify cost scales with size
		cost, err := deployment.GetCost()
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(int64(len(deployment.Circuit))), cost)

		// Test serialization performance
		data, err := deployment.ToBytes()
		require.NoError(t, err)

		// Test deserialization
		newDeployment := &compute.CodeDeployment{}
		err = newDeployment.FromBytes(data, compiler.NewBedlamCompiler())
		require.NoError(t, err)
		assert.Equal(t, deployment.Circuit, newDeployment.Circuit)
	})
}

// Test the integration between compute intrinsic and hypergraph storage
func TestComputeIntrinsic_HypergraphIntegration(t *testing.T) {
	// Setup
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/hypergraph"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/hypergraph"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)

	keyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})

	// Create compute intrinsic
	bp := bulletproofs.NewBulletproofProver()
	decaf := &bulletproofs.Decaf448KeyConstructor{}
	_, err := compute.NewComputeIntrinsic(
		&compute.ComputeIntrinsicConfiguration{ReadPublicKey: make([]byte, 57), WritePublicKey: make([]byte, 57)},
		hg,
		ip,
		bp,
		ve,
		decaf,
		keyManager,
		compiler.NewBedlamCompiler(),
	)
	require.NoError(t, err)

	// Test hypergraph vertex creation
	t.Run("VertexCreation", func(t *testing.T) {
		sourceCode := []byte(`package main
func main(a, b int) {}`)

		frameNumber := uint64(1)
		domain := [32]byte{1, 2, 3}

		inputSizes := [2][]int{{1}, {1}}
		deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, inputSizes, []string{}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		// Prove the deployment
		err = deployment.Prove(frameNumber)
		require.NoError(t, err)

		// Create state and materialize
		state := hgstate.NewHypergraphState(hg)
		resultState, err := deployment.Materialize(1, state)
		require.NoError(t, err)

		// Commit changes
		err = resultState.Commit()
		require.NoError(t, err)

		// Verify vertex was created in hypergraph
		codeAddressBI, err := poseidon.HashBytes(
			slices.Concat(domain[:], deployment.Circuit),
		)
		require.NoError(t, err)
		codeAddress := codeAddressBI.FillBytes(make([]byte, 32))

		vertexAddr := slices.Concat(domain[:], codeAddress)
		vertex, err := hg.GetVertex([64]byte(vertexAddr))
		require.NoError(t, err)
		require.NotNil(t, vertex)

		// Verify the vertex data
		tree, err := hg.GetVertexData([64]byte(vertexAddr))
		require.NoError(t, err)

		sourceData, err := tree.Get([]byte{0 << 2})
		require.NoError(t, err)
		assert.Equal(t, deployment.Circuit, sourceData)
	})
}

// Test compute intrinsic with cryptographic operations
func TestComputeIntrinsic_CryptoOperations(t *testing.T) {
	// Create key manager with keys
	keyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})

	// Test vector commitment operations
	t.Run("VectorCommitmentInCompute", func(t *testing.T) {
		tree := &qcrypto.VectorCommitmentTree{}

		// Insert test data
		testData := []struct {
			index []byte
			data  []byte
			size  *big.Int
		}{
			{[]byte{0}, []byte("data0"), big.NewInt(5)},
			{[]byte{1}, []byte("data1"), big.NewInt(5)},
			{[]byte{2}, []byte("data2"), big.NewInt(5)},
		}

		for _, td := range testData {
			err := tree.Insert(td.index, td.data, nil, td.size)
			require.NoError(t, err)
		}

		// Get commitment
		l, _ := zap.NewProduction()
		ip := bls48581.NewKZGInclusionProver(l)
		commitment := tree.Commit(ip, false)
		require.NotNil(t, commitment)

		// Verify data retrieval
		for _, td := range testData {
			retrieved, err := tree.Get(td.index)
			require.NoError(t, err)
			assert.Equal(t, td.data, retrieved)
		}
	})

	// Test CodeExecute operation
	t.Run("CodeExecute", func(t *testing.T) {
		// Create a BulletproofProver for payments
		dc := &bulletproofs.Decaf448KeyConstructor{}
		bp := &bulletproofs.Decaf448BulletproofProver{}

		vk, _ := dc.New()

		l, _ := zap.NewProduction()
		ip := bls48581.NewKZGInclusionProver(l)
		s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		ve := verenc.NewMPCitHVerifiableEncryptor(1)
		hg := hypergraph.NewHypergraph(
			l,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
			ip,
			[]int{},
			&tests.Nopthenticator{},
		)
		km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)

		// First, deploy two circuits that we'll execute later
		domain := [32]byte{1, 2, 3, 4, 5}

		// Deploy first circuit
		circuit1Code := []byte(`package main
func main(a int, b int) int {
	return a * b
}`)

		inputSizes1 := [2][]int{{32}, {32}}
		deployment1, err := compute.NewCodeDeployment(domain, circuit1Code, [2]string{"qcl:Int", "qcl:Int"}, inputSizes1, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		err = deployment1.Prove(token.FRAME_2_1_CUTOVER + 1)
		require.NoError(t, err)

		// Materialize first circuit
		state := hgstate.NewHypergraphState(hg)
		newst, err := deployment1.Materialize(token.FRAME_2_1_CUTOVER+1, state)
		state = newst.(*hgstate.HypergraphState)
		require.NoError(t, err)

		// Calculate first circuit address
		circuit1AddressBI, err := poseidon.HashBytes(
			slices.Concat(domain[:], deployment1.Circuit),
		)
		require.NoError(t, err)
		circuit1Address := circuit1AddressBI.FillBytes(make([]byte, 32))

		// Deploy second circuit
		circuit2Code := []byte(`package main
func main(a int, b int) int {
	return a + b
}`)

		inputSizes2 := [2][]int{{32}, {32}}
		deployment2, err := compute.NewCodeDeployment(domain, circuit2Code, [2]string{"qcl:Int", "qcl:Int"}, inputSizes2, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
		require.NoError(t, err)

		err = deployment2.Prove(token.FRAME_2_1_CUTOVER + 2)
		require.NoError(t, err)

		// Materialize second circuit
		newst, err = deployment2.Materialize(token.FRAME_2_1_CUTOVER+2, state)
		require.NoError(t, err)
		state = newst.(*hgstate.HypergraphState)

		// Calculate second circuit address
		circuit2AddressBI, err := poseidon.HashBytes(
			slices.Concat(domain[:], deployment2.Circuit),
		)
		require.NoError(t, err)
		circuit2Address := circuit2AddressBI.FillBytes(make([]byte, 32))

		// Commit the deployed circuits
		err = state.Commit()
		require.NoError(t, err)

		// Create test data
		rendezvous := [32]byte{6, 7, 8, 9, 10}

		// Create CodeExecute instance with the deployed circuit addresses
		codeExecute := compute.NewCodeExecute(
			domain,
			vk.Public(),
			vk.Private(),
			rendezvous,
			[]*compute.ExecuteOperation{
				{
					Application: compute.Application{
						Address:          circuit1Address,
						ExecutionContext: compute.ExecutionContextExtrinsic,
					},
					Identifier:   []byte("op1"),
					Dependencies: [][]byte{},
				},
				{
					Application: compute.Application{
						Address:          circuit2Address,
						ExecutionContext: compute.ExecutionContextExtrinsic,
					},
					Identifier:   []byte("op2"),
					Dependencies: [][]byte{},
				},
			},
			hg,
			bp,
			ip,
			ve,
			dc,
			keyManager,
		)

		// Test Prove
		err = codeExecute.Prove(1)
		require.NoError(t, err)
		require.NotEmpty(t, codeExecute.ProofOfPayment[0])
		require.NotEmpty(t, codeExecute.ProofOfPayment[1])

		// Test Verify
		valid, err := codeExecute.Verify(1)
		require.NoError(t, err)
		assert.True(t, valid)

		// Test GetCost
		cost, err := codeExecute.GetCost()
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(69881), cost)

		// Test serialization
		serialized, err := codeExecute.ToBytes()
		require.NoError(t, err)

		// Test deserialization
		newCodeExecute := &compute.CodeExecute{}
		err = newCodeExecute.FromBytes(serialized, hg, bp, ip, ve, dc, km, schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, ip))
		require.NoError(t, err)
		assert.Equal(t, codeExecute.Domain, newCodeExecute.Domain)
		assert.Equal(t, codeExecute.Rendezvous, newCodeExecute.Rendezvous)

		// Test Materialize
		state = hgstate.NewHypergraphState(hg)
		resultState, err := codeExecute.Materialize(1, state)
		require.NoError(t, err)
		require.NotNil(t, resultState)

		// Commit the state
		err = resultState.Commit()
		require.NoError(t, err)

		// Verify the rendezvous was stored
		tree, err := hg.GetVertexData([64]byte(slices.Concat(codeExecute.Domain[:], codeExecute.Rendezvous[:])))
		require.NoError(t, err)

		rendezvousData, err := tree.Get([]byte{0 << 2})
		require.NoError(t, err)
		assert.Equal(t, rendezvous[:], rendezvousData)
	})
}
