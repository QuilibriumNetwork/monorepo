package engines_test

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/engines"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

func TestCreateExecutionEngine(t *testing.T) {
	// Create test dependencies
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockClockStore := new(mocks.MockClockStore)
	mockShardsStore := new(mocks.MockShardsStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)
	mockCompiler := new(mocks.MockCompiler)

	tests := []struct {
		name          string
		engineType    string
		expectedName  string
		expectedError bool
		errorContains string
	}{
		{
			name:         "create global engine",
			engineType:   string(engines.EngineTypeGlobal),
			expectedName: "global",
		},
		{
			name:         "create compute engine",
			engineType:   string(engines.EngineTypeCompute),
			expectedName: "compute",
		},
		{
			name:         "create token engine",
			engineType:   string(engines.EngineTypeToken),
			expectedName: "token",
		},
		{
			name:         "create hypergraph engine",
			engineType:   string(engines.EngineTypeHypergraph),
			expectedName: "hypergraph",
		},
		{
			name:          "unknown engine type",
			engineType:    "unknown",
			expectedError: true,
			errorContains: "unknown engine type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the GetVertex calls for intrinsic checks
			mockHG.On("GetVertex", mock.Anything).Return(nil, errors.New("not found"))

			engine, err := engines.CreateExecutionEngine(
				engines.EngineType(tt.engineType),
				&config.P2PConfig{Network: 99},
				logger,
				mockHG,
				mockClockStore,
				mockShardsStore,
				mockKeyManager,
				mockInclusionProver,
				mockBulletproofProver,
				mockVerEnc,
				mockDecaf,
				mockCompiler,
				engines.GlobalMode,
			)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, engine)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, engine)
				assert.Equal(t, tt.expectedName, engine.GetName())
			}
		})
	}
}

func TestCreateAllEngines(t *testing.T) {
	// Create test dependencies
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockClockStore := new(mocks.MockClockStore)
	mockShardsStore := new(mocks.MockShardsStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)
	mockCompiler := new(mocks.MockCompiler)

	engines, err := engines.CreateAllEngines(
		logger,
		&config.P2PConfig{Network: 99},
		mockHG,
		mockClockStore,
		mockShardsStore,
		mockKeyManager,
		mockInclusionProver,
		mockBulletproofProver,
		mockVerEnc,
		mockDecaf,
		mockCompiler,
		true, // includeGlobal
	)
	// CreateAllEngines doesn't return error, it just logs warnings
	require.NoError(t, err)

	// Verify we got 4 engines (global, compute, token, hypergraph)
	assert.Len(t, engines, 4)

	// Check each engine type is present
	engineTypes := make(map[string]bool)
	for _, engine := range engines {
		engineTypes[engine.GetName()] = true
	}

	assert.True(t, engineTypes["global"])
	assert.True(t, engineTypes["compute"])
	assert.True(t, engineTypes["token"])
	assert.True(t, engineTypes["hypergraph"])
}
