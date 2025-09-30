package engines

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type EngineType string

const (
	EngineTypeGlobal     EngineType = "global"
	EngineTypeCompute    EngineType = "compute"
	EngineTypeToken      EngineType = "token"
	EngineTypeHypergraph EngineType = "hypergraph"
)

var DefaultFeeMarket *fees.Policy

func init() {
	DefaultFeeMarket = &fees.Policy{
		ProducerDomain:          token.QUIL_TOKEN_ADDRESS,
		ConsumeDeploy:           true,
		ConsumeUpdate:           true,
		ConsumeTx:               true,
		ConsumePendingTx:        true,
		ConsumeMintTx:           false, // mint executes free
		ConsumeComputeDeploy:    true,
		ConsumeComputeUpdate:    true,
		ConsumeCodeDeploy:       true,
		ConsumeCodeExecute:      true,
		ConsumeCodeFinalize:     true,
		ConsumeHypergraphDeploy: true,
		ConsumeHypergraphUpdate: true,
		ConsumeVertexAdd:        true,
		ConsumeVertexRemove:     true,
		ConsumeHyperedgeAdd:     true,
		ConsumeHyperedgeRemove:  true,
	}
}

// CreateExecutionEngine creates the specified type of execution engine
func CreateExecutionEngine(
	engineType EngineType,
	config *config.P2PConfig,
	logger *zap.Logger,
	hypergraph hypergraph.Hypergraph,
	clockStore store.ClockStore,
	shardsStore store.ShardsStore,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	mode ExecutionMode,
) (execution.ShardExecutionEngine, error) {
	switch engineType {
	case EngineTypeGlobal:
		return NewGlobalExecutionEngine(
			logger,
			config,
			hypergraph,
			clockStore,
			shardsStore,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
		)
	case EngineTypeCompute:
		return NewComputeExecutionEngine(
			logger,
			hypergraph,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
			compiler,
			mode,
		)
	case EngineTypeToken:
		return NewTokenExecutionEngine(
			logger,
			hypergraph,
			clockStore,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
			mode,
		)
	case EngineTypeHypergraph:
		return NewHypergraphExecutionEngine(
			logger,
			hypergraph,
			clockStore,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
			mode,
		)
	default:
		return nil, errors.Errorf("unknown engine type: %s", engineType)
	}
}

// CreateAllEngines creates all available execution engines
func CreateAllEngines(
	logger *zap.Logger,
	config *config.P2PConfig,
	hypergraph hypergraph.Hypergraph,
	clockStore store.ClockStore,
	shardsStore store.ShardsStore,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	includeGlobal bool,
) ([]execution.ShardExecutionEngine, error) {
	engines := make([]execution.ShardExecutionEngine, 0, 4)

	mode := ApplicationMode

	// Create global engine if requested
	if includeGlobal {
		mode = GlobalMode
		globalEngine, err := CreateExecutionEngine(
			EngineTypeGlobal,
			config,
			logger.With(zap.String("engine", "global")),
			hypergraph,
			clockStore,
			shardsStore,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
			compiler,
			mode,
		)
		if err != nil {
			return nil, errors.Wrap(err, "create all engines")
		}
		engines = append(engines, globalEngine)
	}

	// Create other engines
	for _, engineType := range []EngineType{
		EngineTypeCompute,
		EngineTypeToken,
		EngineTypeHypergraph,
	} {
		engine, err := CreateExecutionEngine(
			engineType,
			config,
			logger.With(zap.String("engine", string(engineType))),
			hypergraph,
			clockStore,
			shardsStore,
			keyManager,
			inclusionProver,
			bulletproofProver,
			verEnc,
			decafConstructor,
			compiler,
			mode,
		)
		if err != nil {
			logger.Warn(
				"failed to create engine",
				zap.String("engine", string(engineType)),
				zap.Error(err),
			)
			continue
		}
		engines = append(engines, engine)
	}

	return engines, nil
}
