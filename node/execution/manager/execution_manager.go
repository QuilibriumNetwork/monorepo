package manager

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/engines"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	hypergraphintrinsic "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// ExecutionEngineManager manages the lifecycle and coordination of execution
// engines
type ExecutionEngineManager struct {
	builder           lifecycle.ComponentManagerBuilder
	logger            *zap.Logger
	config            *config.Config
	engines           map[string]execution.ShardExecutionEngine
	enginesMu         sync.RWMutex
	hypergraph        hypergraph.Hypergraph
	clockStore        store.ClockStore
	shardsStore       store.ShardsStore
	keyManager        keys.KeyManager
	inclusionProver   crypto.InclusionProver
	bulletproofProver crypto.BulletproofProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	compiler          compiler.CircuitCompiler
	frameProver       crypto.FrameProver
	rewardIssuance    consensus.RewardIssuance
	proverRegistry    consensus.ProverRegistry
	blsConstructor    crypto.BlsConstructor
	includeGlobal     bool
}

// NewExecutionEngineManager creates a new execution engine manager
func NewExecutionEngineManager(
	logger *zap.Logger,
	config *config.Config,
	hypergraph hypergraph.Hypergraph,
	clockStore store.ClockStore,
	shardsStore store.ShardsStore,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	frameProver crypto.FrameProver,
	rewardIssuance consensus.RewardIssuance,
	proverRegistry consensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
	includeGlobal bool,
) (*ExecutionEngineManager, error) {
	em := &ExecutionEngineManager{
		logger: logger.With(
			zap.String("component", "execution_manager"),
		),
		config:            config,
		engines:           make(map[string]execution.ShardExecutionEngine),
		hypergraph:        hypergraph,
		clockStore:        clockStore,
		shardsStore:       shardsStore,
		keyManager:        keyManager,
		inclusionProver:   inclusionProver,
		bulletproofProver: bulletproofProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		compiler:          compiler,
		frameProver:       frameProver,
		rewardIssuance:    rewardIssuance,
		proverRegistry:    proverRegistry,
		blsConstructor:    blsConstructor,
		includeGlobal:     includeGlobal,
	}

	err := em.InitializeEngines()
	if err != nil {
		return nil, err
	}

	em.builder = lifecycle.NewComponentManagerBuilder()

	for _, engine := range em.engines {
		em.builder.AddWorker(engine.Start)
	}

	return em, nil
}

// InitializeEngines creates and registers all execution engines
func (m *ExecutionEngineManager) InitializeEngines() error {
	m.logger.Info("initializing execution engines")

	// Create all execution engines
	allEngines, err := engines.CreateAllEngines(
		m.logger,
		m.config.P2P,
		m.hypergraph,
		m.clockStore,
		m.shardsStore,
		m.keyManager,
		m.inclusionProver,
		m.bulletproofProver,
		m.verEnc,
		m.decafConstructor,
		m.compiler,
		m.frameProver,
		m.rewardIssuance,
		m.proverRegistry,
		m.blsConstructor,
		m.includeGlobal,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create execution engines")
	}

	// Register each engine
	m.enginesMu.Lock()
	defer m.enginesMu.Unlock()

	for _, engine := range allEngines {
		name := engine.GetName()
		if _, exists := m.engines[name]; exists {
			return errors.Errorf("duplicate engine name: %s", name)
		}
		m.engines[name] = engine
		m.logger.Info("registered execution engine", zap.String("engine", name))
	}

	m.logger.Info(
		"initialized execution engines",
		zap.Int("count", len(m.engines)),
	)
	return nil
}

// StartAll starts all registered execution engines
func (m *ExecutionEngineManager) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	m.logger.Info("starting all execution engines")
	m.builder.Build().Start(ctx)
	ready()
	<-ctx.Done()
	m.logger.Info("all execution engines stopped")
}

// GetEngine returns a specific execution engine by name
func (m *ExecutionEngineManager) GetEngine(
	name string,
) (execution.ShardExecutionEngine, bool) {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	engine, exists := m.engines[name]
	return engine, exists
}

// GetAllEngines returns all registered execution engines
func (
	m *ExecutionEngineManager,
) GetAllEngines() map[string]execution.ShardExecutionEngine {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	// Return a copy to prevent external modification
	enginesCopy := make(map[string]execution.ShardExecutionEngine)
	for name, engine := range m.engines {
		enginesCopy[name] = engine
	}
	return enginesCopy
}

// GetSupportedCapabilities returns all unique capabilities supported by the
// registered engines
func (
	m *ExecutionEngineManager,
) GetSupportedCapabilities() []*protobufs.Capability {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	// Use a map to track unique protocol identifiers
	uniqueCapabilities := make(map[uint32]*protobufs.Capability)

	// Iterate through all registered engines
	for name, engine := range m.engines {
		m.logger.Debug(
			"collecting capabilities from engine",
			zap.String("engine", name),
		)

		// Get capabilities from the engine
		capabilities := engine.GetCapabilities()

		// Add each capability to the map, using protocol identifier as key to
		// ensure uniqueness
		for _, capability := range capabilities {
			if capability != nil {
				if _, ok := uniqueCapabilities[capability.ProtocolIdentifier]; !ok {
					uniqueCapabilities[capability.ProtocolIdentifier] = capability
				}
			}
		}
	}

	// Convert map to slice
	result := make([]*protobufs.Capability, 0, len(uniqueCapabilities))
	for _, capability := range uniqueCapabilities {
		result = append(result, capability)
	}

	m.logger.Info("collected unique capabilities",
		zap.Int("total_unique", len(result)),
		zap.Int("engines_queried", len(m.engines)),
	)

	return result
}

func (m *ExecutionEngineManager) GetCost(message []byte) (*big.Int, error) {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "get cost")
	}

	messageType := binary.BigEndian.Uint32(message[:4])
	switch messageType {
	case protobufs.MessageBundleType:
		bundle := &protobufs.MessageBundle{}
		if err := bundle.FromCanonicalBytes(message); err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		sum := big.NewInt(0)
		for _, req := range bundle.Requests {
			cost, err := m.getRequestCost(req)
			if err != nil {
				return nil, errors.Wrap(err, "get cost")
			}
			sum.Add(sum, cost)
		}

		return sum, nil

	case protobufs.MessageRequestType:
		request := &protobufs.MessageRequest{}
		if err := request.FromCanonicalBytes(message); err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		cost, err := m.getRequestCost(request)
		return cost, errors.Wrap(err, "get cost")
	}

	return nil, errors.Wrap(errors.New("invalid message type"), "get cost")
}

func (m *ExecutionEngineManager) getRequestCost(
	request *protobufs.MessageRequest,
) (*big.Int, error) {
	requestBytes, err := request.ToCanonicalBytes()
	if err != nil {
		return nil, err
	}

	switch request.Request.(type) {
	case *protobufs.MessageRequest_Join:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Leave:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Pause:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Resume:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Confirm:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Reject:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Kick:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_Update:
		return big.NewInt(0), nil
	case *protobufs.MessageRequest_TokenDeploy:
		return m.engines["token"].GetCost(requestBytes)
	case *protobufs.MessageRequest_TokenUpdate:
		return m.engines["token"].GetCost(requestBytes)
	case *protobufs.MessageRequest_Transaction:
		return m.engines["token"].GetCost(requestBytes)
	case *protobufs.MessageRequest_PendingTransaction:
		return m.engines["token"].GetCost(requestBytes)
	case *protobufs.MessageRequest_MintTransaction:
		return m.engines["token"].GetCost(requestBytes)
	case *protobufs.MessageRequest_HypergraphDeploy:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_HypergraphUpdate:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_VertexAdd:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_VertexRemove:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_HyperedgeAdd:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_HyperedgeRemove:
		return m.engines["hypergraph"].GetCost(requestBytes)
	case *protobufs.MessageRequest_ComputeDeploy:
		return m.engines["compute"].GetCost(requestBytes)
	case *protobufs.MessageRequest_ComputeUpdate:
		return m.engines["compute"].GetCost(requestBytes)
	case *protobufs.MessageRequest_CodeDeploy:
		return m.engines["compute"].GetCost(requestBytes)
	case *protobufs.MessageRequest_CodeExecute:
		return m.engines["compute"].GetCost(requestBytes)
	case *protobufs.MessageRequest_CodeFinalize:
		return m.engines["compute"].GetCost(requestBytes)
	}

	return big.NewInt(0), nil
}

// ProcessMessage routes a message to the appropriate execution engine
func (m *ExecutionEngineManager) ProcessMessage(
	frameNumber uint64,
	feeMultiplier *big.Int,
	address []byte,
	message []byte,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	// Route to global engine for system messages
	if bytes.Equal(address, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
		if engine, exists := m.engines["global"]; exists {
			m.logger.Debug(
				"routing message to global engine",
				zap.String("address", hex.EncodeToString(address)),
			)

			timer := prometheus.NewTimer(
				executionRequestDuration.WithLabelValues("global"),
			)
			defer timer.ObserveDuration()

			result, err := engine.ProcessMessage(
				frameNumber,
				feeMultiplier,
				address,
				message,
				state,
			)
			if err != nil {
				executionRequestsTotal.WithLabelValues("global", "error").Inc()
				return nil, err
			}
			executionRequestsTotal.WithLabelValues("global", "success").Inc()
			return result, nil
		}
		executionRequestsTotal.WithLabelValues("global", "error").Inc()
		return nil, errors.Wrap(
			errors.New("global execution engine not found"),
			"process message",
		)
	}

	if m.config.P2P.Network == 0 {
		if frameNumber <= token.FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END {
			return nil, errors.Wrap(
				errors.New("enrollment period has not ended"),
				"process message",
			)
		}
	}

	route := address // buildutils:allow-slice-alias slice reassigns itself

	if !(bytes.Equal(route, compute.COMPUTE_INTRINSIC_DOMAIN[:]) ||
		bytes.Equal(route, hypergraphintrinsic.HYPERGRAPH_BASE_DOMAIN[:]) ||
		bytes.Equal(route, token.TOKEN_BASE_DOMAIN[:]) ||
		bytes.Equal(route, token.QUIL_TOKEN_ADDRESS[:])) {
		metadata := slices.Concat(
			address,
			bytes.Repeat([]byte{0xff}, 32),
		)
		vertTree, err := m.hypergraph.GetVertexData([64]byte(metadata))
		if err != nil {
			executionRequestsTotal.WithLabelValues("unknown", "error").Inc()
			return nil, errors.Wrap(
				errors.Errorf(
					"no execution engine found for address: %x",
					address,
				),
				"process message",
			)
		}

		if vertTree == nil {
			return nil, errors.Wrap(
				errors.Errorf(
					"no metadata found for address: %x",
					address,
				),
				"process message",
			)
		}

		typeDomain, err := vertTree.Get(bytes.Repeat([]byte{0xff}, 32))
		if err != nil {
			executionRequestsTotal.WithLabelValues("unknown", "error").Inc()
			return nil, errors.Wrap(
				err,
				"process message",
			)
		}

		route = typeDomain
	}

	// Check compute domain
	if bytes.Equal(route, compute.COMPUTE_INTRINSIC_DOMAIN[:]) {
		if engine, exists := m.engines["compute"]; exists {
			m.logger.Debug(
				"routing message to compute engine",
				zap.String("address", hex.EncodeToString(address)),
			)

			timer := prometheus.NewTimer(
				executionRequestDuration.WithLabelValues("compute"),
			)
			defer timer.ObserveDuration()

			result, err := engine.ProcessMessage(
				frameNumber,
				feeMultiplier,
				address,
				message,
				state,
			)
			if err != nil {
				executionRequestsTotal.WithLabelValues("compute", "error").Inc()
				return nil, err
			}
			executionRequestsTotal.WithLabelValues("compute", "success").Inc()
			return result, nil
		}
		executionRequestsTotal.WithLabelValues("compute", "error").Inc()
		return nil, errors.Wrap(
			errors.New("compute execution engine not found"),
			"process message",
		)
	}

	// Check hypergraph domain
	if bytes.Equal(route, hypergraphintrinsic.HYPERGRAPH_BASE_DOMAIN[:]) {
		if engine, exists := m.engines["hypergraph"]; exists {
			m.logger.Debug(
				"routing message to hypergraph engine",
				zap.String("address", hex.EncodeToString(address)),
			)

			timer := prometheus.NewTimer(
				executionRequestDuration.WithLabelValues("hypergraph"),
			)
			defer timer.ObserveDuration()

			result, err := engine.ProcessMessage(
				frameNumber,
				feeMultiplier,
				address,
				message,
				state,
			)
			if err != nil {
				executionRequestsTotal.WithLabelValues("hypergraph", "error").Inc()
				return nil, err
			}
			executionRequestsTotal.WithLabelValues("hypergraph", "success").Inc()
			return result, nil
		}
		executionRequestsTotal.WithLabelValues("hypergraph", "error").Inc()
		return nil, errors.Wrap(
			errors.New("hypergraph execution engine not found"),
			"process message",
		)
	}

	// Check token addresses (both QUIL token and token base domain)
	if bytes.Equal(route, token.TOKEN_BASE_DOMAIN[:]) ||
		bytes.Equal(route, token.QUIL_TOKEN_ADDRESS[:]) {
		if engine, exists := m.engines["token"]; exists {
			m.logger.Debug(
				"routing message to token engine",
				zap.String("address", hex.EncodeToString(address)),
			)

			timer := prometheus.NewTimer(
				executionRequestDuration.WithLabelValues("token"),
			)
			defer timer.ObserveDuration()

			result, err := engine.ProcessMessage(
				frameNumber,
				feeMultiplier,
				address,
				message,
				state,
			)
			if err != nil {
				executionRequestsTotal.WithLabelValues("token", "error").Inc()
				return nil, err
			}
			executionRequestsTotal.WithLabelValues("token", "success").Inc()
			return result, nil
		}
		executionRequestsTotal.WithLabelValues("token", "error").Inc()
		return nil, errors.Wrap(
			errors.New("token execution engine not found"),
			"process message",
		)
	}

	return nil, errors.Wrap(
		errors.Errorf(
			"no execution engine found for address: %x",
			address,
		),
		"process message",
	)
}

// ValidateMessage validates a message without materializing state changes
func (m *ExecutionEngineManager) Lock(
	frameNumber uint64,
	address []byte,
	message []byte,
) ([][]byte, error) {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	engine := m.selectEngine(address)
	if engine == nil {
		return nil, errors.Errorf("no execution engine found for address: %x", address)
	}

	return engine.Lock(frameNumber, address, message)
}

func (m *ExecutionEngineManager) Unlock() error {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	errs := []string{}
	for _, engine := range m.engines {
		err := engine.Unlock()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) != 0 {
		return errors.Wrap(
			errors.Errorf("multiple errors: %s", strings.Join(errs, ", ")),
			"unlock",
		)
	}

	return nil
}

// ValidateMessage validates a message without materializing state changes
func (m *ExecutionEngineManager) ValidateMessage(
	frameNumber uint64,
	address []byte,
	message []byte,
) error {
	m.enginesMu.RLock()
	defer m.enginesMu.RUnlock()

	engine := m.selectEngine(address)
	if engine == nil {
		return errors.Errorf("no execution engine found for address: %x", address)
	}

	return engine.ValidateMessage(frameNumber, address, message)
}

// selectEngine selects the appropriate execution engine based on the address
// Note: This method assumes the caller holds at least a read lock on enginesMu
func (m *ExecutionEngineManager) selectEngine(
	address []byte,
) execution.ShardExecutionEngine {
	// Route to global engine for system messages
	if bytes.Equal(address, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
		if engine, exists := m.engines["global"]; exists {
			return engine
		}
		return nil
	}

	// Route based on intrinsic domain (first 32 bytes)
	if len(address) >= 32 {
		// Check compute domain
		if bytes.Equal(address[:32], compute.COMPUTE_INTRINSIC_DOMAIN[:]) {
			if engine, exists := m.engines["compute"]; exists {
				return engine
			}
			return nil
		}

		// Check hypergraph domain
		if bytes.Equal(
			address[:32],
			hypergraphintrinsic.HYPERGRAPH_BASE_DOMAIN[:],
		) {
			if engine, exists := m.engines["hypergraph"]; exists {
				return engine
			}
			return nil
		}

		// Check token addresses (both QUIL token and token base domain)
		if bytes.Equal(address[:32], token.QUIL_TOKEN_ADDRESS) ||
			bytes.Equal(address[:32], token.TOKEN_BASE_DOMAIN[:]) {
			if engine, exists := m.engines["token"]; exists {
				return engine
			}
			return nil
		}
	}

	return nil
}
