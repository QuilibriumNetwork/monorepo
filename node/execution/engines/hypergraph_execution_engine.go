package engines

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/fees"
	hypergraphintrinsic "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type HypergraphExecutionEngine struct {
	logger            *zap.Logger
	hypergraph        hypergraph.Hypergraph
	clockStore        store.ClockStore
	keyManager        keys.KeyManager
	inclusionProver   crypto.InclusionProver
	bulletproofProver crypto.BulletproofProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor

	// State
	intrinsics      map[string]intrinsics.Intrinsic
	intrinsicsMutex sync.RWMutex
	mode            ExecutionMode
	mu              sync.RWMutex
	stopChan        chan struct{}
}

func NewHypergraphExecutionEngine(
	logger *zap.Logger,
	hypergraph hypergraph.Hypergraph,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	mode ExecutionMode,
) (*HypergraphExecutionEngine, error) {
	return &HypergraphExecutionEngine{
		logger:            logger,
		hypergraph:        hypergraph,
		clockStore:        clockStore,
		keyManager:        keyManager,
		inclusionProver:   inclusionProver,
		bulletproofProver: bulletproofProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		intrinsics:        make(map[string]intrinsics.Intrinsic),
		mode:              mode,
	}, nil
}

func (e *HypergraphExecutionEngine) GetName() string {
	return "hypergraph"
}

// Prove implements execution.ShardExecutionEngine.
func (e *HypergraphExecutionEngine) Prove(
	domain []byte,
	frameNumber uint64,
	message []byte,
) (*protobufs.MessageRequest, error) {
	return nil, errors.New("unimplemented")
}

func (e *HypergraphExecutionEngine) GetCost(message []byte) (*big.Int, error) {
	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "get cost")
	}

	request := &protobufs.MessageRequest{}
	err := request.FromCanonicalBytes(message)
	if err != nil {
		return nil, errors.Wrap(err, "get cost")
	}

	switch req := request.Request.(type) {
	case *protobufs.MessageRequest_HypergraphDeploy:
		deploy, err := hypergraphintrinsic.HypergraphDeployFromProtobuf(
			req.HypergraphDeploy,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return big.NewInt(int64(
			len(deploy.RDFSchema) +
				len(deploy.Config.ReadPublicKey) +
				len(deploy.Config.WritePublicKey) +
				len(deploy.Config.OwnerPublicKey),
		)), nil

	case *protobufs.MessageRequest_HypergraphUpdate:
		update, err := hypergraphintrinsic.HypergraphUpdateFromProtobuf(
			req.HypergraphUpdate,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return big.NewInt(int64(
			len(update.RDFSchema) +
				len(update.Config.ReadPublicKey) +
				len(update.Config.WritePublicKey) +
				len(update.Config.OwnerPublicKey),
		)), nil

	case *protobufs.MessageRequest_VertexAdd:
		vertexAdd, err := hypergraphintrinsic.VertexAddFromProtobuf(
			req.VertexAdd,
			nil,
			nil,
			nil,
			e.verEnc,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return vertexAdd.GetCost()
	case *protobufs.MessageRequest_VertexRemove:
		vertexRemove, err := hypergraphintrinsic.VertexRemoveFromProtobuf(
			req.VertexRemove,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return vertexRemove.GetCost()
	case *protobufs.MessageRequest_HyperedgeAdd:
		hyperedgeAdd, err := hypergraphintrinsic.HyperedgeAddFromProtobuf(
			req.HyperedgeAdd,
			nil,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return hyperedgeAdd.GetCost()
	case *protobufs.MessageRequest_HyperedgeRemove:
		hyperedgeRemove, err := hypergraphintrinsic.HyperedgeRemoveFromProtobuf(
			req.HyperedgeRemove,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return hyperedgeRemove.GetCost()
	}

	return big.NewInt(0), nil
}

func (e *HypergraphExecutionEngine) GetCapabilities() []*protobufs.Capability {
	// Protocol identifier: 0x00030001 (hypergraph protocol v1)
	// High 3 bytes: 0x000300 = hypergraph protocol
	// Low byte: 0x01 = version 1
	return []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x00030001,
			AdditionalMetadata: []byte{},
		},
		// Double Ratchet protocol (0x0101 = 257 = 1<<8 + 1)
		{
			ProtocolIdentifier: 0x0101,
			AdditionalMetadata: []byte{},
		},
		// Triple Ratchet protocol (0x0201 = 513 = 2<<8 + 1)
		{
			ProtocolIdentifier: 0x0201,
			AdditionalMetadata: []byte{},
		},
		// Onion Routing protocol (0x0301 = 769 = 3<<8 + 1)
		{
			ProtocolIdentifier: 0x0301,
			AdditionalMetadata: []byte{},
		},
	}
}

func (e *HypergraphExecutionEngine) Start() <-chan error {
	errChan := make(chan error, 1)

	e.mu.Lock()
	e.stopChan = make(chan struct{}, 1)
	e.mu.Unlock()

	go func() {
		e.logger.Info("starting hypergraph execution engine")

		// Main loop
		for {
			select {
			case <-e.stopChan:
				e.logger.Info("stopping hypergraph execution engine")
				return
			}
		}
	}()

	return errChan
}

func (e *HypergraphExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		e.logger.Info(
			"stopping hypergraph execution engine",
			zap.Bool("force", force),
		)

		// Signal stop if we have a stopChan
		e.mu.RLock()
		if e.stopChan != nil {
			select {
			case <-e.stopChan:
				// Already closed
			default:
				close(e.stopChan)
			}
		}
		e.mu.RUnlock()

		close(errChan)
	}()

	return errChan
}

func (e *HypergraphExecutionEngine) ValidateMessage(
	frameNumber uint64,
	address []byte,
	message []byte,
) error {
	if len(message) < 4 {
		return errors.Wrap(errors.New("invalid message"), "validate message")
	}

	// Read the type prefix to determine if it's a bundle or individual operation
	typePrefix := binary.BigEndian.Uint32(message[:4])

	// Check if it's a message bundle
	if typePrefix == protobufs.MessageBundleType {
		err := e.validateBundle(frameNumber, address, message)
		if err != nil {
			return errors.Wrap(err, "validate message")
		}

		return nil
	} else if typePrefix != protobufs.MessageRequestType {
		return errors.Wrap(
			errors.New("unsupported message type"),
			"validate message",
		)
	}

	request := &protobufs.MessageRequest{}
	err := request.FromCanonicalBytes(message)
	if err != nil {
		return errors.Wrap(err, "validate message")
	}

	// Otherwise, delegate to individual message validation
	err = e.validateIndividualMessage(frameNumber, address, request, false)
	if err != nil {
		return errors.Wrap(err, "validate message")
	}

	return nil
}

func (e *HypergraphExecutionEngine) validateBundle(
	frameNumber uint64,
	address []byte,
	message []byte,
) error {
	// Parse the bundle
	bundle := &protobufs.MessageBundle{}
	if err := bundle.FromCanonicalBytes(message); err != nil {
		return errors.Wrap(err, "validate bundle")
	}

	// Validate fees distribute correctly
	feeQueue := fees.CollectBundleFees(bundle, DefaultFeeMarket)
	consumers := fees.CountFeeConsumers(bundle, DefaultFeeMarket)
	if err := fees.SanityCheck(feeQueue, consumers); err != nil {
		return errors.Wrap(err, "validate bundle")
	}

	// Validate each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		e.logger.Debug(
			"validating bundled operation",
			zap.Int("operation", i),
			zap.String("address", hex.EncodeToString(address)),
		)

		// Check if this is a hypergraph operation type
		isHypergraphOp := op.GetHypergraphDeploy() != nil ||
			op.GetHypergraphUpdate() != nil ||
			op.GetVertexAdd() != nil ||
			op.GetVertexRemove() != nil ||
			op.GetHyperedgeAdd() != nil ||
			op.GetHyperedgeRemove() != nil

		if !isHypergraphOp {
			// Skip non-hypergraph operations
			e.logger.Debug(
				"skipping non-hypergraph operation in bundle",
				zap.Int("operation", i),
			)
			continue
		}

		// Validate this operation individually
		err := e.validateIndividualMessage(
			frameNumber,
			address,
			op,
			true,
		)
		if err != nil {
			return errors.Wrap(err, "validate bundle")
		}
	}

	return nil
}

// validateIndividualMessage validates a single message without bundle handling
func (e *HypergraphExecutionEngine) validateIndividualMessage(
	frameNumber uint64,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
) error {
	isHypergraphOp := false
	isUpdate := false
	var err error
	switch message.Request.(type) {
	case *protobufs.MessageRequest_HypergraphDeploy:
		isHypergraphOp = true
		isUpdate = true
	case *protobufs.MessageRequest_HypergraphUpdate:
		isHypergraphOp = true
		isUpdate = true
	case *protobufs.MessageRequest_VertexAdd:
		isHypergraphOp = true
	case *protobufs.MessageRequest_VertexRemove:
		isHypergraphOp = true
	case *protobufs.MessageRequest_HyperedgeAdd:
		isHypergraphOp = true
	case *protobufs.MessageRequest_HyperedgeRemove:
		isHypergraphOp = true
	}
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	if !isHypergraphOp {
		return errors.Wrap(
			errors.New("invalid type"),
			"validate individual message",
		)
	}

	// For hypergraph deploy operations, just validate the structure
	if isUpdate && fromBundle {
		return errors.Wrap(message.Validate(), "validate individual message")
	}

	// For other operations, try to load the intrinsic and validate
	addressStr := string(address)
	e.intrinsicsMutex.RLock()
	intrinsic, exists := e.intrinsics[addressStr]
	e.intrinsicsMutex.RUnlock()

	if !exists {
		// Try to load existing intrinsic
		loaded, err := hypergraphintrinsic.LoadHypergraphIntrinsic(
			address,
			e.hypergraph,
			e.inclusionProver,
			e.keyManager,
			nil, // Signer can and should be nil for verifier path
			e.verEnc,
		)
		if err != nil {
			return errors.Wrap(err, "validate individual message")
		}

		e.intrinsicsMutex.Lock()
		e.intrinsics[addressStr] = loaded
		e.intrinsicsMutex.Unlock()
		intrinsic = loaded
	}

	payload := []byte{}
	switch message.Request.(type) {
	case *protobufs.MessageRequest_HypergraphDeploy:
		err = errors.New("deployments must be bundled")
	case *protobufs.MessageRequest_HypergraphUpdate:
		err = errors.New("updates must be bundled")
	case *protobufs.MessageRequest_VertexAdd:
		payload, err = message.GetVertexAdd().ToCanonicalBytes()
	case *protobufs.MessageRequest_VertexRemove:
		payload, err = message.GetVertexRemove().ToCanonicalBytes()
	case *protobufs.MessageRequest_HyperedgeAdd:
		payload, err = message.GetHyperedgeAdd().ToCanonicalBytes()
	case *protobufs.MessageRequest_HyperedgeRemove:
		payload, err = message.GetHyperedgeRemove().ToCanonicalBytes()
	default:
		err = errors.New("unsupported message type")
	}
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	// Validate the operation
	err = intrinsic.Validate(frameNumber, payload)
	return errors.Wrap(err, "validate individual message")
}

func (e *HypergraphExecutionEngine) ProcessMessage(
	frameNumber uint64,
	feeMultiplier *big.Int,
	address []byte,
	message []byte,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "process message")
	}

	// Read the type prefix to determine if it's a bundle or individual operation
	typePrefix := binary.BigEndian.Uint32(message[:4])

	// Check if it's a message bundle
	if typePrefix == protobufs.MessageBundleType {
		result, err := e.handleBundle(
			frameNumber,
			feeMultiplier,
			address,
			message,
			state,
		)
		if err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		return result, nil
	}

	return nil, errors.Wrap(
		errors.New("unsupported message type"),
		"process message",
	)
}

func (e *HypergraphExecutionEngine) handleBundle(
	frameNumber uint64,
	feeMultiplier *big.Int,
	address []byte,
	payload []byte,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	// Parse the bundle
	bundle := &protobufs.MessageBundle{}
	if err := bundle.FromCanonicalBytes(payload); err != nil {
		return nil, errors.Wrap(err, "handle bundle")
	}

	responses := &execution.ProcessMessageResult{}

	// Validate fees distribute correctly
	feeQueue := fees.CollectBundleFees(bundle, DefaultFeeMarket)
	consumers := fees.CountFeeConsumers(bundle, DefaultFeeMarket)
	if err := fees.SanityCheck(feeQueue, consumers); err != nil {
		return nil, errors.Wrap(err, "handle bundle")
	}

	// Process each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		e.logger.Debug(
			"processing bundled operation",
			zap.Int("operation", i),
			zap.String("address", hex.EncodeToString(address)),
		)

		// Check if this is a hypergraph operation type
		isHypergraphOp := op.GetHypergraphDeploy() != nil ||
			op.GetHypergraphUpdate() != nil ||
			op.GetVertexAdd() != nil ||
			op.GetVertexRemove() != nil ||
			op.GetHyperedgeAdd() != nil ||
			op.GetHyperedgeRemove() != nil

		if !isHypergraphOp {
			if fees.NeedsOneFee(op, DefaultFeeMarket) {
				_ = fees.PopFee(&feeQueue)
			}

			// Skip non-hypergraph operations
			// They are retained in the bundle for reference but not processed here
			e.logger.Debug(
				"skipping non-hypergraph operation in bundle",
				zap.Int("operation", i),
			)
			continue
		}

		feeForOp := big.NewInt(0)
		if fees.NeedsOneFee(op, DefaultFeeMarket) {
			// Pre-checked; defensive guard helpful for future policy changes
			if len(feeQueue) == 0 {
				return nil, errors.Wrapf(
					errors.New("fee underflow"),
					"handle bundle: op %d required a fee but none left",
					i,
				)
			}
			feeForOp = fees.PopFee(&feeQueue)
		}

		// Process the individual operation by calling ProcessMessage recursively
		// but with the individual operation payload
		opResponses, err := e.processIndividualMessage(
			frameNumber,
			feeForOp,
			feeMultiplier,
			address,
			op,
			true,
			state,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "handle bundle: operation %d failed", i)
		}

		// Collect responses
		responses.Messages = append(responses.Messages, opResponses.Messages...)
		responses.State = state
	}

	e.logger.Info(
		"processed message bundle",
		zap.Int("operations", len(bundle.Requests)),
		zap.String("address", hex.EncodeToString(address)),
		zap.Int("responses", len(responses.Messages)),
	)

	return responses, nil
}

// processIndividualMessage processes a single message without bundle handling
func (e *HypergraphExecutionEngine) processIndividualMessage(
	frameNumber uint64,
	feePaid *big.Int,
	feeMultiplier *big.Int,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	payload := []byte{}
	var err error
	switch message.Request.(type) {
	case *protobufs.MessageRequest_HypergraphDeploy:
		payload, err = message.GetHypergraphDeploy().ToCanonicalBytes()
	case *protobufs.MessageRequest_HypergraphUpdate:
		payload, err = message.GetHypergraphUpdate().ToCanonicalBytes()
	case *protobufs.MessageRequest_VertexAdd:
		payload, err = message.GetVertexAdd().ToCanonicalBytes()
	case *protobufs.MessageRequest_VertexRemove:
		payload, err = message.GetVertexRemove().ToCanonicalBytes()
	case *protobufs.MessageRequest_HyperedgeAdd:
		payload, err = message.GetHyperedgeAdd().ToCanonicalBytes()
	case *protobufs.MessageRequest_HyperedgeRemove:
		payload, err = message.GetHyperedgeRemove().ToCanonicalBytes()
	default:
		err = errors.New("unsupported message type")
	}
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	// Read the type prefix to determine if it's a deploy or operation
	typePrefix := binary.BigEndian.Uint32(payload[:4])

	// Check if it's a hypergraph deploy or update
	if typePrefix == protobufs.HypergraphDeploymentType ||
		typePrefix == protobufs.HypergraphUpdateType {
		if fromBundle {
			return e.handleDeploy(address, payload, frameNumber, feePaid, state)
		} else {
			return nil, errors.Wrap(
				errors.New("deploy or update messages must be bundled"),
				"process individual message",
			)
		}
	}

	// In global mode, only deploy messages are valid after deployment has
	// occurred (but bundles can contain mixed operations)
	if e.mode == GlobalMode {
		_, err := e.hypergraph.GetVertex(
			[64]byte(slices.Concat(address, bytes.Repeat([]byte{0xff}, 32))),
		)
		if err == nil || !fromBundle {
			return nil, errors.Wrap(
				errors.New("non-deploy messages not allowed in global mode"),
				"process individual message",
			)
		}
	}

	// Otherwise, try to handle it as an operation on existing intrinsic
	addressStr := string(address)
	e.intrinsicsMutex.RLock()
	intrinsic, exists := e.intrinsics[addressStr]
	e.intrinsicsMutex.RUnlock()

	if !exists {
		// Try to load existing intrinsic
		loaded, err := hypergraphintrinsic.LoadHypergraphIntrinsic(
			address,
			e.hypergraph,
			e.inclusionProver,
			e.keyManager,
			nil, // Signer can and should be nil for verifier path
			e.verEnc,
		)
		if err != nil {
			return nil, errors.Wrap(err, "process individual message")
		}

		e.intrinsicsMutex.Lock()
		e.intrinsics[addressStr] = loaded
		e.intrinsicsMutex.Unlock()
		intrinsic = loaded
	}

	err = e.validateIndividualMessage(frameNumber, address, message, fromBundle)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	// Process the operation
	newState, err := intrinsic.InvokeStep(
		frameNumber,
		payload,
		feePaid,
		feeMultiplier,
		state,
	)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	newState, err = intrinsic.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	e.logger.Debug(
		"processed individual message",
		zap.String("address", hex.EncodeToString(address)),
		zap.Any("state", newState),
	)

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    newState,
	}, nil
}

func (e *HypergraphExecutionEngine) handleDeploy(
	address []byte,
	payload []byte,
	frameNumber uint64,
	feePaid *big.Int,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	var intrinsic *hypergraphintrinsic.HypergraphIntrinsic
	if bytes.Equal(address, hypergraphintrinsic.HYPERGRAPH_BASE_DOMAIN[:]) {
		// Deserialize the deploy arguments
		deployPb := &protobufs.HypergraphDeploy{}
		err := deployPb.FromCanonicalBytes(payload)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		deployArgs, err := hypergraphintrinsic.HypergraphDeployFromProtobuf(
			deployPb,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Create new hypergraph intrinsic
		intrinsic = hypergraphintrinsic.NewHypergraphIntrinsic(
			deployArgs.Config,
			e.hypergraph,
			e.inclusionProver,
			e.keyManager,
			nil,
			e.verEnc,
		)

		// Deploy the intrinsic
		state, err = intrinsic.Deploy(
			hypergraphintrinsic.HYPERGRAPH_BASE_DOMAIN,
			nil, // provers
			nil, // creator
			feePaid,
			deployArgs.RDFSchema,
			frameNumber,
			state,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Get the deployed address
		deployedAddress := intrinsic.Address()

		// Store the intrinsic
		e.intrinsicsMutex.Lock()
		e.intrinsics[string(deployedAddress)] = intrinsic
		e.intrinsicsMutex.Unlock()

		e.logger.Info(
			"deployed hypergraph intrinsic",
			zap.String("address", hex.EncodeToString(deployedAddress)),
		)
	} else {
		// Deserialize the update arguments
		updatePb := &protobufs.HypergraphUpdate{}
		err := updatePb.FromCanonicalBytes(payload)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Load existing hypergraph intrinsic
		intrinsic, err = hypergraphintrinsic.LoadHypergraphIntrinsic(
			address,
			e.hypergraph,
			e.inclusionProver,
			e.keyManager,
			nil,
			e.verEnc,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Deploy (update) the intrinsic
		var domain [32]byte
		copy(domain[:], address)
		state, err = intrinsic.Deploy(
			domain,
			nil, // provers
			nil, // creator
			feePaid,
			payload, // Pass the entire serialized update message
			frameNumber,
			state,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Store the intrinsic
		e.intrinsicsMutex.Lock()
		e.intrinsics[string(address)] = intrinsic
		e.intrinsicsMutex.Unlock()

		e.logger.Info(
			"updated hypergraph intrinsic",
			zap.String("address", hex.EncodeToString(address)),
		)
	}

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    state,
	}, nil
}

var _ execution.ShardExecutionEngine = (*HypergraphExecutionEngine)(nil)
