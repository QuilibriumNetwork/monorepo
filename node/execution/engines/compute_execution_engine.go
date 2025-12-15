package engines

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

var ErrUnsupportedMessageType = errors.New("unsupported message type")

type ComputeExecutionEngine struct {
	logger            *zap.Logger
	hypergraph        hypergraph.Hypergraph
	keyManager        keys.KeyManager
	inclusionProver   crypto.InclusionProver
	bulletproofProver crypto.BulletproofProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	compiler          compiler.CircuitCompiler

	// State
	intrinsics      map[string]intrinsics.Intrinsic
	intrinsicsMutex sync.RWMutex
	mode            ExecutionMode
	mu              sync.RWMutex
	ctx             lifecycle.SignalerContext
}

func NewComputeExecutionEngine(
	logger *zap.Logger,
	hypergraph hypergraph.Hypergraph,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	compiler compiler.CircuitCompiler,
	mode ExecutionMode,
) (*ComputeExecutionEngine, error) {
	return &ComputeExecutionEngine{
		logger:            logger,
		hypergraph:        hypergraph,
		keyManager:        keyManager,
		inclusionProver:   inclusionProver,
		bulletproofProver: bulletproofProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		compiler:          compiler,
		intrinsics:        make(map[string]intrinsics.Intrinsic),
		mode:              mode,
	}, nil
}

func (e *ComputeExecutionEngine) GetName() string {
	return "compute"
}

func (e *ComputeExecutionEngine) GetCapabilities() []*protobufs.Capability {
	// Protocol identifier: 0x00010001 (compute protocol v1)
	// High 3 bytes: 0x000100 = compute protocol
	// Low byte: 0x01 = version 1
	capabilities := []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x00010001,
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
		// KZG verification protocols
		{
			ProtocolIdentifier: 0x00010101, // KZG_VERIFY_BLS48581
			AdditionalMetadata: []byte{},
		},
		// Bulletproof verification protocols for DECAF448
		{
			ProtocolIdentifier: 0x00010201, // BULLETPROOF_RANGE_VERIFY_DECAF448
			AdditionalMetadata: []byte{},
		},
		{
			ProtocolIdentifier: 0x00010301, // BULLETPROOF_SUM_VERIFY_DECAF448
			AdditionalMetadata: []byte{},
		},
		// Signature verification protocols
		{
			ProtocolIdentifier: 0x00010401, // SECP256K1_ECDSA_VERIFY
			AdditionalMetadata: []byte{},
		},
		{
			ProtocolIdentifier: 0x00010501, // ED25519_EDDSA_VERIFY
			AdditionalMetadata: []byte{},
		},
		{
			ProtocolIdentifier: 0x00010601, // ED448_EDDSA_VERIFY
			AdditionalMetadata: []byte{},
		},
		{
			ProtocolIdentifier: 0x00010701, // DECAF448_SCHNORR_VERIFY
			AdditionalMetadata: []byte{},
		},
		{
			ProtocolIdentifier: 0x00010801, // SECP256R1_ECDSA_VERIFY
			AdditionalMetadata: []byte{},
		},
	}
	return capabilities
}

func (e *ComputeExecutionEngine) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	e.logger.Info("starting compute execution engine")
	e.ctx = ctx
	ready()

	<-ctx.Done()
	e.logger.Info("stopping compute execution engine")
}

func (e *ComputeExecutionEngine) Prove(
	domain []byte,
	frameNumber uint64,
	message []byte,
) (
	*protobufs.MessageRequest,
	error,
) {
	intrinsic, err := e.tryGetIntrinsic(domain)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "prove")
	}

	request := &protobufs.MessageRequest{}
	err = request.FromCanonicalBytes(message)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	switch req := request.Request.(type) {
	case *protobufs.MessageRequest_CodeDeploy:
		deploy, err := compute.CodeDeploymentFromProtobuf(req.CodeDeploy)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		if err := deploy.Prove(frameNumber); err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_CodeDeploy{
				CodeDeploy: deploy.ToProtobuf(),
			},
		}, nil

	case *protobufs.MessageRequest_CodeExecute:
		exec, err := compute.CodeExecuteFromProtobuf(
			req.CodeExecute,
			e.hypergraph,
			e.bulletproofProver,
			e.inclusionProver,
			e.verEnc,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		if err := exec.Prove(frameNumber); err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_CodeExecute{
				CodeExecute: exec.ToProtobuf(),
			},
		}, nil

	case *protobufs.MessageRequest_CodeFinalize:
		key, err := e.keyManager.GetSigningKey("q-execution-key")
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		fin, err := compute.CodeFinalizeFromProtobuf(
			req.CodeFinalize,
			[32]byte(domain),
			e.hypergraph,
			e.bulletproofProver,
			e.inclusionProver,
			e.verEnc,
			e.keyManager,
			intrinsic.(*compute.ComputeIntrinsic).Config(),
			key.Private(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_CodeFinalize{
				CodeFinalize: fin.ToProtobuf(),
			},
		}, nil
	}

	return nil, errors.Wrap(errors.New("unsupported type"), "prove")
}

func (e *ComputeExecutionEngine) Lock(
	frameNumber uint64,
	address []byte,
	message []byte,
) ([][]byte, error) {
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		// non-applicable
		return nil, nil
	}

	if len(message) > 4 &&
		binary.BigEndian.Uint32(message[:4]) == protobufs.MessageBundleType {
		bundle := &protobufs.MessageBundle{}
		err = bundle.FromCanonicalBytes(message)
		if err != nil {
			return nil, errors.Wrap(err, "lock")
		}

		addresses := [][]byte{}
		for _, r := range bundle.Requests {
			req, err := r.ToCanonicalBytes()
			if err != nil {
				return nil, errors.Wrap(err, "lock")
			}

			addrs, err := intrinsic.Lock(frameNumber, req[8:])
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, addrs...)
		}

		return addresses, nil
	}

	addresses, err := intrinsic.Lock(frameNumber, message)
	return addresses, errors.Wrap(err, "lock")
}

func (e *ComputeExecutionEngine) Unlock() error {
	e.intrinsicsMutex.RLock()
	errs := []string{}
	for _, intrinsic := range e.intrinsics {
		err := intrinsic.Unlock()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	e.intrinsicsMutex.RUnlock()

	if len(errs) != 0 {
		return errors.Wrap(
			errors.Errorf("multiple errors: %s", strings.Join(errs, ", ")),
			"unlock",
		)
	}

	return nil
}

func (e *ComputeExecutionEngine) GetCost(message []byte) (*big.Int, error) {
	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "get cost")
	}

	request := &protobufs.MessageRequest{}
	err := request.FromCanonicalBytes(message)
	if err != nil {
		return nil, errors.Wrap(err, "get cost")
	}

	switch req := request.Request.(type) {
	case *protobufs.MessageRequest_ComputeDeploy:
		deploy, err := compute.ComputeDeployFromProtobuf(req.ComputeDeploy)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return big.NewInt(int64(
			len(deploy.RDFSchema) +
				len(deploy.Config.ReadPublicKey) +
				len(deploy.Config.WritePublicKey) +
				len(deploy.Config.OwnerPublicKey),
		)), nil

	case *protobufs.MessageRequest_ComputeUpdate:
		update, err := compute.ComputeUpdateFromProtobuf(req.ComputeUpdate)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		if update.Config == nil {
			return big.NewInt(int64(len(update.RDFSchema))), nil
		}

		return big.NewInt(int64(
			len(update.RDFSchema) +
				len(update.Config.ReadPublicKey) +
				len(update.Config.WritePublicKey) +
				len(update.Config.OwnerPublicKey),
		)), nil

	case *protobufs.MessageRequest_CodeDeploy:
		deploy, err := compute.CodeDeploymentFromProtobuf(req.CodeDeploy)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}
		return deploy.GetCost()

	case *protobufs.MessageRequest_CodeExecute:
		exec, err := compute.CodeExecuteFromProtobuf(
			req.CodeExecute,
			e.hypergraph,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return exec.GetCost()

	case *protobufs.MessageRequest_CodeFinalize:
		fin, err := compute.CodeFinalizeFromProtobuf(
			req.CodeFinalize,
			[32]byte{},
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
			nil,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return fin.GetCost()
	}

	return big.NewInt(0), nil
}

func (e *ComputeExecutionEngine) ValidateMessage(
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

func (e *ComputeExecutionEngine) validateBundle(
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
		select {
		case <-e.ctx.Done():
			return errors.Wrap(errors.New("context canceled"), "validate bundle")
		default:
			e.logger.Debug(
				"validating bundled operation",
				zap.Int("operation", i),
				zap.String("address", hex.EncodeToString(address)),
			)

			// Check if this is a compute operation type
			isComputeOp := op.GetComputeDeploy() != nil ||
				op.GetComputeUpdate() != nil ||
				op.GetCodeDeploy() != nil ||
				op.GetCodeExecute() != nil ||
				op.GetCodeFinalize() != nil

			if !isComputeOp {
				// Skip non-compute operations
				e.logger.Debug(
					"skipping non-compute operation in bundle",
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
	}

	return nil
}

// validateIndividualMessage validates a single message without bundle handling
func (e *ComputeExecutionEngine) validateIndividualMessage(
	frameNumber uint64,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
) error {
	payload, err := e.tryExtractMessageForIntrinsic(message)
	if err != nil {
		if errors.Is(err, ErrUnsupportedMessageType) {
			// Not a compute operation, this validation doesn't apply
			return nil
		}
		return errors.Wrap(err, "validate individual message")
	}

	// For compute deploy operations, just validate the structure
	if (message.GetComputeDeploy() != nil || message.GetComputeUpdate() != nil) &&
		fromBundle {
		return errors.Wrap(message.Validate(), "validate individual message")
	}

	// For other operations, try to load the intrinsic and validate
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	switch message.Request.(type) {
	case *protobufs.MessageRequest_ComputeDeploy:
		return errors.Wrap(
			errors.New("deployments must be bundled"),
			"validate individual message",
		)
	case *protobufs.MessageRequest_ComputeUpdate:
		return errors.Wrap(
			errors.New("updates must be bundled"),
			"validate individual message",
		)
	}

	// Validate the operation
	err = intrinsic.Validate(frameNumber, payload)
	return errors.Wrap(err, "validate individual message")
}

func (e *ComputeExecutionEngine) ProcessMessage(
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

	if e.mode == GlobalMode && !bytes.Equal(
		address,
		compute.COMPUTE_INTRINSIC_DOMAIN[:],
	) {
		return nil, errors.Wrap(
			errors.New("non-deploy messages not allowed in global mode"),
			"process message",
		)
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

func (e *ComputeExecutionEngine) handleDeploy(
	address []byte,
	payload []byte,
	frameNumber uint64,
	feePaid *big.Int,
	state state.State,
) (*execution.ProcessMessageResult, []byte, error) {
	var deployAddress []byte

	if len(payload) < 4 {
		return nil, nil, errors.Wrap(errors.New("invalid payload"), "handle deploy")
	}

	deployType := binary.BigEndian.Uint32(payload[:4])
	var intrinsic *compute.ComputeIntrinsic
	if deployType == protobufs.ComputeDeploymentType {
		args := protobufs.ComputeDeploy{}
		err := args.FromCanonicalBytes(payload)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		// Create configuration from deploy arguments
		config := &compute.ComputeIntrinsicConfiguration{
			ReadPublicKey:  args.Config.ReadPublicKey,
			WritePublicKey: args.Config.WritePublicKey,
			OwnerPublicKey: args.Config.OwnerPublicKey,
		}

		// Create new compute intrinsic with configuration
		intrinsic, err = compute.NewComputeIntrinsic(
			config,
			e.hypergraph,
			e.inclusionProver,
			e.bulletproofProver,
			e.verEnc,
			e.decafConstructor,
			e.keyManager,
			e.compiler,
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		// Deploy the intrinsic
		state, deployAddress, err = intrinsic.Deploy(
			compute.COMPUTE_INTRINSIC_DOMAIN,
			nil,
			nil,
			feePaid,
			args.RdfSchema,
			frameNumber,
			state,
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		e.logger.Info(
			"deployed compute intrinsic",
			zap.String("address", hex.EncodeToString(intrinsic.Address())),
		)
	} else if deployType == protobufs.ComputeUpdateType {
		// Deserialize the update arguments
		updatePb := &protobufs.ComputeUpdate{}
		err := updatePb.FromCanonicalBytes(payload)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		// Load existing compute intrinsic
		intrinsic, err = compute.LoadComputeIntrinsic(
			address,
			e.hypergraph,
			state,
			e.inclusionProver,
			e.bulletproofProver,
			e.verEnc,
			e.decafConstructor,
			e.keyManager,
			e.compiler,
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		// Deploy (update) the intrinsic
		var domain [32]byte
		copy(domain[:], address)
		state, deployAddress, err = intrinsic.Deploy(
			domain,
			nil, // provers
			nil, // creator
			feePaid,
			payload, // Pass the entire serialized update message
			frameNumber,
			state,
		)
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle deploy")
		}

		e.logger.Info(
			"updated compute intrinsic",
			zap.String("address", hex.EncodeToString(intrinsic.Address())),
		)
	} else {
		return nil, nil, errors.Wrap(
			errors.New("invalid deployment type"),
			"handle deploy",
		)
	}

	// Store the intrinsic
	e.intrinsicsMutex.Lock()
	e.intrinsics[string(deployAddress)] = intrinsic
	e.intrinsicsMutex.Unlock()

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    state,
	}, deployAddress, nil
}

func (e *ComputeExecutionEngine) handleBundle(
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

	movingAddress := address // buildutils:allow-slice-alias assigned slice will not mutate, reassignment will

	// Validate fees distribute correctly
	feeQueue := fees.CollectBundleFees(bundle, DefaultFeeMarket)
	consumers := fees.CountFeeConsumers(bundle, DefaultFeeMarket)
	if err := fees.SanityCheck(feeQueue, consumers); err != nil {
		return nil, errors.Wrap(err, "handle bundle")
	}
	responses.State = state

	// Process each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		e.logger.Debug(
			"processing bundled operation",
			zap.Int("operation", i),
			zap.String("address", hex.EncodeToString(address)),
		)

		// Check if this is a compute operation type
		isComputeOp := op.GetComputeDeploy() != nil ||
			op.GetComputeUpdate() != nil ||
			op.GetCodeDeploy() != nil ||
			op.GetCodeExecute() != nil ||
			op.GetCodeFinalize() != nil

		if !isComputeOp {
			if fees.NeedsOneFee(op, DefaultFeeMarket) {
				_ = fees.PopFee(&feeQueue)
			}
			// Skip non-compute operations (e.g., token payments)
			// They are retained in the bundle for reference but not processed here
			e.logger.Debug(
				"skipping non-compute operation in bundle",
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
		opResponses, applicableDeploy, err := e.processIndividualMessage(
			frameNumber,
			feeForOp,
			feeMultiplier,
			movingAddress,
			op,
			true,
			state,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "handle bundle: operation %d failed", i)
		}

		if op.GetComputeDeploy() != nil {
			movingAddress = applicableDeploy
		}

		// Collect responses
		responses.Messages = append(responses.Messages, opResponses.Messages...)
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
func (e *ComputeExecutionEngine) processIndividualMessage(
	frameNumber uint64,
	feePaid *big.Int,
	feeMultiplier *big.Int,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
	state state.State,
) (*execution.ProcessMessageResult, []byte, error) {
	payload, err := e.tryExtractMessageForIntrinsic(message)
	if err != nil {
		return nil, nil, errors.Wrap(err, "process individual message")
	}

	// Read the type prefix to determine if it's a deploy or operation
	typePrefix := binary.BigEndian.Uint32(payload[:4])

	// Check if it's a compute deploy or update
	if typePrefix == protobufs.ComputeDeploymentType ||
		typePrefix == protobufs.ComputeUpdateType {
		if fromBundle {
			return e.handleDeploy(address, payload, frameNumber, feePaid, state)
		} else {
			return nil, nil, errors.Wrap(
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
			return nil, nil, errors.Wrap(
				errors.New("non-deploy messages not allowed in global mode"),
				"process individual message",
			)
		}
	}

	// Otherwise, try to handle it as an operation on existing intrinsic
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		return nil, nil, errors.Wrap(err, "process individual message")
	}

	// Process the operation
	state, err = intrinsic.InvokeStep(
		frameNumber,
		payload,
		feePaid,
		feeMultiplier,
		state,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "process individual message")
	}

	// Log state changes for debugging
	e.logger.Debug(
		"processed individual message",
		zap.String("address", hex.EncodeToString(address)),
	)

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    state,
	}, nil, nil
}

func (e *ComputeExecutionEngine) tryGetIntrinsic(
	address []byte,
) (intrinsics.Intrinsic, error) {
	addressStr := string(address)
	e.intrinsicsMutex.RLock()
	intrinsic, exists := e.intrinsics[addressStr]
	e.intrinsicsMutex.RUnlock()

	if !exists {
		// Try to load existing intrinsic
		loaded, err := compute.LoadComputeIntrinsic(
			address,
			e.hypergraph,
			hgstate.NewHypergraphState(e.hypergraph),
			e.inclusionProver,
			e.bulletproofProver,
			e.verEnc,
			e.decafConstructor,
			e.keyManager,
			e.compiler,
		)
		if err != nil {
			return nil, errors.Wrap(err, "try get intrinsic")
		}

		e.intrinsicsMutex.Lock()
		e.intrinsics[addressStr] = loaded
		e.intrinsicsMutex.Unlock()
		intrinsic = loaded
	}

	return intrinsic, nil
}

func (e *ComputeExecutionEngine) tryExtractMessageForIntrinsic(
	message *protobufs.MessageRequest,
) ([]byte, error) {
	payload := []byte{}
	var err error
	switch message.Request.(type) {
	case *protobufs.MessageRequest_ComputeDeploy:
		payload, err = message.GetComputeDeploy().ToCanonicalBytes()
	case *protobufs.MessageRequest_ComputeUpdate:
		payload, err = message.GetComputeUpdate().ToCanonicalBytes()
	case *protobufs.MessageRequest_CodeDeploy:
		payload, err = message.GetCodeDeploy().ToCanonicalBytes()
	case *protobufs.MessageRequest_CodeExecute:
		payload, err = message.GetCodeExecute().ToCanonicalBytes()
	case *protobufs.MessageRequest_CodeFinalize:
		payload, err = message.GetCodeFinalize().ToCanonicalBytes()
	default:
		err = ErrUnsupportedMessageType
	}
	return payload, err
}

var _ execution.ShardExecutionEngine = (*ComputeExecutionEngine)(nil)
