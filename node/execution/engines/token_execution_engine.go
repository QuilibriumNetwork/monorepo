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
	"source.quilibrium.com/quilibrium/monorepo/node/execution/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// ExecutionMode defines whether the engine is running in global or application
// mode
type ExecutionMode int

const (
	// GlobalMode - only deploy messages are valid
	GlobalMode ExecutionMode = iota
	// ApplicationMode - both deploy and invoke messages are valid
	ApplicationMode
)

type TokenExecutionEngine struct {
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

func NewTokenExecutionEngine(
	logger *zap.Logger,
	hypergraph hypergraph.Hypergraph,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	mode ExecutionMode,
) (*TokenExecutionEngine, error) {
	return &TokenExecutionEngine{
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

func (e *TokenExecutionEngine) GetName() string {
	return "token"
}

// Prove implements execution.ShardExecutionEngine.
func (e *TokenExecutionEngine) Prove(
	domain []byte,
	frameNumber uint64,
	message []byte,
) (*protobufs.MessageRequest, error) {
	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "prove")
	}

	request := &protobufs.MessageRequest{}
	err := request.FromCanonicalBytes(message)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	switch req := request.Request.(type) {
	case *protobufs.MessageRequest_Transaction:
		transaction, err := token.TransactionFromProtobuf(
			req.Transaction,
			e.inclusionProver,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		if err := transaction.Prove(frameNumber); err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Transaction{
				Transaction: transaction.ToProtobuf(),
			},
		}, nil

	case *protobufs.MessageRequest_PendingTransaction:
		pendingTransaction, err := token.PendingTransactionFromProtobuf(
			req.PendingTransaction,
			e.inclusionProver,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		if err := pendingTransaction.Prove(frameNumber); err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_PendingTransaction{
				PendingTransaction: pendingTransaction.ToProtobuf(),
			},
		}, nil

	case *protobufs.MessageRequest_MintTransaction:
		mintTransaction, err := token.MintTransactionFromProtobuf(
			req.MintTransaction,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		if err := mintTransaction.Prove(frameNumber); err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_MintTransaction{
				MintTransaction: mintTransaction.ToProtobuf(),
			},
		}, nil
	}

	return nil, errors.Wrap(errors.New("invalid type"), "prove")
}

func (e *TokenExecutionEngine) GetCost(message []byte) (*big.Int, error) {
	if len(message) < 4 {
		return nil, errors.Wrap(errors.New("invalid message"), "get cost")
	}

	request := &protobufs.MessageRequest{}
	err := request.FromCanonicalBytes(message)
	if err != nil {
		return nil, errors.Wrap(err, "get cost")
	}

	switch req := request.Request.(type) {
	case *protobufs.MessageRequest_TokenDeploy:
		configBytes, err := req.TokenDeploy.Config.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return big.NewInt(int64(
			len(configBytes),
		)), nil

	case *protobufs.MessageRequest_TokenUpdate:
		configBytes, err := req.TokenUpdate.Config.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return big.NewInt(int64(
			len(configBytes),
		)), nil

	case *protobufs.MessageRequest_Transaction:
		transaction, err := token.TransactionFromProtobuf(
			req.Transaction,
			e.inclusionProver,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return transaction.GetCost()

	case *protobufs.MessageRequest_PendingTransaction:
		pendingTransaction, err := token.PendingTransactionFromProtobuf(
			req.PendingTransaction,
			e.inclusionProver,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return pendingTransaction.GetCost()

	case *protobufs.MessageRequest_MintTransaction:
		mintTransaction, err := token.MintTransactionFromProtobuf(
			req.MintTransaction,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		return mintTransaction.GetCost()

	}

	return big.NewInt(0), nil
}

func (e *TokenExecutionEngine) GetCapabilities() []*protobufs.Capability {
	// Protocol identifier: 0x00040001 (token protocol v1)
	// High 3 bytes: 0x000400 = token protocol
	// Low byte: 0x01 = version 1
	return []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x00040001,
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

func (e *TokenExecutionEngine) Start() <-chan error {
	errChan := make(chan error, 1)

	e.mu.Lock()
	e.stopChan = make(chan struct{}, 1)
	e.mu.Unlock()

	go func() {
		e.logger.Info("starting token execution engine")

		<-e.stopChan
		e.logger.Info("stopping token execution engine")
	}()

	return errChan
}

func (e *TokenExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		e.logger.Info("stopping token execution engine", zap.Bool("force", force))

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

func (e *TokenExecutionEngine) ValidateMessage(
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

func (e *TokenExecutionEngine) validateBundle(
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
		isHypergraphOp := op.GetTokenDeploy() != nil ||
			op.GetTokenUpdate() != nil ||
			op.GetTransaction() != nil ||
			op.GetMintTransaction() != nil ||
			op.GetPendingTransaction() != nil

		if !isHypergraphOp {
			// Skip non-token operations
			e.logger.Debug(
				"skipping non-token operation in bundle",
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
func (e *TokenExecutionEngine) validateIndividualMessage(
	frameNumber uint64,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
) error {
	isTokenOp := false
	isUpdate := false
	switch message.Request.(type) {
	case *protobufs.MessageRequest_TokenDeploy:
		isTokenOp = true
		isUpdate = true
	case *protobufs.MessageRequest_TokenUpdate:
		isTokenOp = true
		isUpdate = true
	case *protobufs.MessageRequest_MintTransaction:
		isTokenOp = true
	case *protobufs.MessageRequest_PendingTransaction:
		isTokenOp = true
	case *protobufs.MessageRequest_Transaction:
		isTokenOp = true
	}

	if !isTokenOp {
		return errors.Wrap(
			errors.New("invalid type"),
			"validate individual message",
		)
	}

	// For token deploy operations, just validate the structure
	if isUpdate && fromBundle {
		return errors.Wrap(message.Validate(), "validate individual message")
	}

	// For other operations, try to load the intrinsic and validate
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	payload := []byte{}
	switch message.Request.(type) {
	case *protobufs.MessageRequest_TokenDeploy:
		err = errors.New("deployments must be bundled")
	case *protobufs.MessageRequest_TokenUpdate:
		err = errors.New("updates must be bundled")
	case *protobufs.MessageRequest_MintTransaction:
		payload, err = message.GetMintTransaction().ToCanonicalBytes()
	case *protobufs.MessageRequest_PendingTransaction:
		payload, err = message.GetPendingTransaction().ToCanonicalBytes()
	case *protobufs.MessageRequest_Transaction:
		payload, err = message.GetTransaction().ToCanonicalBytes()
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

func (e *TokenExecutionEngine) ProcessMessage(
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
	} else if typePrefix != protobufs.MessageRequestType {
		return nil, errors.Wrap(
			errors.New("unsupported message type"),
			"process message",
		)
	}

	// Parse the bundle
	request := &protobufs.MessageRequest{}
	if err := request.FromCanonicalBytes(message); err != nil {
		return nil, errors.Wrap(err, "process message")
	}

	// Otherwise, delegate to individual message processing
	result, err := e.processIndividualMessage(
		frameNumber,
		big.NewInt(0),
		feeMultiplier,
		address,
		request,
		false,
		state,
	)
	if err != nil {
		return nil, errors.Wrap(err, "process message")
	}

	return result, nil
}

func (e *TokenExecutionEngine) Lock(
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

	return intrinsic.Lock(frameNumber, message)
}

func (e *TokenExecutionEngine) Unlock() error {
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

func (e *TokenExecutionEngine) handleBundle(
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

	// Validate fees distribute correctly
	feeQueue := fees.CollectBundleFees(bundle, DefaultFeeMarket)
	consumers := fees.CountFeeConsumers(bundle, DefaultFeeMarket)
	if err := fees.SanityCheck(feeQueue, consumers); err != nil {
		return nil, errors.Wrap(err, "handle bundle")
	}

	responses := &execution.ProcessMessageResult{}

	// Process each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		e.logger.Debug(
			"processing bundled operation",
			zap.Int("operation", i),
			zap.String("address", hex.EncodeToString(address)),
		)

		// Check if this is a token operation type
		isTokenOp := op.GetTokenDeploy() != nil ||
			op.GetTokenUpdate() != nil ||
			op.GetTransaction() != nil ||
			op.GetMintTransaction() != nil ||
			op.GetPendingTransaction() != nil

		if !isTokenOp {
			if fees.NeedsOneFee(op, DefaultFeeMarket) {
				_ = fees.PopFee(&feeQueue)
			}

			// Skip non-token operations
			// They are retained in the bundle for reference but not processed here
			e.logger.Debug(
				"skipping non-token operation in bundle",
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
func (e *TokenExecutionEngine) processIndividualMessage(
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
	domain := address
	switch message.Request.(type) {
	case *protobufs.MessageRequest_TokenDeploy:
		payload, err = message.GetTokenDeploy().ToCanonicalBytes()
	case *protobufs.MessageRequest_TokenUpdate:
		payload, err = message.GetTokenUpdate().ToCanonicalBytes()
	case *protobufs.MessageRequest_MintTransaction:
		payload, err = message.GetMintTransaction().ToCanonicalBytes()
		domain = message.GetMintTransaction().Domain
	case *protobufs.MessageRequest_PendingTransaction:
		payload, err = message.GetPendingTransaction().ToCanonicalBytes()
		domain = message.GetPendingTransaction().Domain
	case *protobufs.MessageRequest_Transaction:
		payload, err = message.GetTransaction().ToCanonicalBytes()
		domain = message.GetTransaction().Domain
	default:
		err = errors.New("unsupported message type")
	}
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	// Read the type prefix to determine if it's a deploy or operation
	typePrefix := binary.BigEndian.Uint32(payload[:4])

	// Check if it's a token deploy or update
	if typePrefix == protobufs.TokenDeploymentType ||
		typePrefix == protobufs.TokenUpdateType {
		if fromBundle {
			return e.handleDeploy(domain, payload, frameNumber, feePaid, state)
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
			[64]byte(slices.Concat(domain, bytes.Repeat([]byte{0xff}, 32))),
		)
		if err == nil || !fromBundle {
			return nil, errors.Wrap(
				errors.New("non-deploy messages not allowed in global mode"),
				"process individual message",
			)
		}
	}

	// Otherwise, try to handle it as an operation on existing intrinsic
	intrinsic, err := e.tryGetIntrinsic(domain)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	err = e.validateIndividualMessage(frameNumber, domain, message, fromBundle)
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

	e.logger.Debug(
		"processed individual message",
		zap.String("address", hex.EncodeToString(address)),
	)

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    newState,
	}, nil
}

func (e *TokenExecutionEngine) handleDeploy(
	address []byte,
	payload []byte,
	frameNumber uint64,
	feePaid *big.Int,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	if bytes.Equal(address, token.QUIL_TOKEN_ADDRESS) {
		return nil, errors.Wrap(errors.New("reserved"), "handle deploy")
	}

	var intrinsic *token.TokenIntrinsic
	if bytes.Equal(address, token.TOKEN_BASE_DOMAIN[:]) {
		// Deserialize the deploy arguments
		deployPb := &protobufs.TokenDeploy{}
		err := deployPb.FromCanonicalBytes(payload)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		deployArgs, err := token.TokenDeployFromProtobuf(deployPb)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Create new token intrinsic
		intrinsic, err = token.NewTokenIntrinsic(
			deployArgs.Config,
			e.hypergraph,
			e.verEnc,
			e.decafConstructor,
			e.bulletproofProver,
			e.inclusionProver,
			e.keyManager,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Deploy the intrinsic
		state, err = intrinsic.Deploy(
			token.TOKEN_BASE_DOMAIN,
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
			"deployed token intrinsic",
			zap.String("address", hex.EncodeToString(deployedAddress)),
			zap.String("name", deployArgs.Config.Name),
			zap.String("symbol", deployArgs.Config.Symbol),
		)
	} else {
		// Deserialize the update arguments
		updatePb := &protobufs.TokenUpdate{}
		err := updatePb.FromCanonicalBytes(payload)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		deployArgs, err := token.TokenUpdateFromProtobuf(updatePb)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Load existing token intrinsic
		intrinsic, err = token.LoadTokenIntrinsic(
			address,
			e.hypergraph,
			e.verEnc,
			e.decafConstructor,
			e.bulletproofProver,
			e.inclusionProver,
			e.keyManager,
			e.clockStore,
		)
		if err != nil {
			return nil, errors.Wrap(err, "handle deploy")
		}

		// Update the intrinsic
		state, err = intrinsic.Deploy(
			[32]byte(address),
			nil, // provers
			nil, // creator
			feePaid,
			payload,
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
			"updated token intrinsic",
			zap.String("address", hex.EncodeToString(deployedAddress)),
			zap.String("name", deployArgs.Config.Name),
			zap.String("symbol", deployArgs.Config.Symbol),
		)
	}

	return &execution.ProcessMessageResult{
		Messages: []*protobufs.Message{},
		State:    state,
	}, nil
}

func (e *TokenExecutionEngine) tryGetIntrinsic(
	address []byte,
) (intrinsics.Intrinsic, error) {
	addressStr := string(address)
	e.intrinsicsMutex.RLock()
	intrinsic, exists := e.intrinsics[addressStr]
	e.intrinsicsMutex.RUnlock()

	if !exists { // Try to load existing intrinsic
		loaded, err := token.LoadTokenIntrinsic(
			address,
			e.hypergraph,
			e.verEnc,
			e.decafConstructor,
			e.bulletproofProver,
			e.inclusionProver,
			e.keyManager,
			e.clockStore,
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

var _ execution.ShardExecutionEngine = (*TokenExecutionEngine)(nil)
