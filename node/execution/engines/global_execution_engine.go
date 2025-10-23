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
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

type GlobalExecutionEngine struct {
	logger            *zap.Logger
	config            *config.P2PConfig
	hypergraph        hypergraph.Hypergraph
	clockStore        store.ClockStore
	shardsStore       store.ShardsStore
	keyManager        keys.KeyManager
	inclusionProver   crypto.InclusionProver
	bulletproofProver crypto.BulletproofProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	frameProver       crypto.FrameProver
	rewardIssuance    consensus.RewardIssuance
	proverRegistry    consensus.ProverRegistry
	blsConstructor    crypto.BlsConstructor

	// State
	intrinsics      map[string]intrinsics.Intrinsic
	intrinsicsMutex sync.RWMutex
	mu              sync.RWMutex
	stopChan        chan struct{}
}

func NewGlobalExecutionEngine(
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
	frameProver crypto.FrameProver,
	rewardIssuance consensus.RewardIssuance,
	proverRegistry consensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
) (*GlobalExecutionEngine, error) {
	return &GlobalExecutionEngine{
		logger:            logger,
		config:            config,
		hypergraph:        hypergraph,
		clockStore:        clockStore,
		shardsStore:       shardsStore,
		keyManager:        keyManager,
		inclusionProver:   inclusionProver,
		bulletproofProver: bulletproofProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		frameProver:       frameProver,
		rewardIssuance:    rewardIssuance,
		proverRegistry:    proverRegistry,
		blsConstructor:    blsConstructor,
		intrinsics:        make(map[string]intrinsics.Intrinsic),
	}, nil
}

func (e *GlobalExecutionEngine) GetName() string {
	return "global"
}

func (e *GlobalExecutionEngine) GetCost(message []byte) (*big.Int, error) {
	return big.NewInt(0), nil
}

func (e *GlobalExecutionEngine) GetCapabilities() []*protobufs.Capability {
	// Protocol identifier: 0x00020001 (global protocol v1)
	// High 3 bytes: 0x000200 = global protocol
	// Low byte: 0x01 = version 1
	return []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x00020001,
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

func (e *GlobalExecutionEngine) Start() <-chan error {
	errChan := make(chan error, 1)

	e.mu.Lock()
	e.stopChan = make(chan struct{}, 1)
	e.mu.Unlock()

	go func() {
		e.logger.Info("starting global execution engine")

		<-e.stopChan
		e.logger.Info("stopping global execution engine")
	}()

	return errChan
}

func (e *GlobalExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error, 1)

	go func() {
		e.logger.Info("stopping global execution engine", zap.Bool("force", force))

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

func (e *GlobalExecutionEngine) ValidateMessage(
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

func (e *GlobalExecutionEngine) validateBundle(
	frameNumber uint64,
	address []byte,
	message []byte,
) error {
	// Parse the bundle
	bundle := &protobufs.MessageBundle{}
	if err := bundle.FromCanonicalBytes(message); err != nil {
		return errors.Wrap(err, "validate bundle")
	}

	responses := &execution.ProcessMessageResult{}

	// Validate each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		e.logger.Debug(
			"validating bundled operation",
			zap.Int("operation", i),
			zap.String("address", hex.EncodeToString(address)),
		)

		// Check if this is a global operation type
		isGlobalOp := op.GetJoin() != nil ||
			op.GetLeave() != nil ||
			op.GetPause() != nil ||
			op.GetResume() != nil ||
			op.GetConfirm() != nil ||
			op.GetReject() != nil ||
			op.GetKick() != nil ||
			op.GetUpdate() != nil ||
			op.GetShard() != nil

		if !isGlobalOp {
			if e.config.Network == 0 &&
				frameNumber <= token.FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END {
				return errors.Wrap(
					errors.New("enrollment period has not ended"),
					"validate bundle",
				)
			}
			// Skip non-global operations (e.g., token payments, compute ops)
			// They are retained in the bundle for reference but not validated here
			e.logger.Debug(
				"skipping non-global operation in bundle",
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

	e.logger.Info(
		"processed message bundle",
		zap.Int("operations", len(bundle.Requests)),
		zap.String("address", hex.EncodeToString(address)),
		zap.Int("responses", len(responses.Messages)),
	)

	return nil
}

// validateIndividualMessage validates a single message without bundle handling
func (e *GlobalExecutionEngine) validateIndividualMessage(
	frameNumber uint64,
	address []byte,
	message *protobufs.MessageRequest,
	_ bool,
) error {
	// Try to get or load the global intrinsic
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	payload, err := e.tryExtractMessageForIntrinsic(message)
	if err != nil {
		return errors.Wrap(err, "validate individual message")
	}

	// Validate the operation
	err = intrinsic.Validate(frameNumber, payload)
	return errors.Wrap(err, "validate individual message")
}

func (e *GlobalExecutionEngine) ProcessMessage(
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

func (e *GlobalExecutionEngine) handleBundle(
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

	// Process each operation in the bundle sequentially
	for i, op := range bundle.Requests {
		// Process this operation individually
		opResponses, err := e.processIndividualMessage(
			frameNumber,
			feeMultiplier,
			address,
			op,
			true,
			state,
		)
		if err != nil {
			// Skip non-global operations (e.g., token payments, compute ops)
			// They are retained in the bundle for reference but not processed here
			e.logger.Debug(
				"skipping non-global operation in bundle",
				zap.Int("operation", i),
			)
			continue
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
func (e *GlobalExecutionEngine) processIndividualMessage(
	frameNumber uint64,
	feeMultiplier *big.Int,
	address []byte,
	message *protobufs.MessageRequest,
	fromBundle bool,
	state state.State,
) (*execution.ProcessMessageResult, error) {
	payload, err := e.tryExtractMessageForIntrinsic(message)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	// Try to get or load the global intrinsic
	intrinsic, err := e.tryGetIntrinsic(address)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	err = e.validateIndividualMessage(frameNumber, address, message, fromBundle)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	// Process the operation
	_, err = intrinsic.InvokeStep(
		frameNumber,
		payload,
		big.NewInt(0),
		feeMultiplier,
		state,
	)
	if err != nil {
		return nil, errors.Wrap(err, "process individual message")
	}

	newState, err := intrinsic.Commit()
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

// Prove implements execution.ShardExecutionEngine.
func (e *GlobalExecutionEngine) Prove(
	domain []byte,
	frameNumber uint64,
	message []byte,
) (*protobufs.MessageRequest, error) {
	return nil, errors.New("unimplemented")
}

func (e *GlobalExecutionEngine) Lock(
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

func (e *GlobalExecutionEngine) Unlock() error {
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

func (e *GlobalExecutionEngine) tryGetIntrinsic(address []byte) (
	intrinsics.Intrinsic,
	error,
) {
	// Check if the message is for the global intrinsic
	if !bytes.Equal(address, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
		return nil, errors.Wrap(
			errors.New("invalid address for global execution engine"),
			"try get intrinsic",
		)
	}

	addressStr := string(address)
	e.intrinsicsMutex.RLock()
	intrinsic, exists := e.intrinsics[addressStr]
	e.intrinsicsMutex.RUnlock()

	if !exists {
		// Load the global intrinsic
		loaded, err := global.LoadGlobalIntrinsic(
			address,
			e.hypergraph,
			e.inclusionProver,
			e.keyManager,
			e.frameProver,
			e.clockStore,
			e.rewardIssuance,
			e.proverRegistry,
			e.blsConstructor,
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

func (e *GlobalExecutionEngine) tryExtractMessageForIntrinsic(
	message *protobufs.MessageRequest,
) ([]byte, error) {
	payload := []byte{}
	var err error
	switch r := message.Request.(type) {
	case *protobufs.MessageRequest_Update:
		payload, err = r.Update.ToCanonicalBytes()
	case *protobufs.MessageRequest_Shard:
		payload, err = r.Shard.ToCanonicalBytes()
	case *protobufs.MessageRequest_Join:
		for _, f := range r.Join.Filters {
			if len(f) >= 32 {
				l1 := up2p.GetBloomFilterIndices(f[:32], 256, 3)
				path := []uint32{}
				for _, p := range f[32:] {
					path = append(path, uint32(p))
				}
				shards, err := e.shardsStore.GetAppShards(
					slices.Concat(l1, f[:32]),
					path,
				)
				if err != nil {
					return nil, errors.Wrap(err, "try extract message for intrinsic")
				}
				if len(shards) != 1 || !slices.Equal(shards[0].Path, path) {
					return nil, errors.Wrap(
						errors.New("invalid shard"),
						"try extract message for intrinsic",
					)
				}
			}
		}
		payload, err = r.Join.ToCanonicalBytes()
	case *protobufs.MessageRequest_Leave:
		payload, err = r.Leave.ToCanonicalBytes()
	case *protobufs.MessageRequest_Pause:
		payload, err = r.Pause.ToCanonicalBytes()
	case *protobufs.MessageRequest_Resume:
		payload, err = r.Resume.ToCanonicalBytes()
	case *protobufs.MessageRequest_Confirm:
		payload, err = r.Confirm.ToCanonicalBytes()
	case *protobufs.MessageRequest_Reject:
		payload, err = r.Reject.ToCanonicalBytes()
	case *protobufs.MessageRequest_Kick:
		payload, err = r.Kick.ToCanonicalBytes()
	default:
		err = errors.New("unsupported message type")
	}

	return payload, errors.Wrap(err, "try extract message for intrinsic")
}

var _ execution.ShardExecutionEngine = (*GlobalExecutionEngine)(nil)
