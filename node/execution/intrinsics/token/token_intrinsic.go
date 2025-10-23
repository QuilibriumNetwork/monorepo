package token

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"
	observability "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type TokenIntrinsic struct {
	domain              [32]byte
	bulletproofProver   crypto.BulletproofProver
	inclusionProver     crypto.InclusionProver
	verEnc              crypto.VerifiableEncryptor
	decafConstructor    crypto.DecafConstructor
	hypergraph          hgcrdt.Hypergraph
	config              *TokenIntrinsicConfiguration
	keyManager          tkeys.KeyManager
	consensusMetadata   *qcrypto.VectorCommitmentTree
	sumcheckInfo        *qcrypto.VectorCommitmentTree
	rdfHypergraphSchema string
	rdfMultiprover      *schema.RDFMultiprover
	lockedWrites        map[string]struct{}
	lockedReads         map[string]int
	lockedWritesMx      sync.RWMutex
	lockedReadsMx       sync.RWMutex
	state               state.State
	clockStore          store.ClockStore
}

// SumCheck implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) SumCheck() bool {
	return true
}

// Address implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Address() []byte {
	return t.domain[:]
}

// Commit implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Commit() (state.State, error) {
	timer := prometheus.NewTimer(
		observability.CommitDuration.WithLabelValues("token"),
	)
	defer timer.ObserveDuration()

	if t.state == nil {
		observability.CommitErrors.WithLabelValues("token").Inc()
		return nil, errors.Wrap(errors.New("nothing to commit"), "commit")
	}

	if err := t.state.Commit(); err != nil {
		observability.CommitErrors.WithLabelValues("token").Inc()
		return t.state, errors.Wrap(err, "commit")
	}

	observability.CommitTotal.WithLabelValues("token").Inc()
	return t.state, nil
}

// Deploy implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Deploy(
	domain [32]byte,
	provers [][]byte,
	creator []byte,
	fee *big.Int,
	contextData []byte,
	frameNumber uint64,
	hgstate state.State,
) (
	state.State,
	error,
) {
	timer := prometheus.NewTimer(
		observability.MaterializeDuration.WithLabelValues("token"),
	)
	defer timer.ObserveDuration()

	if !bytes.Equal(domain[:], TOKEN_BASE_DOMAIN[:]) {
		vert, err := hgstate.Get(
			domain[:],
			hg.HYPERGRAPH_METADATA_ADDRESS,
			hg.VertexAddsDiscriminator,
		)
		if err != nil {
			return nil, errors.Wrap(
				state.ErrInvalidDomain,
				"deploy",
			)
		}

		if vert == nil {
			return nil, errors.Wrap(
				state.ErrInvalidDomain,
				"deploy",
			)
		}

		// Deserialize the update arguments
		updatePb := &protobufs.TokenUpdate{}
		err = updatePb.FromCanonicalBytes(contextData)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		deployArgs, err := TokenUpdateFromProtobuf(updatePb)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		if err := updatePb.Validate(); err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		updateWithoutSignature := proto.Clone(updatePb).(*protobufs.TokenUpdate)

		updateWithoutSignature.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		validSig, err := t.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			t.config.OwnerPublicKey,
			message,
			updatePb.PublicKeySignatureBls48581.Signature,
			slices.Concat(domain[:], []byte("TOKEN_UPDATE")),
		)
		if err != nil || !validSig {
			return nil, errors.Wrap(errors.New("invalid signature"), "deploy")
		}

		if t.config.Behavior != deployArgs.Config.Behavior {
			return nil, errors.Wrap(
				errors.New("behavior cannot be updated"),
				"deploy",
			)
		}

		if t.config.MintStrategy != nil {
			if deployArgs.Config.MintStrategy == nil {
				return nil, errors.Wrap(
					errors.New("mint strategy missing"),
					"deploy",
				)
			}

			err := validateTokenConfiguration(deployArgs.Config)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			if deployArgs.Config.Supply.Cmp(t.config.Supply) < 0 {
				return nil, errors.Wrap(
					errors.New("supply cannot be reduced"),
					"deploy",
				)
			}

			if deployArgs.Config.Units != nil &&
				deployArgs.Config.Units.Cmp(t.config.Units) != 0 {
				return nil, errors.Wrap(
					errors.New("supply cannot be reduced"),
					"deploy",
				)
			}
		}

		vertexAddress := slices.Concat(
			t.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
		)

		// Ensure the vertex is present and has not been removed
		_, err = t.hypergraph.GetVertex([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		prior, err := t.hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		tree, err := t.hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		configTree, err := NewTokenConfigurationMetadata(
			deployArgs.Config,
			t.rdfMultiprover,
		)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		commit := configTree.Commit(t.inclusionProver, false)

		out, err := tries.SerializeNonLazyTree(configTree)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		err = tree.Insert([]byte{16 << 2}, out, commit, configTree.GetSize())
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		err = hgstate.Set(
			t.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
			hg.VertexAddsDiscriminator,
			frameNumber,
			hgstate.(*hg.HypergraphState).NewVertexAddMaterializedState(
				[32]byte(t.Address()),
				[32]byte(hg.HYPERGRAPH_METADATA_ADDRESS),
				frameNumber,
				prior,
				tree,
			),
		)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		t.state = hgstate

		return hgstate, nil
	}

	initialConsensusMetadata, err := newTokenConsensusMetadata(
		provers,
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	initialSumcheckInfo, err := newTokenSumcheckInfo()
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	additionalData := make([]*qcrypto.VectorCommitmentTree, 14)
	additionalData[13], err = NewTokenConfigurationMetadata(
		t.config,
		t.rdfMultiprover,
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	tokenDomainBI, err := poseidon.HashBytes(
		slices.Concat(
			TOKEN_PREFIX,
			additionalData[13].Commit(t.inclusionProver, false),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	tokenDomain := tokenDomainBI.FillBytes(make([]byte, 32))

	t.domain = [32]byte(tokenDomain)

	rdfHypergraphSchema, err := newTokenRDFHypergraphSchema(
		tokenDomain,
		t.config,
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	if err := hgstate.Init(
		tokenDomain,
		initialConsensusMetadata,
		initialSumcheckInfo,
		rdfHypergraphSchema,
		additionalData,
		TOKEN_BASE_DOMAIN[:],
	); err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	if (t.config.Behavior & Divisible) == 0 {
		if len(contextData)%120 != 0 {
			return nil, errors.Wrap(
				errors.New("non-divisible token must have correct context data"),
				"deploy",
			)
		}

		additionalReferenceTree := &qcrypto.VectorCommitmentTree{}
		for i := 0; i < len(contextData)/120; i++ {
			err = additionalReferenceTree.Insert(
				binary.BigEndian.AppendUint32(nil, uint32(i*2)),
				contextData[i*120:(i*120)+64],
				nil,
				big.NewInt(64),
			)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			err = additionalReferenceTree.Insert(
				binary.BigEndian.AppendUint32(nil, uint32(i*2+1)),
				contextData[(i*120)+64:(i+1)*120],
				nil,
				big.NewInt(56),
			)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}
		}

		err = hgstate.Set(
			tokenDomain,
			TOKEN_ADDITIONAL_REFRENCES_ADDRESS[:],
			hg.VertexAddsDiscriminator,
			frameNumber,
			hgstate.(*hg.HypergraphState).NewVertexAddMaterializedState(
				[32]byte(tokenDomain),
				TOKEN_ADDITIONAL_REFRENCES_ADDRESS,
				frameNumber,
				nil,
				additionalReferenceTree,
			),
		)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}
	}
	t.state = hgstate
	t.rdfHypergraphSchema = rdfHypergraphSchema

	return t.state, nil
}

// Validate implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Validate(
	frameNumber uint64,
	input []byte,
) error {
	timer := prometheus.NewTimer(
		observability.ValidateDuration.WithLabelValues("token"),
	)
	defer timer.ObserveDuration()

	// Check the type prefix to determine operation type
	if len(input) < 4 {
		observability.ValidateErrors.WithLabelValues(
			"token",
			"invalid_input",
		).Inc()
		return errors.Wrap(
			errors.New("input too short to determine type"),
			"validate",
		)
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	switch typePrefix {
	case protobufs.TransactionType:
		tx := &Transaction{}
		if err := tx.FromBytes(
			input,
			t.config,
			t.hypergraph,
			t.bulletproofProver,
			t.inclusionProver,
			t.verEnc,
			t.decafConstructor,
			keys.ToKeyRing(t.keyManager, true),
			"",
			t.rdfMultiprover,
		); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the transaction
		valid, err := tx.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"transaction",
			).Inc()
			return errors.Wrap(errors.New("invalid transaction"), "validate")
		}

		observability.ValidateTotal.WithLabelValues("token", "transaction").Inc()
		return nil

	case protobufs.PendingTransactionType:
		pendingTx := &PendingTransaction{}
		if err := pendingTx.FromBytes(
			input,
			t.config,
			t.hypergraph,
			t.bulletproofProver,
			t.inclusionProver,
			t.verEnc,
			t.decafConstructor,
			keys.ToKeyRing(t.keyManager, true),
			"",
			t.rdfMultiprover,
		); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"pending_transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the pending transaction
		valid, err := pendingTx.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"pending_transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"pending_transaction",
			).Inc()
			return errors.Wrap(errors.New("invalid pending transaction"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"token",
			"pending_transaction",
		).Inc()
		return nil

	case protobufs.MintTransactionType:
		mintTx := &MintTransaction{}
		if err := mintTx.FromBytes(
			input,
			t.config,
			t.hypergraph,
			t.bulletproofProver,
			t.inclusionProver,
			t.verEnc,
			t.decafConstructor,
			keys.ToKeyRing(t.keyManager, true),
			"",
			t.rdfMultiprover,
		); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"mint_transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the mint transaction
		valid, err := mintTx.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"mint_transaction",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"token",
				"mint_transaction",
			).Inc()
			return errors.Wrap(errors.New("invalid mint transaction"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"token",
			"mint_transaction",
		).Inc()
		return nil

	default:
		observability.ValidateErrors.WithLabelValues(
			"token",
			"unknown_type",
		).Inc()
		return errors.Wrap(
			fmt.Errorf("unknown token operation type: %d", typePrefix),
			"validate",
		)
	}
}

// InvokeStep implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) InvokeStep(
	frameNumber uint64,
	input []byte,
	feePaid *big.Int,
	feeMultiplier *big.Int,
	state state.State,
) (state.State, error) {
	timer := prometheus.NewTimer(
		observability.InvokeStepDuration.WithLabelValues("token"),
	)
	defer timer.ObserveDuration()

	// Check type prefix to determine transaction type
	if len(input) < 4 {
		observability.InvokeStepErrors.WithLabelValues(
			"token",
			"invalid_input",
		).Inc()
		return nil, errors.Wrap(errors.New("invalid input length"), "invoke step")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	// Initialize transaction object based on type
	var operation intrinsics.IntrinsicOperation
	var opName string

	// Determine which type of transaction this is based on type prefix
	switch typePrefix {
	case protobufs.TransactionType:
		opName = "transaction"
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("token", opName),
		)
		defer opTimer.ObserveDuration()

		// Parse Transaction directly from input
		pbTx := &protobufs.Transaction{}
		if err := pbTx.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		tx, err := TransactionFromProtobuf(pbTx, t.inclusionProver)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Inject runtime dependencies
		tx.hypergraph = t.hypergraph
		tx.bulletproofProver = t.bulletproofProver
		tx.inclusionProver = t.inclusionProver
		tx.verEnc = t.verEnc
		tx.config = t.config
		tx.decafConstructor = t.decafConstructor
		tx.keyRing = keys.ToKeyRing(t.keyManager, true)
		tx.rdfMultiprover = t.rdfMultiprover

		// Verify the transaction
		valid, err := tx.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		if !valid {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(errors.New("invalid transaction"), "invoke step")
		}

		operation = tx

	case protobufs.PendingTransactionType:
		opName = "pending_transaction"
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("token", opName),
		)
		defer opTimer.ObserveDuration()

		// Parse PendingTransaction directly from input
		pbTx := &protobufs.PendingTransaction{}
		if err := pbTx.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		tx, err := PendingTransactionFromProtobuf(pbTx, t.inclusionProver)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Inject runtime dependencies
		tx.hypergraph = t.hypergraph
		tx.bulletproofProver = t.bulletproofProver
		tx.inclusionProver = t.inclusionProver
		tx.verEnc = t.verEnc
		tx.config = t.config
		tx.decafConstructor = t.decafConstructor
		tx.keyRing = keys.ToKeyRing(t.keyManager, true)
		tx.rdfMultiprover = t.rdfMultiprover

		// Verify the transaction
		valid, err := tx.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		if !valid {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(
				errors.New("invalid pending transaction"),
				"invoke step",
			)
		}

		operation = tx

	case protobufs.MintTransactionType:
		opName = "mint_transaction"
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("token", opName),
		)
		defer opTimer.ObserveDuration()

		// Parse MintTransaction directly from input
		pbTx := &protobufs.MintTransaction{}
		if err := pbTx.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		tx, err := MintTransactionFromProtobuf(pbTx)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Inject runtime dependencies
		tx.hypergraph = t.hypergraph
		tx.bulletproofProver = t.bulletproofProver
		tx.inclusionProver = t.inclusionProver
		tx.verEnc = t.verEnc
		tx.config = t.config
		tx.decafConstructor = t.decafConstructor
		tx.keyRing = keys.ToKeyRing(t.keyManager, true)
		tx.rdfMultiprover = t.rdfMultiprover
		tx.clockStore = t.clockStore

		// Verify the transaction
		valid, err := tx.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		if !valid {
			observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
			return nil, errors.Wrap(
				errors.New("invalid mint transaction"),
				"invoke step",
			)
		}

		operation = tx

	default:
		observability.InvokeStepErrors.WithLabelValues(
			"token",
			"unknown_type",
		).Inc()
		return nil, errors.Wrap(
			errors.New("unknown transaction type"),
			"invoke step",
		)
	}

	matTimer := prometheus.NewTimer(
		observability.MaterializeDuration.WithLabelValues("token"),
	)
	var err error
	t.state, err = operation.Materialize(frameNumber, state)
	matTimer.ObserveDuration()

	if err != nil {
		observability.InvokeStepErrors.WithLabelValues("token", opName).Inc()
		return t.state, errors.Wrap(err, "invoke step")
	}

	observability.InvokeStepTotal.WithLabelValues("token", opName).Inc()
	return t.state, nil
}

// Lock implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Lock(
	frameNumber uint64,
	input []byte,
) ([][]byte, error) {
	t.lockedReadsMx.Lock()
	t.lockedWritesMx.Lock()
	defer t.lockedReadsMx.Unlock()
	defer t.lockedWritesMx.Unlock()

	if t.lockedReads == nil {
		t.lockedReads = make(map[string]int)
	}

	if t.lockedWrites == nil {
		t.lockedWrites = make(map[string]struct{})
	}

	// Check type prefix to determine request type
	if len(input) < 4 {
		observability.LockErrors.WithLabelValues(
			"token",
			"invalid_input",
		).Inc()
		return nil, errors.Wrap(errors.New("input too short"), "lock")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	var reads, writes [][]byte
	var err error

	// Handle each type based on type prefix
	switch typePrefix {
	case protobufs.TransactionType:
		reads, writes, err = t.tryLockTransaction(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues("token", "transaction").Inc()

	case protobufs.PendingTransactionType:
		reads, writes, err = t.tryLockPendingTransaction(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues(
			"token",
			"pending_transaction",
		).Inc()

	case protobufs.MintTransactionType:
		reads, writes, err = t.tryLockMintTransaction(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues(
			"token",
			"mint_transaction",
		).Inc()

	default:
		observability.LockErrors.WithLabelValues(
			"token",
			"unknown_type",
		).Inc()
		return nil, errors.Wrap(
			errors.New("unknown compute request type"),
			"lock",
		)
	}

	for _, address := range writes {
		if _, ok := t.lockedWrites[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
		if _, ok := t.lockedReads[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for reading", address),
				"lock",
			)
		}
	}

	for _, address := range reads {
		if _, ok := t.lockedWrites[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
	}

	set := map[string]struct{}{}

	for _, address := range writes {
		t.lockedWrites[string(address)] = struct{}{}
		t.lockedReads[string(address)] = t.lockedReads[string(address)] + 1
		set[string(address)] = struct{}{}
	}

	for _, address := range reads {
		t.lockedReads[string(address)] = t.lockedReads[string(address)] + 1
		set[string(address)] = struct{}{}
	}

	result := [][]byte{}
	for a := range set {
		result = append(result, []byte(a))
	}

	return result, nil
}

// Unlock implements intrinsics.Intrinsic.
func (t *TokenIntrinsic) Unlock() error {
	t.lockedReadsMx.Lock()
	t.lockedWritesMx.Lock()
	defer t.lockedReadsMx.Unlock()
	defer t.lockedWritesMx.Unlock()

	t.lockedReads = make(map[string]int)
	t.lockedWrites = make(map[string]struct{})

	return nil
}

func (t *TokenIntrinsic) tryLockTransaction(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	tx := &Transaction{}
	if err := tx.FromBytes(
		input,
		t.config,
		t.hypergraph,
		t.bulletproofProver,
		t.inclusionProver,
		t.verEnc,
		t.decafConstructor,
		keys.ToKeyRing(t.keyManager, true),
		"",
		t.rdfMultiprover,
	); err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := tx.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := tx.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

func (t *TokenIntrinsic) tryLockPendingTransaction(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	pendingTx := &PendingTransaction{}
	if err := pendingTx.FromBytes(
		input,
		t.config,
		t.hypergraph,
		t.bulletproofProver,
		t.inclusionProver,
		t.verEnc,
		t.decafConstructor,
		keys.ToKeyRing(t.keyManager, true),
		"",
		t.rdfMultiprover,
	); err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"pending_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := pendingTx.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"pending_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := pendingTx.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"pending_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

func (t *TokenIntrinsic) tryLockMintTransaction(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	mintTx := &MintTransaction{}
	if err := mintTx.FromBytes(
		input,
		t.config,
		t.hypergraph,
		t.bulletproofProver,
		t.inclusionProver,
		t.verEnc,
		t.decafConstructor,
		keys.ToKeyRing(t.keyManager, true),
		"",
		t.rdfMultiprover,
	); err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"mint_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := mintTx.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"mint_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := mintTx.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"token",
			"mint_transaction",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

func (t *TokenIntrinsic) GetRDFSchemaDocument() string {
	return t.rdfHypergraphSchema
}

func (t *TokenIntrinsic) GetRDFSchema() (
	map[string]map[string]*schema.RDFTag,
	error,
) {
	tags, err := t.rdfMultiprover.GetSchemaMap(t.rdfHypergraphSchema)
	return tags, errors.Wrap(err, "get rdf schema")
}

func LoadTokenIntrinsic(
	appAddress []byte,
	hypergraph hgcrdt.Hypergraph,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	keyManager tkeys.KeyManager,
	clockStore store.ClockStore,
) (*TokenIntrinsic, error) {
	var config *TokenIntrinsicConfiguration
	var consensusMetadata *qcrypto.VectorCommitmentTree
	var sumcheckInfo *qcrypto.VectorCommitmentTree
	var rdfHypergraphSchema string

	if bytes.Equal(appAddress, QUIL_TOKEN_ADDRESS) {
		config = QUIL_TOKEN_CONFIGURATION
		consensusMetadata = &qcrypto.VectorCommitmentTree{}
		sumcheckInfo = &qcrypto.VectorCommitmentTree{}
		rdfHypergraphSchema = ""
	} else {
		vertexAddress := slices.Concat(
			appAddress,
			hg.HYPERGRAPH_METADATA_ADDRESS,
		)

		// Ensure the vertex is present and has not been removed
		_, err := hypergraph.GetVertex([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}

		tree, err := hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}

		config, err = unpackAndVerifyTokenConfigurationMetadata(
			inclusionProver,
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}

		consensusMetadata, err = unpackAndVerifyConsensusMetadata(tree)
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}

		sumcheckInfo, err = unpackAndVerifySumcheckInfo(tree)
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}

		rdfHypergraphSchema, err = unpackAndVerifyRdfHypergraphSchema(tree)
		if err != nil {
			return nil, errors.Wrap(err, "load token intrinsic")
		}
	}

	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, inclusionProver)

	return &TokenIntrinsic{
		lockedWrites:        make(map[string]struct{}),
		lockedReads:         make(map[string]int),
		domain:              [32]byte(appAddress),
		bulletproofProver:   bulletproofProver,
		inclusionProver:     inclusionProver,
		verEnc:              verEnc,
		decafConstructor:    decafConstructor,
		hypergraph:          hypergraph,
		config:              config,
		keyManager:          keyManager,
		consensusMetadata:   consensusMetadata,
		sumcheckInfo:        sumcheckInfo,
		rdfHypergraphSchema: rdfHypergraphSchema,
		rdfMultiprover:      rdfMultiprover,
		state:               hg.NewHypergraphState(hypergraph),
		clockStore:          clockStore,
	}, nil
}

func NewTokenIntrinsic(
	config *TokenIntrinsicConfiguration,
	hypergraph hgcrdt.Hypergraph,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	keyManager tkeys.KeyManager,
) (*TokenIntrinsic, error) {
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, inclusionProver)

	return &TokenIntrinsic{
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		decafConstructor:  decafConstructor,
		hypergraph:        hypergraph,
		config:            config,
		keyManager:        keyManager,
		state:             nil,
		rdfMultiprover:    rdfMultiprover,
	}, nil
}

var _ intrinsics.Intrinsic = (*TokenIntrinsic)(nil)
