package global

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	observability "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

type GlobalIntrinsic struct {
	lockedWrites        map[string]struct{}
	lockedReads         map[string]int
	lockedWritesMx      sync.RWMutex
	lockedReadsMx       sync.RWMutex
	state               state.State
	rdfHypergraphSchema string
	rdfMultiprover      *schema.RDFMultiprover
	hypergraph          hypergraph.Hypergraph
	keyManager          keys.KeyManager
}

var GLOBAL_RDF_SCHEMA = `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX prover: <https://types.quilibrium.com/schema-repository/global/prover/>
PREFIX allocation: <https://types.quilibrium.com/schema-repository/global/allocation/>
PREFIX reward: <https://types.quilibrium.com/schema-repository/global/reward/>

prover:Prover a rdfs:Class.
prover:PublicKey a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 585;
  qcl:order 0;
  rdfs:range prover:Prover.
prover:Status a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 1;
  rdfs:range prover:Prover.
prover:AvailableStorage a rdfs:Property;
  rdfs:domain qcl:Uint;
	qcl:size 8;
	qcl:order 2;
	rdfs:range prover:Prover.
prover:Seniority a rdfs:Property;
	rdfs:domain qcl:Uint;
	qcl:size 8;
	qcl:order 3;
	rdfs:range prover:Prover.
prover:KickFrameNumber a rdfs:Property;
	rdfs:domain qcl:Uint;
	qcl:size 8;
	qcl:order 4;
	rdfs:range prover:Prover.

allocation:ProverAllocation a rdfs:Class.
allocation:Prover a rdfs:Property;
  rdfs:domain prover:Prover;
	qcl:order 0;
	rdfs:range allocation:ProverAllocation.
allocation:Status a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 1;
  rdfs:range allocation:ProverAllocation.
allocation:ConfirmationFilter a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 2;
  rdfs:range allocation:ProverAllocation.
allocation:RejectionFilter a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 3;
  rdfs:range allocation:ProverAllocation.
allocation:JoinFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 4;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 5;
  rdfs:range allocation:ProverAllocation.
allocation:PauseFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 6;
  rdfs:range allocation:ProverAllocation.
allocation:ResumeFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 7;
  rdfs:range allocation:ProverAllocation.
allocation:KickFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 8;
  rdfs:range allocation:ProverAllocation.
allocation:JoinConfirmFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 9;
  rdfs:range allocation:ProverAllocation.
allocation:JoinRejectFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 10;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveConfirmFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 11;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveRejectFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 12;
  rdfs:range allocation:ProverAllocation.
allocation:LastActiveFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
	qcl:size 8;
	qcl:order 13;
	rdfs:range allocation:ProverAllocation.

reward:ProverReward a rdfs:Class.
reward:DelegateAddress a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 0;
  rdfs:range reward:ProverReward.
reward:Balance a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 1;
  rdfs:range reward:ProverReward.
`

// GetRDFSchema implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) GetRDFSchema() (
	map[string]map[string]*schema.RDFTag,
	error,
) {
	tags, err := a.rdfMultiprover.GetSchemaMap(a.rdfHypergraphSchema)
	return tags, errors.Wrap(err, "get rdf schema")
}

// SumCheck implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) SumCheck() bool {
	return true
}

// Address implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) Address() []byte {
	return intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]
}

// Commit implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) Commit() (state.State, error) {
	timer := prometheus.NewTimer(
		observability.CommitDuration.WithLabelValues("global"),
	)
	defer timer.ObserveDuration()

	if a.state == nil {
		observability.CommitErrors.WithLabelValues("global").Inc()
		return nil, errors.Wrap(errors.New("nothing to commit"), "commit")
	}

	if err := a.state.Commit(); err != nil {
		observability.CommitErrors.WithLabelValues("global").Inc()
		return a.state, errors.Wrap(err, "commit")
	}

	observability.CommitTotal.WithLabelValues("global").Inc()
	return a.state, nil
}

// Deploy implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) Deploy(
	domain [32]byte,
	provers [][]byte,
	creator []byte,
	fee *big.Int,
	contextData []byte,
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	return nil, errors.Wrap(
		errors.New("global intrinsic cannot be deployed"),
		"deploy",
	)
}

func (a *GlobalIntrinsic) Validate(
	frameNumber uint64,
	input []byte,
) error {
	timer := prometheus.NewTimer(
		observability.ValidateDuration.WithLabelValues("global"),
	)
	defer timer.ObserveDuration()

	// Check type prefix to determine request type
	if len(input) < 4 {
		observability.InvokeStepErrors.WithLabelValues(
			"global",
			"invalid_input",
		).Inc()
		return errors.Wrap(errors.New("input too short"), "validate")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	// Handle each type based on type prefix
	switch typePrefix {
	case protobufs.ProverJoinType:
		// Parse ProverJoin directly from input
		pbJoin := &protobufs.ProverJoin{}
		if err := pbJoin.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverJoinFromProtobuf(
			pbJoin,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return errors.Wrap(errors.New("invalid prover join"), "validate")
		}

		observability.ValidateTotal.WithLabelValues("global", "prover_join").Inc()
		return nil

	case protobufs.ProverLeaveType:
		// Parse ProverLeave directly from input
		pbLeave := &protobufs.ProverLeave{}
		if err := pbLeave.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverLeaveFromProtobuf(
			pbLeave,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return errors.Wrap(errors.New("invalid prover leave"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"global",
			"prover_leave",
		).Inc()
		return nil

	case protobufs.ProverPauseType:
		// Parse ProverPause directly from input
		pbPause := &protobufs.ProverPause{}
		if err := pbPause.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverPauseFromProtobuf(
			pbPause,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return errors.Wrap(errors.New("invalid prover pause"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"global",
			"prover_pause",
		).Inc()
		return nil

	case protobufs.ProverResumeType:
		// Parse ProverResume directly from input
		pbResume := &protobufs.ProverResume{}
		if err := pbResume.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverResumeFromProtobuf(
			pbResume,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return errors.Wrap(
				errors.New("invalid prover resume"),
				"validate",
			)
		}

		observability.ValidateTotal.WithLabelValues(
			"global",
			"prover_resume",
		).Inc()
		return nil

	case protobufs.ProverConfirmType:
		// Parse ProverConfirm directly from input
		pbConfirm := &protobufs.ProverConfirm{}
		if err := pbConfirm.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverConfirmFromProtobuf(
			pbConfirm,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return errors.Wrap(
				errors.New("invalid prover confirm"),
				"validate",
			)
		}

		observability.ValidateTotal.WithLabelValues(
			"global",
			"prover_confirm",
		).Inc()
		return nil

	case protobufs.ProverRejectType:
		// Parse ProverReject directly from input
		pbReject := &protobufs.ProverReject{}
		if err := pbReject.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverRejectFromProtobuf(
			pbReject,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return errors.Wrap(
				errors.New("invalid prover reject"),
				"validate",
			)
		}

		observability.ValidateTotal.WithLabelValues(
			"global",
			"prover_reject",
		).Inc()
		return nil

	case protobufs.ProverKickType:
		// Parse ProverKick directly from input
		pbKick := &protobufs.ProverKick{}
		if err := pbKick.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverKickFromProtobuf(pbKick, a.hypergraph, nil, a.keyManager)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return errors.Wrap(
				errors.New("invalid prover kick"),
				"validate",
			)
		}

		observability.ValidateTotal.WithLabelValues("global", "prover_kick").Inc()
		return nil

	default:
		observability.ValidateErrors.WithLabelValues(
			"global",
			"unknown_type",
		).Inc()
		return errors.Wrap(
			errors.New("unknown global request type"),
			"validate",
		)
	}
}

// InvokeStep implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) InvokeStep(
	frameNumber uint64,
	input []byte,
	fee *big.Int,
	feeMultiplier *big.Int,
	state state.State,
) (state.State, error) {
	timer := prometheus.NewTimer(
		observability.InvokeStepDuration.WithLabelValues("global"),
	)
	defer timer.ObserveDuration()

	// Check type prefix to determine request type
	if len(input) < 4 {
		observability.InvokeStepErrors.WithLabelValues(
			"global",
			"invalid_input",
		).Inc()
		return nil, errors.Wrap(errors.New("input too short"), "invoke step")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	// Handle each type based on type prefix
	switch typePrefix {
	case protobufs.ProverJoinType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("global", "prover_join"),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverJoin directly from input
		pbJoin := &protobufs.ProverJoin{}
		if err := pbJoin.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverJoinFromProtobuf(
			pbJoin,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return nil, errors.Wrap(errors.New("invalid prover join"), "invoke step")
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_join",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues("global", "prover_join").Inc()
		return a.state, nil

	case protobufs.ProverLeaveType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("global", "prover_leave"),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverLeave directly from input
		pbLeave := &protobufs.ProverLeave{}
		if err := pbLeave.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverLeaveFromProtobuf(
			pbLeave,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return nil, errors.Wrap(errors.New("invalid prover leave"), "invoke step")
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_leave",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues(
			"global",
			"prover_leave",
		).Inc()
		return a.state, nil

	case protobufs.ProverPauseType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("global", "prover_pause"),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverPause directly from input
		pbPause := &protobufs.ProverPause{}
		if err := pbPause.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverPauseFromProtobuf(
			pbPause,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return nil, errors.Wrap(errors.New("invalid prover pause"), "invoke step")
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_pause",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues(
			"global",
			"prover_pause",
		).Inc()
		return a.state, nil

	case protobufs.ProverResumeType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"global",
				"prover_resume",
			),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverResume directly from input
		pbResume := &protobufs.ProverResume{}
		if err := pbResume.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverResumeFromProtobuf(
			pbResume,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid prover resume"),
				"invoke step",
			)
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_resume",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues(
			"global",
			"prover_resume",
		).Inc()
		return a.state, nil

	case protobufs.ProverConfirmType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"global",
				"prover_confirm",
			),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverConfirm directly from input
		pbConfirm := &protobufs.ProverConfirm{}
		if err := pbConfirm.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverConfirmFromProtobuf(
			pbConfirm,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid prover confirm"),
				"invoke step",
			)
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_confirm",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues(
			"global",
			"prover_confirm",
		).Inc()
		return a.state, nil

	case protobufs.ProverRejectType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"global",
				"prover_reject",
			),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverReject directly from input
		pbReject := &protobufs.ProverReject{}
		if err := pbReject.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverRejectFromProtobuf(
			pbReject,
			a.hypergraph,
			nil,
			nil,
			a.keyManager,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph
		op.keyManager = a.keyManager

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid prover reject"),
				"invoke step",
			)
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_reject",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues(
			"global",
			"prover_reject",
		).Inc()
		return a.state, nil

	case protobufs.ProverKickType:
		opTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues("global", "prover_kick"),
		)
		defer opTimer.ObserveDuration()

		// Parse ProverKick directly from input
		pbKick := &protobufs.ProverKick{}
		if err := pbKick.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Convert from protobuf to intrinsics type
		op, err := ProverKickFromProtobuf(pbKick, a.hypergraph, nil, a.keyManager)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Set runtime dependencies
		op.rdfMultiprover = a.rdfMultiprover
		op.hypergraph = a.hypergraph

		valid, err := op.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid prover kick"),
				"invoke step",
			)
		}

		matTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("global"),
		)
		a.state, err = op.Materialize(frameNumber, state)
		matTimer.ObserveDuration()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"global",
				"prover_kick",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		observability.InvokeStepTotal.WithLabelValues("global", "prover_kick").Inc()
		return a.state, nil

	default:
		observability.InvokeStepErrors.WithLabelValues(
			"global",
			"unknown_type",
		).Inc()
		return nil, errors.Wrap(
			errors.New("unknown global request type"),
			"invoke step",
		)
	}
}

// Lock implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) Lock(
	writeAddresses [][]byte,
	readAddresses [][]byte,
) error {
	a.lockedReadsMx.Lock()
	a.lockedWritesMx.Lock()
	defer a.lockedReadsMx.Unlock()
	defer a.lockedWritesMx.Unlock()

	if a.lockedReads == nil {
		a.lockedReads = make(map[string]int)
	}

	if a.lockedWrites == nil {
		a.lockedWrites = make(map[string]struct{})
	}

	for _, address := range writeAddresses {
		if _, ok := a.lockedWrites[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
		if _, ok := a.lockedReads[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for reading", address),
				"lock",
			)
		}
	}

	for _, address := range readAddresses {
		if _, ok := a.lockedWrites[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
	}

	for _, address := range writeAddresses {
		a.lockedWrites[string(address)] = struct{}{}
		a.lockedReads[string(address)] = a.lockedReads[string(address)] + 1
	}

	for _, address := range readAddresses {
		a.lockedReads[string(address)] = a.lockedReads[string(address)] + 1
	}

	return nil
}

// Unlock implements intrinsics.Intrinsic.
func (a *GlobalIntrinsic) Unlock(
	writeAddresses [][]byte,
	readAddresses [][]byte,
) error {
	a.lockedReadsMx.Lock()
	a.lockedWritesMx.Lock()
	defer a.lockedReadsMx.Unlock()
	defer a.lockedWritesMx.Unlock()

	if a.lockedReads == nil {
		a.lockedReads = make(map[string]int)
	}

	if a.lockedWrites == nil {
		a.lockedWrites = make(map[string]struct{})
	}

	alteredWriteLocks := make(map[string]struct{})
	for k, v := range a.lockedWrites {
		alteredWriteLocks[k] = v
	}

	for _, address := range writeAddresses {
		delete(alteredWriteLocks, string(address))
	}

	for _, address := range readAddresses {
		if _, ok := alteredWriteLocks[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is still locked for writing", address),
				"unlock",
			)
		}
	}

	for _, address := range writeAddresses {
		delete(a.lockedWrites, string(address))
		i, ok := a.lockedReads[string(address)]
		if ok {
			if i <= 1 {
				delete(a.lockedReads, string(address))
			} else {
				a.lockedReads[string(address)] = i - 1
			}
		}
	}

	for _, address := range readAddresses {
		i, ok := a.lockedReads[string(address)]
		if ok {
			if i <= 1 {
				delete(a.lockedReads, string(address))
			} else {
				a.lockedReads[string(address)] = i - 1
			}
		}
	}

	return nil
}

// LoadGlobalIntrinsic loads the global intrinsic from the global intrinsic
// address. The global intrinsic is implicitly deployed and always exists at the
// global address.
func LoadGlobalIntrinsic(
	address []byte,
	hypergraph hypergraph.Hypergraph,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*GlobalIntrinsic, error) {
	// Verify the address is the global intrinsic address
	if !bytes.Equal(address, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) {
		return nil, errors.Wrap(
			errors.New("invalid address for global intrinsic"),
			"load global intrinsic",
		)
	}

	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, inclusionProver)

	// The global intrinsic doesn't need any initialization since it's implicitly
	// deployed
	return &GlobalIntrinsic{
		lockedWrites:        make(map[string]struct{}),
		lockedReads:         make(map[string]int),
		state:               nil,
		rdfHypergraphSchema: GLOBAL_RDF_SCHEMA,
		rdfMultiprover:      rdfMultiprover,
		hypergraph:          hypergraph,
		keyManager:          keyManager,
	}, nil
}

var _ intrinsics.Intrinsic = (*GlobalIntrinsic)(nil)
