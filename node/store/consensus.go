package store

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type PebbleConsensusStore struct {
	db     store.KVDB
	logger *zap.Logger
}

var _ consensus.ConsensusStore[*protobufs.ProposalVote] = (*PebbleConsensusStore)(nil)

func NewPebbleConsensusStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleConsensusStore {
	return &PebbleConsensusStore{
		db,
		logger,
	}
}

// GetConsensusState implements consensus.ConsensusStore.
func (p *PebbleConsensusStore) GetConsensusState(filter []byte) (
	*models.ConsensusState[*protobufs.ProposalVote],
	error,
) {
	value, closer, err := p.db.Get(
		slices.Concat([]byte{CONSENSUS, CONSENSUS_STATE}, filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get consensus state")
	}
	defer closer.Close()

	c := slices.Clone(value)
	if len(c) < 24 {
		return nil, errors.Wrap(errors.New("invalid data"), "get consensus state")
	}

	state := &models.ConsensusState[*protobufs.ProposalVote]{}
	buf := bytes.NewBuffer(c)

	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return nil, errors.Wrap(err, "get consensus state")
	}
	if filterLen > 0 {
		filterBytes := make([]byte, filterLen)
		if _, err := buf.Read(filterBytes); err != nil {
			return nil, errors.Wrap(err, "get consensus state")
		}
		state.Filter = filterBytes
	}

	if err := binary.Read(
		buf,
		binary.BigEndian,
		&state.FinalizedRank,
	); err != nil {
		return nil, errors.Wrap(err, "get consensus state")
	}

	if err := binary.Read(
		buf,
		binary.BigEndian,
		&state.LatestAcknowledgedRank,
	); err != nil {
		return nil, errors.Wrap(err, "get consensus state")
	}

	var latestTimeoutLen uint32
	if err := binary.Read(buf, binary.BigEndian, &latestTimeoutLen); err != nil {
		return nil, errors.Wrap(err, "get consensus state")
	}
	if latestTimeoutLen > 0 {
		latestTimeoutBytes := make([]byte, latestTimeoutLen)
		if _, err := buf.Read(latestTimeoutBytes); err != nil {
			return nil, errors.Wrap(err, "get consensus state")
		}
		lt := &protobufs.TimeoutState{}
		if err := lt.FromCanonicalBytes(latestTimeoutBytes); err != nil {
			return nil, errors.Wrap(err, "get consensus state")
		}
		state.LatestTimeout = &models.TimeoutState[*protobufs.ProposalVote]{
			Rank:                        lt.Vote.Rank,
			LatestQuorumCertificate:     lt.LatestQuorumCertificate,
			PriorRankTimeoutCertificate: lt.PriorRankTimeoutCertificate,
			Vote:                        &lt.Vote,
			TimeoutTick:                 lt.TimeoutTick,
		}
	}

	return state, nil
}

// GetLivenessState implements consensus.ConsensusStore.
func (p *PebbleConsensusStore) GetLivenessState(filter []byte) (
	*models.LivenessState,
	error,
) {
	value, closer, err := p.db.Get(
		slices.Concat([]byte{CONSENSUS, CONSENSUS_LIVENESS}, filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get liveness state")
	}
	defer closer.Close()

	c := slices.Clone(value)
	if len(c) < 20 {
		return nil, errors.Wrap(errors.New("invalid data"), "get liveness state")
	}

	state := &models.LivenessState{}
	buf := bytes.NewBuffer(c)

	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return nil, errors.Wrap(err, "get liveness state")
	}
	if filterLen > 0 {
		filterBytes := make([]byte, filterLen)
		if _, err := buf.Read(filterBytes); err != nil {
			return nil, errors.Wrap(err, "get liveness state")
		}
		state.Filter = filterBytes
	}

	if err := binary.Read(
		buf,
		binary.BigEndian,
		&state.CurrentRank,
	); err != nil {
		return nil, errors.Wrap(err, "get liveness state")
	}

	var latestQCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &latestQCLen); err != nil {
		return nil, errors.Wrap(err, "get liveness state")
	}
	if latestQCLen > 0 {
		latestQCBytes := make([]byte, latestQCLen)
		if _, err := buf.Read(latestQCBytes); err != nil {
			return nil, errors.Wrap(err, "get liveness state")
		}
		lt := &protobufs.QuorumCertificate{}
		if err := lt.FromCanonicalBytes(latestQCBytes); err != nil {
			return nil, errors.Wrap(err, "get liveness state")
		}
		state.LatestQuorumCertificate = lt
	}

	var priorTCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &priorTCLen); err != nil {
		return nil, errors.Wrap(err, "get liveness state")
	}
	if priorTCLen > 0 {
		priorTCBytes := make([]byte, priorTCLen)
		if _, err := buf.Read(priorTCBytes); err != nil {
			return nil, errors.Wrap(err, "get liveness state")
		}
		lt := &protobufs.TimeoutCertificate{}
		if err := lt.FromCanonicalBytes(priorTCBytes); err != nil {
			return nil, errors.Wrap(err, "get liveness state")
		}
		state.PriorRankTimeoutCertificate = lt
	}

	return state, nil
}

// PutConsensusState implements consensus.ConsensusStore.
func (p *PebbleConsensusStore) PutConsensusState(
	state *models.ConsensusState[*protobufs.ProposalVote],
) error {
	buf := new(bytes.Buffer)

	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(state.Filter)),
	); err != nil {
		return errors.Wrap(err, "put consensus state")
	}
	if _, err := buf.Write(state.Filter); err != nil {
		return errors.Wrap(err, "put consensus state")
	}

	if err := binary.Write(
		buf,
		binary.BigEndian,
		state.FinalizedRank,
	); err != nil {
		return errors.Wrap(err, "put consensus state")
	}

	if err := binary.Write(
		buf,
		binary.BigEndian,
		state.LatestAcknowledgedRank,
	); err != nil {
		return errors.Wrap(err, "put consensus state")
	}

	if state.LatestTimeout == nil {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(0),
		); err != nil {
			return errors.Wrap(err, "put consensus state")
		}
	} else {
		var priorTC *protobufs.TimeoutCertificate
		if state.LatestTimeout.PriorRankTimeoutCertificate != nil {
			priorTC = state.LatestTimeout.PriorRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
		}
		lt := &protobufs.TimeoutState{
			LatestQuorumCertificate:     state.LatestTimeout.LatestQuorumCertificate.(*protobufs.QuorumCertificate),
			PriorRankTimeoutCertificate: priorTC,
			Vote:                        *state.LatestTimeout.Vote,
			TimeoutTick:                 state.LatestTimeout.TimeoutTick,
		}
		timeoutBytes, err := lt.ToCanonicalBytes()
		if err != nil {
			return errors.Wrap(err, "put consensus state")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(timeoutBytes)),
		); err != nil {
			return errors.Wrap(err, "put consensus state")
		}
		if _, err := buf.Write(timeoutBytes); err != nil {
			return errors.Wrap(err, "put consensus state")
		}
	}

	return errors.Wrap(
		p.db.Set(
			slices.Concat([]byte{CONSENSUS, CONSENSUS_STATE}, state.Filter),
			buf.Bytes(),
		),
		"put consensus state",
	)
}

// PutLivenessState implements consensus.ConsensusStore.
func (p *PebbleConsensusStore) PutLivenessState(
	state *models.LivenessState,
) error {
	buf := new(bytes.Buffer)

	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(state.Filter)),
	); err != nil {
		return errors.Wrap(err, "put liveness state")
	}
	if _, err := buf.Write(state.Filter); err != nil {
		return errors.Wrap(err, "put liveness state")
	}

	if err := binary.Write(
		buf,
		binary.BigEndian,
		state.CurrentRank,
	); err != nil {
		return errors.Wrap(err, "put liveness state")
	}

	if state.LatestQuorumCertificate == nil {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(0),
		); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
	} else {
		qc := state.LatestQuorumCertificate.(*protobufs.QuorumCertificate)
		qcBytes, err := qc.ToCanonicalBytes()
		if err != nil {
			return errors.Wrap(err, "put liveness state")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(qcBytes)),
		); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
		if _, err := buf.Write(qcBytes); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
	}

	if state.PriorRankTimeoutCertificate == nil {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(0),
		); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
	} else {
		tc := state.PriorRankTimeoutCertificate.(*protobufs.TimeoutCertificate)
		timeoutBytes, err := tc.ToCanonicalBytes()
		if err != nil {
			return errors.Wrap(err, "put liveness state")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(timeoutBytes)),
		); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
		if _, err := buf.Write(timeoutBytes); err != nil {
			return errors.Wrap(err, "put liveness state")
		}
	}

	return errors.Wrap(
		p.db.Set(
			slices.Concat([]byte{CONSENSUS, CONSENSUS_LIVENESS}, state.Filter),
			buf.Bytes(),
		),
		"put liveness state",
	)
}
