package protobufs

import (
	"bytes"
	"encoding/binary"
	"slices"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Source implements models.QuorumCertificate.
func (g *QuorumCertificate) Equals(other models.QuorumCertificate) bool {
	return bytes.Equal(g.Filter, other.GetFilter()) &&
		g.Rank == other.GetRank() &&
		g.FrameNumber == other.GetFrameNumber() &&
		g.Identity() == other.Identity()
}

func (
	g *QuorumCertificate,
) GetAggregatedSignature() models.AggregatedSignature {
	return g.AggregateSignature
}

// Source implements models.Unique.
func (g *QuorumCertificate) Clone() models.Unique {
	return proto.Clone(g).(*QuorumCertificate)
}

// GetSignature implements models.Unique.
func (g *QuorumCertificate) GetSignature() []byte {
	return g.AggregateSignature.Signature
}

// Source implements models.Unique.
func (g *QuorumCertificate) Source() models.Identity {
	return g.AggregateSignature.Identity()
}

// Source implements models.Unique.
func (g *QuorumCertificate) Identity() models.Identity {
	return models.Identity(g.Selector)
}

// Source implements models.TimeoutCertificate.
func (g *TimeoutCertificate) Equals(other models.TimeoutCertificate) bool {
	if other == nil {
		return false
	}

	if t, ok := other.(*TimeoutCertificate); !ok || t == nil {
		return false
	}

	return bytes.Equal(g.Filter, other.GetFilter()) &&
		g.Rank == other.GetRank() &&
		slices.Equal(g.LatestRanks, other.GetLatestRanks()) &&
		g.LatestQuorumCertificate.Equals(other.GetLatestQuorumCert())
}

func (
	g *TimeoutCertificate,
) GetAggregatedSignature() models.AggregatedSignature {
	return g.AggregateSignature
}

func (
	g *TimeoutCertificate,
) GetLatestQuorumCert() models.QuorumCertificate {
	return g.LatestQuorumCertificate
}

// Source implements models.Unique.
func (g *TimeoutCertificate) Clone() models.Unique {
	return proto.Clone(g).(*TimeoutCertificate)
}

// GetSignature implements models.Unique.
func (g *TimeoutCertificate) GetSignature() []byte {
	return g.AggregateSignature.Signature
}

// Source implements models.Unique.
func (g *TimeoutCertificate) Source() models.Identity {
	return models.Identity(
		binary.BigEndian.AppendUint64(slices.Clone(g.Filter), g.Rank),
	)
}

// Source implements models.Unique.
func (g *TimeoutCertificate) Identity() models.Identity {
	return models.Identity(
		binary.BigEndian.AppendUint64(slices.Clone(g.Filter), g.Rank),
	)
}

// GetSignature implements models.Unique.
func (f *ProposalVote) Clone() models.Unique {
	return proto.Clone(f).(*ProposalVote)
}

// GetSignature implements models.Unique.
func (f *ProposalVote) GetSignature() []byte {
	return f.PublicKeySignatureBls48581.Signature
}

// Source implements models.Unique.
func (f *ProposalVote) Source() models.Identity {
	return models.Identity(f.Selector)
}

// GetSignature implements models.Unique.
func (f *ProposalVote) Identity() models.Identity {
	return models.Identity(f.PublicKeySignatureBls48581.Address)
}

func (g *GlobalFrame) Clone() models.Unique {
	return proto.Clone(g).(*GlobalFrame)
}

// GetRank implements models.Unique.
func (g *GlobalFrame) GetRank() uint64 {
	return g.Header.Rank
}

// GetSignature implements models.Unique.
func (g *GlobalFrame) GetSignature() []byte {
	return g.Header.PublicKeySignatureBls48581.Signature
}

// GetTimestamp implements models.Unique.
func (g *GlobalFrame) GetTimestamp() uint64 {
	return uint64(g.Header.Timestamp)
}

// Identity implements models.Unique.
func (g *GlobalFrame) Identity() models.Identity {
	selectorBI, err := poseidon.HashBytes(g.Header.Output)
	if err != nil {
		return ""
	}

	return models.Identity(selectorBI.FillBytes(make([]byte, 32)))
}

// Source implements models.Unique.
func (g *GlobalFrame) Source() models.Identity {
	return models.Identity(g.Header.Prover)
}

func (g *GlobalFrame) GetFrameNumber() uint64 {
	return g.Header.FrameNumber
}

func (a *AppShardFrame) Clone() models.Unique {
	return proto.Clone(a).(*AppShardFrame)
}

// GetRank implements models.Unique.
func (a *AppShardFrame) GetRank() uint64 {
	return a.Header.Rank
}

// GetSignature implements models.Unique.
func (a *AppShardFrame) GetSignature() []byte {
	return a.Header.PublicKeySignatureBls48581.Signature
}

// GetTimestamp implements models.Unique.
func (a *AppShardFrame) GetTimestamp() uint64 {
	return uint64(a.Header.Timestamp)
}

// Identity implements models.Unique.
func (a *AppShardFrame) Identity() models.Identity {
	selectorBI, err := poseidon.HashBytes(a.Header.Output)
	if err != nil {
		return ""
	}

	return models.Identity(selectorBI.FillBytes(make([]byte, 32)))
}

// Source implements models.Unique.
func (a *AppShardFrame) Source() models.Identity {
	return models.Identity(a.Header.Prover)
}

func (a *AppShardFrame) GetFrameNumber() uint64 {
	return a.Header.FrameNumber
}

func (s *AppShardProposal) GetRank() uint64 {
	rank := uint64(0)
	if s.State != nil && s.State.GetRank() > rank {
		rank = s.State.GetRank()
	}
	if s.ParentQuorumCertificate != nil &&
		s.ParentQuorumCertificate.GetRank() > rank {
		rank = s.ParentQuorumCertificate.GetRank()
	}
	if s.PriorRankTimeoutCertificate != nil &&
		s.PriorRankTimeoutCertificate.GetRank() > rank {
		rank = s.PriorRankTimeoutCertificate.GetRank()
	}
	return rank
}

func (s *AppShardProposal) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		AppShardProposalType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write state
	stateBytes, err := s.State.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(stateBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(stateBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_quorum_certificate
	parentQCBytes, err := s.ParentQuorumCertificate.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(parentQCBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(parentQCBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prior_rank_timeout_certificate
	if s.PriorRankTimeoutCertificate == nil {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(0),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		priorTCBytes, err := s.PriorRankTimeoutCertificate.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(priorTCBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(priorTCBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write vote
	voteBytes, err := s.Vote.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(voteBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(voteBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (s *AppShardProposal) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != AppShardProposalType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read state
	var stateLen uint32
	if err := binary.Read(buf, binary.BigEndian, &stateLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if stateLen > 7500000 {
		return errors.Wrap(
			errors.New("invalid state length"),
			"from canonical bytes",
		)
	}
	stateBytes := make([]byte, stateLen)
	if _, err := buf.Read(stateBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.State = &AppShardFrame{}
	if err := s.State.FromCanonicalBytes(stateBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_quorum_certificate
	var parentQCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentQCLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if parentQCLen > 33871 {
		return errors.Wrap(
			errors.New("invalid quorum certificate length"),
			"from canonical bytes",
		)
	}
	parentQCBytes := make([]byte, parentQCLen)
	if _, err := buf.Read(parentQCBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.ParentQuorumCertificate = &QuorumCertificate{}
	if err := s.ParentQuorumCertificate.FromCanonicalBytes(
		parentQCBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read prior_rank_timeout_certificate
	var priorRankTCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &priorRankTCLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if priorRankTCLen > 35194 {
		return errors.Wrap(
			errors.New("invalid prior rank timeout certificate length"),
			"from canonical bytes",
		)
	}
	if priorRankTCLen != 0 {
		priorRankTCBytes := make([]byte, priorRankTCLen)
		if _, err := buf.Read(priorRankTCBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		s.PriorRankTimeoutCertificate = &TimeoutCertificate{}
		if err := s.PriorRankTimeoutCertificate.FromCanonicalBytes(
			priorRankTCBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read vote
	var voteLen uint32
	if err := binary.Read(buf, binary.BigEndian, &voteLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if voteLen > 770 {
		return errors.Wrap(
			errors.New("invalid vote length"),
			"from canonical bytes",
		)
	}
	voteBytes := make([]byte, voteLen)
	if _, err := buf.Read(voteBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.Vote = &ProposalVote{}
	if err := s.Vote.FromCanonicalBytes(
		voteBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (s *GlobalProposal) GetRank() uint64 {
	rank := uint64(0)
	if s.State != nil && s.State.GetRank() > rank {
		rank = s.State.GetRank()
	}
	if s.ParentQuorumCertificate != nil &&
		s.ParentQuorumCertificate.GetRank() > rank {
		rank = s.ParentQuorumCertificate.GetRank()
	}
	if s.PriorRankTimeoutCertificate != nil &&
		s.PriorRankTimeoutCertificate.GetRank() > rank {
		rank = s.PriorRankTimeoutCertificate.GetRank()
	}
	return rank
}

func (s *GlobalProposal) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		GlobalProposalType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write state
	stateBytes, err := s.State.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(stateBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(stateBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_quorum_certificate
	parentQCBytes, err := s.ParentQuorumCertificate.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(parentQCBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(parentQCBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prior_rank_timeout_certificate
	if s.PriorRankTimeoutCertificate == nil {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(0),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		priorTCBytes, err := s.PriorRankTimeoutCertificate.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(priorTCBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(priorTCBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write vote
	voteBytes, err := s.Vote.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(voteBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(voteBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (s *GlobalProposal) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalProposalType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read state
	var stateLen uint32
	if err := binary.Read(buf, binary.BigEndian, &stateLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if stateLen > 7800000 {
		return errors.Wrap(
			errors.New("invalid state length"),
			"from canonical bytes",
		)
	}
	stateBytes := make([]byte, stateLen)
	if _, err := buf.Read(stateBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.State = &GlobalFrame{}
	if err := s.State.FromCanonicalBytes(stateBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_quorum_certificate
	var parentQCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentQCLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if parentQCLen > 847 {
		return errors.Wrap(
			errors.New("invalid parent quorum certificate length"),
			"from canonical bytes",
		)
	}
	parentQCBytes := make([]byte, parentQCLen)
	if _, err := buf.Read(parentQCBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.ParentQuorumCertificate = &QuorumCertificate{}
	if err := s.ParentQuorumCertificate.FromCanonicalBytes(
		parentQCBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read prior_rank_timeout_certificate
	var priorRankTCLen uint32
	if err := binary.Read(buf, binary.BigEndian, &priorRankTCLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if priorRankTCLen > 2170 {
		return errors.Wrap(
			errors.New("invalid prior rank timeout certificate length"),
			"from canonical bytes",
		)
	}
	if priorRankTCLen != 0 {
		priorRankTCBytes := make([]byte, priorRankTCLen)
		if _, err := buf.Read(priorRankTCBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		s.PriorRankTimeoutCertificate = &TimeoutCertificate{}
		if err := s.PriorRankTimeoutCertificate.FromCanonicalBytes(
			priorRankTCBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read vote
	var voteLen uint32
	if err := binary.Read(buf, binary.BigEndian, &voteLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if voteLen > 770 {
		return errors.Wrap(
			errors.New("invalid vote length"),
			"from canonical bytes",
		)
	}
	voteBytes := make([]byte, voteLen)
	if _, err := buf.Read(voteBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	s.Vote = &ProposalVote{}
	if err := s.Vote.FromCanonicalBytes(
		voteBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (s *SeniorityMerge) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		SeniorityMergeType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_type
	if err := binary.Write(buf, binary.BigEndian, s.KeyType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prover_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ProverPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.ProverPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (s *SeniorityMerge) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != SeniorityMergeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read signature
	var signatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &signatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if signatureLen > 114 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	s.Signature = make([]byte, signatureLen)
	if _, err := buf.Read(s.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read key_type
	if err := binary.Read(buf, binary.BigEndian, &s.KeyType); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read prover_public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen > 585 {
		return errors.Wrap(
			errors.New("invalid key length"),
			"from canonical bytes",
		)
	}
	s.ProverPublicKey = make([]byte, keyLen)
	if _, err := buf.Read(s.ProverPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (l *LegacyProverRequest) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		LegacyProverRequestType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signatures_ed448 count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(l.PublicKeySignaturesEd448)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, sig := range l.PublicKeySignaturesEd448 {
		sigBytes, err := sig.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (l *LegacyProverRequest) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != LegacyProverRequestType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key_signatures_ed448
	var sigCount uint32
	if err := binary.Read(buf, binary.BigEndian, &sigCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigCount > 100 {
		return errors.Wrap(
			errors.New("invalid signature count"),
			"from canonical bytes",
		)
	}
	l.PublicKeySignaturesEd448 = make([]*Ed448Signature, sigCount)
	for i := uint32(0); i < sigCount; i++ {
		var sigLen uint32
		if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if sigLen > 187 {
			return errors.Wrap(
				errors.New("invalid signature length"),
				"from canonical bytes",
			)
		}
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		l.PublicKeySignaturesEd448[i] = &Ed448Signature{}
		if err := l.PublicKeySignaturesEd448[i].FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverJoin) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverJoinType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filters count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each filter
	for _, filter := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(filter)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(filter); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write delegate_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.DelegateAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if len(p.DelegateAddress) != 0 {
		if _, err := buf.Write(p.DelegateAddress); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write merge_targets count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.MergeTargets)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each merge target
	for _, target := range p.MergeTargets {
		targetBytes, err := target.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(targetBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(targetBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (p *ProverJoin) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverJoinType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filters count
	var filtersCount uint32
	if err := binary.Read(buf, binary.BigEndian, &filtersCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	if filtersCount > 100 {
		return errors.Wrap(
			errors.New("invalid filter count"),
			"from canonical bytes",
		)
	}

	p.Filters = make([][]byte, filtersCount)
	// Read each filter
	for i := uint32(0); i < filtersCount; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if filterLen > 64 {
			return errors.Wrap(
				errors.New("invalid filter length"),
				"from canonical bytes",
			)
		}
		p.Filters[i] = make([]byte, filterLen)
		if _, err := buf.Read(p.Filters[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 753 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581SignatureWithProofOfPossession{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read delegate_address
	var delegateAddressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &delegateAddressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if delegateAddressLen > 32 {
		return errors.Wrap(
			errors.New("invalid delegate address length"),
			"from canonical bytes",
		)
	}
	p.DelegateAddress = make([]byte, delegateAddressLen)
	if _, err := buf.Read(p.DelegateAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read merge_targets count
	var mergeTargetsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mergeTargetsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.MergeTargets = make([]*SeniorityMerge, mergeTargetsCount)
	// Read each merge target
	for i := uint32(0); i < mergeTargetsCount; i++ {
		var targetLen uint32
		if err := binary.Read(buf, binary.BigEndian, &targetLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if targetLen > 675 {
			return errors.Wrap(
				errors.New("invalid merge target length"),
				"from canonical bytes",
			)
		}
		targetBytes := make([]byte, targetLen)
		if _, err := buf.Read(targetBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.MergeTargets[i] = &SeniorityMerge{}
		if err := p.MergeTargets[i].FromCanonicalBytes(
			targetBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proofLen > 51600 {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"from canonical bytes",
		)
	}
	p.Proof = make([]byte, proofLen)
	if _, err := buf.Read(p.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (p *ProverLeave) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverLeaveType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filters count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each filter
	for _, filter := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(filter)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(filter); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverLeave) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverLeaveType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filters count
	var filtersCount uint32
	if err := binary.Read(buf, binary.BigEndian, &filtersCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filtersCount > 100 {
		return errors.Wrap(
			errors.New("invalid filters count"),
			"from canonical byte",
		)
	}
	p.Filters = make([][]byte, filtersCount)
	// Read each filter
	for i := uint32(0); i < filtersCount; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if filterLen > 64 {
			return errors.Wrap(
				errors.New("invalid filter length"),
				"from canonical bytes",
			)
		}
		p.Filters[i] = make([]byte, filterLen)
		if _, err := buf.Read(p.Filters[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverPause) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverPauseType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverPause) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverPauseType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverResume) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverResumeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverResume) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverResumeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverConfirm) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverConfirmType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write deprecated field for filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(32),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(bytes.Repeat([]byte("reserved"), 4)); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write filters
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, f := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(f)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(f); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverConfirm) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverConfirmType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read filters
	filtersLen := uint32(0)
	if err := binary.Read(buf, binary.BigEndian, &filtersLen); err != nil {
		// Skip errors here, can be old messages
		return nil
	}

	if filtersLen > 100 {
		return errors.Wrap(
			errors.New("invalid filters length"),
			"from canonical bytes",
		)
	}

	p.Filters = make([][]byte, 0, filtersLen)
	for i := uint32(0); i < filtersLen; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if filterLen > 64 || filterLen < 32 {
			return errors.Wrap(
				errors.New("invalid filters length"),
				"from canonical bytes",
			)
		}

		filterBytes := make([]byte, filterLen)
		if _, err := buf.Read(filterBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Filters = append(p.Filters, filterBytes)
	}

	return nil
}

func (p *ProverReject) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverRejectType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write deprecated field for filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(32),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(bytes.Repeat([]byte("reserved"), 4)); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write filters
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, f := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(f)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(f); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverReject) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverRejectType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read filters
	filtersLen := uint32(0)
	if err := binary.Read(buf, binary.BigEndian, &filtersLen); err != nil {
		// Skip errors here, can be old messages
		return nil
	}

	if filtersLen > 100 {
		return errors.Wrap(
			errors.New("invalid filters length"),
			"from canonical bytes",
		)
	}

	p.Filters = make([][]byte, 0, filtersLen)
	for i := uint32(0); i < filtersLen; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if filterLen > 64 || filterLen < 32 {
			return errors.Wrap(
				errors.New("invalid filters length"),
				"from canonical bytes",
			)
		}

		filterBytes := make([]byte, filterLen)
		if _, err := buf.Read(filterBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Filters = append(p.Filters, filterBytes)
	}

	return nil
}

func (p *ProverUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverUpdateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write delegate_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.DelegateAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.DelegateAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverUpdateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read delegate_address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if addressLen > 32 {
		return errors.Wrap(
			errors.New("invalid address length"),
			"from canonical bytes",
		)
	}
	p.DelegateAddress = make([]byte, addressLen)
	if _, err := buf.Read(p.DelegateAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// AltShardUpdate serialization methods
func (a *AltShardUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, AltShardUpdateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.PublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.PublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, a.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write vertex_adds_root (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.VertexAddsRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.VertexAddsRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write vertex_removes_root (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.VertexRemovesRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.VertexRemovesRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hyperedge_adds_root (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.HyperedgeAddsRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.HyperedgeAddsRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hyperedge_removes_root (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.HyperedgeRemovesRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.HyperedgeRemovesRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (a *AltShardUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != AltShardUpdateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key
	var pubKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if pubKeyLen > 600 {
		return errors.Wrap(
			errors.New("invalid public key length"),
			"from canonical bytes",
		)
	}
	a.PublicKey = make([]byte, pubKeyLen)
	if _, err := buf.Read(a.PublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &a.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read vertex_adds_root
	var vertexAddsLen uint32
	if err := binary.Read(buf, binary.BigEndian, &vertexAddsLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if vertexAddsLen > 80 {
		return errors.Wrap(
			errors.New("invalid vertex adds root length"),
			"from canonical bytes",
		)
	}
	a.VertexAddsRoot = make([]byte, vertexAddsLen)
	if _, err := buf.Read(a.VertexAddsRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read vertex_removes_root
	var vertexRemovesLen uint32
	if err := binary.Read(buf, binary.BigEndian, &vertexRemovesLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if vertexRemovesLen > 80 {
		return errors.Wrap(
			errors.New("invalid vertex removes root length"),
			"from canonical bytes",
		)
	}
	a.VertexRemovesRoot = make([]byte, vertexRemovesLen)
	if _, err := buf.Read(a.VertexRemovesRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hyperedge_adds_root
	var hyperedgeAddsLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hyperedgeAddsLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if hyperedgeAddsLen > 80 {
		return errors.Wrap(
			errors.New("invalid hyperedge adds root length"),
			"from canonical bytes",
		)
	}
	a.HyperedgeAddsRoot = make([]byte, hyperedgeAddsLen)
	if _, err := buf.Read(a.HyperedgeAddsRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hyperedge_removes_root
	var hyperedgeRemovesLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hyperedgeRemovesLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if hyperedgeRemovesLen > 80 {
		return errors.Wrap(
			errors.New("invalid hyperedge removes root length"),
			"from canonical bytes",
		)
	}
	a.HyperedgeRemovesRoot = make([]byte, hyperedgeRemovesLen)
	if _, err := buf.Read(a.HyperedgeRemovesRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 80 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	a.Signature = make([]byte, sigLen)
	if _, err := buf.Read(a.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ShardSplit serialization methods
func (s *ShardSplit) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ShardSplitType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write shard_address (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ShardAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.ShardAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write number of proposed_shards
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ProposedShards)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each proposed shard (length-prefixed)
	for _, shard := range s.ProposedShards {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(shard)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(shard); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, s.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if s.PublicKeySignatureBls48581 != nil {
		sigBytes, err := s.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (s *ShardSplit) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ShardSplitType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read shard_address
	var addrLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if addrLen > 64 {
		return errors.Wrap(
			errors.New("invalid shard address length"),
			"from canonical bytes",
		)
	}
	s.ShardAddress = make([]byte, addrLen)
	if _, err := buf.Read(s.ShardAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read number of proposed_shards
	var numShards uint32
	if err := binary.Read(buf, binary.BigEndian, &numShards); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if numShards > 8 {
		return errors.Wrap(
			errors.New("too many proposed shards"),
			"from canonical bytes",
		)
	}

	// Read each proposed shard
	s.ProposedShards = make([][]byte, numShards)
	for i := uint32(0); i < numShards; i++ {
		var shardLen uint32
		if err := binary.Read(buf, binary.BigEndian, &shardLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if shardLen > 66 {
			return errors.Wrap(
				errors.New("invalid proposed shard length"),
				"from canonical bytes",
			)
		}
		s.ProposedShards[i] = make([]byte, shardLen)
		if _, err := buf.Read(s.ProposedShards[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &s.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		s.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := s.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (s *ShardSplit) Validate() error {
	if len(s.ShardAddress) < 32 || len(s.ShardAddress) > 63 {
		return errors.New("shard_address must be 32-63 bytes")
	}

	if len(s.ProposedShards) < 2 || len(s.ProposedShards) > 8 {
		return errors.New("proposed_shards must have 2-8 entries")
	}

	for _, shard := range s.ProposedShards {
		if len(shard) != len(s.ShardAddress)+1 &&
			len(shard) != len(s.ShardAddress)+2 {
			return errors.Errorf(
				"proposed shard length %d invalid for parent length %d",
				len(shard), len(s.ShardAddress),
			)
		}
		if !bytes.HasPrefix(shard, s.ShardAddress) {
			return errors.New("proposed shard must share parent prefix")
		}
	}

	if s.PublicKeySignatureBls48581 == nil {
		return errors.New("BLS signature must be present")
	}

	return nil
}

// ShardMerge serialization methods
func (s *ShardMerge) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ShardMergeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write number of shard_addresses
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ShardAddresses)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each shard address (length-prefixed)
	for _, addr := range s.ShardAddresses {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(addr)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(addr); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write parent_address (length-prefixed)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ParentAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.ParentAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, s.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if s.PublicKeySignatureBls48581 != nil {
		sigBytes, err := s.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (s *ShardMerge) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ShardMergeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read number of shard_addresses
	var numAddrs uint32
	if err := binary.Read(buf, binary.BigEndian, &numAddrs); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if numAddrs > 8 {
		return errors.Wrap(
			errors.New("too many shard addresses"),
			"from canonical bytes",
		)
	}

	// Read each shard address
	s.ShardAddresses = make([][]byte, numAddrs)
	for i := uint32(0); i < numAddrs; i++ {
		var addrLen uint32
		if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if addrLen > 64 {
			return errors.Wrap(
				errors.New("invalid shard address length"),
				"from canonical bytes",
			)
		}
		s.ShardAddresses[i] = make([]byte, addrLen)
		if _, err := buf.Read(s.ShardAddresses[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read parent_address
	var parentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if parentLen > 64 {
		return errors.Wrap(
			errors.New("invalid parent address length"),
			"from canonical bytes",
		)
	}
	s.ParentAddress = make([]byte, parentLen)
	if _, err := buf.Read(s.ParentAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &s.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		s.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := s.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (s *ShardMerge) Validate() error {
	if len(s.ShardAddresses) < 2 || len(s.ShardAddresses) > 8 {
		return errors.New("shard_addresses must have 2-8 entries")
	}

	if len(s.ParentAddress) != 32 {
		return errors.New("parent_address must be 32 bytes")
	}

	for _, addr := range s.ShardAddresses {
		if len(addr) <= 32 {
			return errors.New("cannot merge base shards (must be > 32 bytes)")
		}
		if !bytes.HasPrefix(addr, s.ParentAddress) {
			return errors.New(
				"all shard addresses must share the parent address prefix",
			)
		}
	}

	if s.PublicKeySignatureBls48581 == nil {
		return errors.New("BLS signature must be present")
	}

	return nil
}

func (m *MessageRequest) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MessageRequestType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Serialize the inner message (which already contains its own type discriminator)
	var innerBytes []byte
	var err error

	switch request := m.Request.(type) {
	case *MessageRequest_Join:
		innerBytes, err = request.Join.ToCanonicalBytes()
	case *MessageRequest_Leave:
		innerBytes, err = request.Leave.ToCanonicalBytes()
	case *MessageRequest_Pause:
		innerBytes, err = request.Pause.ToCanonicalBytes()
	case *MessageRequest_Resume:
		innerBytes, err = request.Resume.ToCanonicalBytes()
	case *MessageRequest_Confirm:
		innerBytes, err = request.Confirm.ToCanonicalBytes()
	case *MessageRequest_Reject:
		innerBytes, err = request.Reject.ToCanonicalBytes()
	case *MessageRequest_Kick:
		innerBytes, err = request.Kick.ToCanonicalBytes()
	case *MessageRequest_Update:
		innerBytes, err = request.Update.ToCanonicalBytes()
	case *MessageRequest_TokenDeploy:
		innerBytes, err = request.TokenDeploy.ToCanonicalBytes()
	case *MessageRequest_TokenUpdate:
		innerBytes, err = request.TokenUpdate.ToCanonicalBytes()
	case *MessageRequest_Transaction:
		innerBytes, err = request.Transaction.ToCanonicalBytes()
	case *MessageRequest_PendingTransaction:
		innerBytes, err = request.PendingTransaction.ToCanonicalBytes()
	case *MessageRequest_MintTransaction:
		innerBytes, err = request.MintTransaction.ToCanonicalBytes()
	case *MessageRequest_HypergraphDeploy:
		innerBytes, err = request.HypergraphDeploy.ToCanonicalBytes()
	case *MessageRequest_HypergraphUpdate:
		innerBytes, err = request.HypergraphUpdate.ToCanonicalBytes()
	case *MessageRequest_VertexAdd:
		innerBytes, err = request.VertexAdd.ToCanonicalBytes()
	case *MessageRequest_VertexRemove:
		innerBytes, err = request.VertexRemove.ToCanonicalBytes()
	case *MessageRequest_HyperedgeAdd:
		innerBytes, err = request.HyperedgeAdd.ToCanonicalBytes()
	case *MessageRequest_HyperedgeRemove:
		innerBytes, err = request.HyperedgeRemove.ToCanonicalBytes()
	case *MessageRequest_ComputeDeploy:
		innerBytes, err = request.ComputeDeploy.ToCanonicalBytes()
	case *MessageRequest_ComputeUpdate:
		innerBytes, err = request.ComputeUpdate.ToCanonicalBytes()
	case *MessageRequest_CodeDeploy:
		innerBytes, err = request.CodeDeploy.ToCanonicalBytes()
	case *MessageRequest_CodeExecute:
		innerBytes, err = request.CodeExecute.ToCanonicalBytes()
	case *MessageRequest_CodeFinalize:
		innerBytes, err = request.CodeFinalize.ToCanonicalBytes()
	case *MessageRequest_Shard:
		innerBytes, err = request.Shard.ToCanonicalBytes()
	case *MessageRequest_AltShardUpdate:
		innerBytes, err = request.AltShardUpdate.ToCanonicalBytes()
	case *MessageRequest_SeniorityMerge:
		innerBytes, err = request.SeniorityMerge.ToCanonicalBytes()
	case *MessageRequest_ShardSplit:
		innerBytes, err = request.ShardSplit.ToCanonicalBytes()
	case *MessageRequest_ShardMerge:
		innerBytes, err = request.ShardMerge.ToCanonicalBytes()
	default:
		return nil, errors.New("unknown request type")
	}

	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write length-prefixed inner message
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(innerBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(innerBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MessageRequest) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageRequestType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read length of inner message
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	if dataLen == 0 {
		return errors.New("empty message request")
	}

	// Read the inner message bytes
	dataBytes := make([]byte, dataLen)
	if _, err := buf.Read(dataBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Peek at the type discriminator (first 4 bytes)
	if len(dataBytes) < 4 {
		return errors.New("message too short to contain type discriminator")
	}

	innerTypeBuf := bytes.NewBuffer(dataBytes[:4])
	var innerType uint32
	if err := binary.Read(
		innerTypeBuf,
		binary.BigEndian,
		&innerType,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Route based on the embedded type discriminator
	switch innerType {
	case ProverJoinType:
		join := &ProverJoin{}
		if err := join.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Join{Join: join}

	case ProverLeaveType:
		leave := &ProverLeave{}
		if err := leave.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Leave{Leave: leave}

	case ProverPauseType:
		pause := &ProverPause{}
		if err := pause.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Pause{Pause: pause}

	case ProverResumeType:
		resume := &ProverResume{}
		if err := resume.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Resume{Resume: resume}

	case ProverConfirmType:
		confirm := &ProverConfirm{}
		if err := confirm.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Confirm{Confirm: confirm}

	case ProverRejectType:
		reject := &ProverReject{}
		if err := reject.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Reject{Reject: reject}

	case ProverKickType:
		kick := &ProverKick{}
		if err := kick.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Kick{Kick: kick}

	case ProverUpdateType:
		update := &ProverUpdate{}
		if err := update.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Update{Update: update}

	case TokenDeploymentType:
		tokenDeploy := &TokenDeploy{}
		if err := tokenDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_TokenDeploy{TokenDeploy: tokenDeploy}

	case TokenUpdateType:
		tokenUpdate := &TokenUpdate{}
		if err := tokenUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_TokenUpdate{TokenUpdate: tokenUpdate}

	case TransactionType:
		transaction := &Transaction{}
		if err := transaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Transaction{Transaction: transaction}

	case PendingTransactionType:
		pendingTransaction := &PendingTransaction{}
		if err := pendingTransaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_PendingTransaction{
			PendingTransaction: pendingTransaction,
		}

	case MintTransactionType:
		mintTransaction := &MintTransaction{}
		if err := mintTransaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_MintTransaction{
			MintTransaction: mintTransaction,
		}

	case HypergraphDeploymentType:
		hypergraphDeploy := &HypergraphDeploy{}
		if err := hypergraphDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HypergraphDeploy{
			HypergraphDeploy: hypergraphDeploy,
		}

	case HypergraphUpdateType:
		hypergraphUpdate := &HypergraphUpdate{}
		if err := hypergraphUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HypergraphUpdate{
			HypergraphUpdate: hypergraphUpdate,
		}

	case VertexAddType:
		vertexAdd := &VertexAdd{}
		if err := vertexAdd.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_VertexAdd{VertexAdd: vertexAdd}

	case VertexRemoveType:
		vertexRemove := &VertexRemove{}
		if err := vertexRemove.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_VertexRemove{VertexRemove: vertexRemove}

	case HyperedgeAddType:
		hyperedgeAdd := &HyperedgeAdd{}
		if err := hyperedgeAdd.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HyperedgeAdd{HyperedgeAdd: hyperedgeAdd}

	case HyperedgeRemoveType:
		hyperedgeRemove := &HyperedgeRemove{}
		if err := hyperedgeRemove.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HyperedgeRemove{
			HyperedgeRemove: hyperedgeRemove,
		}

	case ComputeDeploymentType:
		computeDeploy := &ComputeDeploy{}
		if err := computeDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ComputeDeploy{ComputeDeploy: computeDeploy}

	case ComputeUpdateType:
		computeUpdate := &ComputeUpdate{}
		if err := computeUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ComputeUpdate{ComputeUpdate: computeUpdate}

	case CodeDeploymentType:
		codeDeploy := &CodeDeployment{}
		if err := codeDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeDeploy{CodeDeploy: codeDeploy}

	case CodeExecuteType:
		codeExecute := &CodeExecute{}
		if err := codeExecute.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeExecute{CodeExecute: codeExecute}

	case CodeFinalizeType:
		codeFinalize := &CodeFinalize{}
		if err := codeFinalize.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeFinalize{CodeFinalize: codeFinalize}

	case FrameHeaderType:
		frameHeader := &FrameHeader{}
		if err := frameHeader.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Shard{Shard: frameHeader}

	case AltShardUpdateType:
		altShardUpdate := &AltShardUpdate{}
		if err := altShardUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_AltShardUpdate{
			AltShardUpdate: altShardUpdate,
		}

	case ProverSeniorityMergeType:
		seniorityMerge := &ProverSeniorityMerge{}
		if err := seniorityMerge.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_SeniorityMerge{
			SeniorityMerge: seniorityMerge,
		}

	case ShardSplitType:
		shardSplit := &ShardSplit{}
		if err := shardSplit.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ShardSplit{
			ShardSplit: shardSplit,
		}

	case ShardMergeType:
		shardMerge := &ShardMerge{}
		if err := shardMerge.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ShardMerge{
			ShardMerge: shardMerge,
		}

	default:
		return errors.Errorf("unknown message type: 0x%08X", innerType)
	}

	return nil
}

func (m *MessageBundle) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MessageBundleType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write number of requests
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each request
	for _, request := range m.Requests {
		if request != nil {
			requestBytes, err := request.ToCanonicalBytes()
			if err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(requestBytes)),
			); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if _, err := buf.Write(requestBytes); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		} else {
			if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		}
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, m.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MessageBundle) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageBundleType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read number of requests
	var numRequests uint32
	if err := binary.Read(buf, binary.BigEndian, &numRequests); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read each request
	m.Requests = make([]*MessageRequest, 0, numRequests)
	for i := uint32(0); i < numRequests; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if requestLen > 0 {
			requestBytes := make([]byte, requestLen)
			if _, err := buf.Read(requestBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			request := &MessageRequest{}
			if err := request.FromCanonicalBytes(requestBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			m.Requests = append(m.Requests, request)
		} else {
			m.Requests = append(m.Requests, nil)
		}
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &m.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (g *GlobalFrameHeader) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		GlobalFrameHeaderType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, g.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rank
	if err := binary.Write(buf, binary.BigEndian, g.Rank); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, g.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write difficulty
	if err := binary.Write(buf, binary.BigEndian, g.Difficulty); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.ParentSelector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.ParentSelector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write global_commitments count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.GlobalCommitments)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, commitment := range g.GlobalCommitments {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(commitment)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(commitment); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover_tree_commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.ProverTreeCommitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.ProverTreeCommitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write requests_root
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.RequestsRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.RequestsRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prover
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Prover)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.Prover); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if g.PublicKeySignatureBls48581 != nil {
		sigBytes, err := g.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (g *GlobalFrameHeader) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalFrameHeaderType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &g.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rank
	if err := binary.Read(buf, binary.BigEndian, &g.Rank); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &g.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read difficulty
	if err := binary.Read(buf, binary.BigEndian, &g.Difficulty); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if outputLen > 516 {
		return errors.Wrap(
			errors.New("invalid output length"),
			"from canonical bytes",
		)
	}
	g.Output = make([]byte, outputLen)
	if _, err := buf.Read(g.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_selector
	var parentSelectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentSelectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if parentSelectorLen > 32 {
		return errors.Wrap(
			errors.New("invalid parent selector length"),
			"from canonical bytes",
		)
	}
	g.ParentSelector = make([]byte, parentSelectorLen)
	if _, err := buf.Read(g.ParentSelector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read global_commitments
	var commitmentsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitmentsCount > 256 {
		return errors.Wrap(
			errors.New("invalid commitments count"),
			"from canonical bytes",
		)
	}
	g.GlobalCommitments = make([][]byte, commitmentsCount)
	for i := uint32(0); i < commitmentsCount; i++ {
		var commitmentLen uint32
		if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if commitmentLen > 74 {
			return errors.Wrap(
				errors.New("invalid commitment length"),
				"from canonical bytes",
			)
		}
		g.GlobalCommitments[i] = make([]byte, commitmentLen)
		if _, err := buf.Read(g.GlobalCommitments[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover_tree_commitment
	var proverTreeCommitmentLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&proverTreeCommitmentLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proverTreeCommitmentLen > 74 {
		return errors.Wrap(
			errors.New("invalid prover tree commitment length"),
			"from canonical bytes",
		)
	}
	g.ProverTreeCommitment = make([]byte, proverTreeCommitmentLen)
	if _, err := buf.Read(g.ProverTreeCommitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read requests_root
	var requestsRootLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&requestsRootLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if requestsRootLen > 74 {
		return errors.Wrap(
			errors.New("invalid requests root length"),
			"from canonical bytes",
		)
	}
	g.RequestsRoot = make([]byte, requestsRootLen)
	if _, err := buf.Read(g.RequestsRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read prover
	var proverLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&proverLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proverLen > 32 {
		return errors.Wrap(
			errors.New("invalid prover length"),
			"from canonical bytes",
		)
	}
	g.Prover = make([]byte, proverLen)
	if _, err := buf.Read(g.Prover); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 711 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := g.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (f *FrameHeader) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, FrameHeaderType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rank
	if err := binary.Write(buf, binary.BigEndian, f.Rank); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, f.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write difficulty
	if err := binary.Write(buf, binary.BigEndian, f.Difficulty); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.ParentSelector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.ParentSelector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write requests_root
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.RequestsRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.RequestsRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write state_roots count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.StateRoots)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, root := range f.StateRoots {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(root)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(root); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Prover)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Prover); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write fee_multiplier_vote
	if err := binary.Write(
		buf,
		binary.BigEndian,
		f.FeeMultiplierVote,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if f.PublicKeySignatureBls48581 != nil {
		sigBytes, err := f.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *FrameHeader) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != FrameHeaderType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if addressLen > 64 {
		return errors.Wrap(
			errors.New("invalid address length"),
			"from canonical bytes",
		)
	}
	f.Address = make([]byte, addressLen)
	if _, err := buf.Read(f.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rank
	if err := binary.Read(buf, binary.BigEndian, &f.Rank); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &f.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read difficulty
	if err := binary.Read(buf, binary.BigEndian, &f.Difficulty); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if outputLen != 516 {
		return errors.Wrap(
			errors.New("invalid output length"),
			"from canonical bytes",
		)
	}
	f.Output = make([]byte, outputLen)
	if _, err := buf.Read(f.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_selector
	var parentSelectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentSelectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if parentSelectorLen > 32 {
		return errors.Wrap(
			errors.New("invalid selector length"),
			"from canonical bytes",
		)
	}
	f.ParentSelector = make([]byte, parentSelectorLen)
	if _, err := buf.Read(f.ParentSelector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read requests_root
	var requestsRootLen uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsRootLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if requestsRootLen > 74 {
		return errors.Wrap(
			errors.New("invalid requests root length"),
			"from canonical bytes",
		)
	}
	f.RequestsRoot = make([]byte, requestsRootLen)
	if _, err := buf.Read(f.RequestsRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read state_roots
	var stateRootsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &stateRootsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if stateRootsCount != 4 {
		return errors.Wrap(
			errors.New("invalid state roots length"),
			"from canonical bytes",
		)
	}
	f.StateRoots = make([][]byte, stateRootsCount)
	for i := uint32(0); i < stateRootsCount; i++ {
		var rootLen uint32
		if err := binary.Read(buf, binary.BigEndian, &rootLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if rootLen > 74 {
			return errors.Wrap(
				errors.New("invalid state root length"),
				"from canonical bytes",
			)
		}
		f.StateRoots[i] = make([]byte, rootLen)
		if _, err := buf.Read(f.StateRoots[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover
	var proverLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proverLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proverLen > 32 {
		return errors.Wrap(
			errors.New("invalid prover length"),
			"from canonical bytes",
		)
	}
	f.Prover = make([]byte, proverLen)
	if _, err := buf.Read(f.Prover); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read fee_multiplier_vote
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&f.FeeMultiplierVote,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 33735 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := f.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverLivenessCheck) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ProverLivenessCheckType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, p.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment_hash
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.CommitmentHash)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.CommitmentHash); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverLivenessCheck) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverLivenessCheckType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &p.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read commitment_hash
	var commitmentHashLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentHashLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitmentHashLen > 20000 {
		return errors.Wrap(
			errors.New("invalid commitment hash length"),
			"from canonical bytes",
		)
	}
	p.CommitmentHash = make([]byte, commitmentHashLen)
	if _, err := buf.Read(p.CommitmentHash); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen == 0 {
		return errors.Wrap(errors.New("invalid signature"), "from canonical bytes")
	}

	sigBytes := make([]byte, sigLen)
	if _, err := buf.Read(sigBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
	if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
		sigBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (f *ProposalVote) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProposalVoteType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rank
	if err := binary.Write(buf, binary.BigEndian, f.Rank); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Selector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Selector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, f.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if f.PublicKeySignatureBls48581 != nil {
		sigBytes, err := f.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *ProposalVote) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProposalVoteType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	f.Filter = make([]byte, filterLen)
	if _, err := buf.Read(f.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rank
	if err := binary.Read(buf, binary.BigEndian, &f.Rank); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read selector
	var selectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &selectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if selectorLen > 32 {
		return errors.Wrap(
			errors.New("invalid selector length"),
			"from canonical bytes",
		)
	}
	f.Selector = make([]byte, selectorLen)
	if _, err := buf.Read(f.Selector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &f.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 634 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := f.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (f *TimeoutState) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TimeoutStateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write latest_quorum_certificate
	latestQCBytes, err := f.LatestQuorumCertificate.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(latestQCBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(latestQCBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prior_rank_timeout_certificate
	if f.PriorRankTimeoutCertificate != nil {
		priorTCBytes, err := f.PriorRankTimeoutCertificate.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(priorTCBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(priorTCBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write vote
	if f.Vote != nil {
		voteBytes, err := f.Vote.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(voteBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(voteBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write timeout_tick
	if err := binary.Write(buf, binary.BigEndian, f.TimeoutTick); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, f.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (f *TimeoutState) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TimeoutStateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read latest_quorum_certificate
	var latestQuorumCertLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&latestQuorumCertLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if latestQuorumCertLen > 33871 {
		return errors.Wrap(
			errors.New("invalid latest quorum certificate length"),
			"from canonical bytes",
		)
	}
	if latestQuorumCertLen > 0 {
		latestQuorumCertBytes := make([]byte, latestQuorumCertLen)
		if _, err := buf.Read(latestQuorumCertBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.LatestQuorumCertificate = &QuorumCertificate{}
		if err := f.LatestQuorumCertificate.FromCanonicalBytes(
			latestQuorumCertBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prior_rank_timeout_certificate
	var priorRankTimeoutCertLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&priorRankTimeoutCertLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if priorRankTimeoutCertLen > 35194 {
		return errors.Wrap(
			errors.New("invalid prior rank timeout certificate length"),
			"from canonical bytes",
		)
	}
	if priorRankTimeoutCertLen > 0 {
		priorRankTimeoutBytes := make([]byte, priorRankTimeoutCertLen)
		if _, err := buf.Read(priorRankTimeoutBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.PriorRankTimeoutCertificate = &TimeoutCertificate{}
		if err := f.PriorRankTimeoutCertificate.FromCanonicalBytes(
			priorRankTimeoutBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read vote
	var voteLen uint32
	if err := binary.Read(buf, binary.BigEndian, &voteLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if voteLen > 770 {
		return errors.Wrap(
			errors.New("invalid vote length"),
			"from canonical bytes",
		)
	}
	if voteLen > 0 {
		voteBytes := make([]byte, voteLen)
		if _, err := buf.Read(voteBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.Vote = &ProposalVote{}
		if err := f.Vote.FromCanonicalBytes(voteBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read timeout_tick
	if err := binary.Read(buf, binary.BigEndian, &f.TimeoutTick); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &f.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (f *QuorumCertificate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		QuorumCertificateType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rank
	if err := binary.Write(buf, binary.BigEndian, f.Rank); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Selector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Selector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	if err := binary.Write(buf, binary.BigEndian, f.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write aggregate_signature
	if f.AggregateSignature != nil {
		sigBytes, err := f.AggregateSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *QuorumCertificate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != QuorumCertificateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	f.Filter = make([]byte, filterLen)
	if _, err := buf.Read(f.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rank
	if err := binary.Read(buf, binary.BigEndian, &f.Rank); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read selector
	var selectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &selectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if selectorLen > 32 {
		return errors.Wrap(
			errors.New("invalid selector length"),
			"from canonical bytes",
		)
	}
	f.Selector = make([]byte, selectorLen)
	if _, err := buf.Read(f.Selector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &f.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read aggregate_signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 33735 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.AggregateSignature = &BLS48581AggregateSignature{}
		if err := f.AggregateSignature.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TimeoutCertificate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TimeoutCertificateType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rank
	if err := binary.Write(buf, binary.BigEndian, t.Rank); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write latest_ranks
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.LatestRanks)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, r := range t.LatestRanks {
		if err := binary.Write(buf, binary.BigEndian, r); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write latest_quorum_certificate
	if t.LatestQuorumCertificate != nil {
		latestQCBytes, err := t.LatestQuorumCertificate.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(latestQCBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(latestQCBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, t.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write aggregate_signature
	if t.AggregateSignature != nil {
		sigBytes, err := t.AggregateSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TimeoutCertificate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TimeoutCertificateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if filterLen > 64 {
		return errors.Wrap(
			errors.New("invalid filter length"),
			"from canonical bytes",
		)
	}
	t.Filter = make([]byte, filterLen)
	if _, err := buf.Read(t.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rank
	if err := binary.Read(buf, binary.BigEndian, &t.Rank); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read latest_ranks
	var latestRanksCount uint32
	if err := binary.Read(buf, binary.BigEndian, &latestRanksCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if latestRanksCount > 64 {
		return errors.Wrap(
			errors.New("invalid latest ranks count"),
			"from canonical bytes",
		)
	}
	t.LatestRanks = make([]uint64, latestRanksCount)
	if err := binary.Read(buf, binary.BigEndian, &t.LatestRanks); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read latest_quorum_certificate
	var latestQuorumCertLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&latestQuorumCertLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if latestQuorumCertLen > 33871 {
		return errors.Wrap(
			errors.New("invalid latest quorum certificate length"),
			"from canonical bytes",
		)
	}
	if latestQuorumCertLen > 0 {
		latestQuorumCertBytes := make([]byte, latestQuorumCertLen)
		if _, err := buf.Read(latestQuorumCertBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.LatestQuorumCertificate = &QuorumCertificate{}
		if err := t.LatestQuorumCertificate.FromCanonicalBytes(
			latestQuorumCertBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &t.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read aggregate_signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 711 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.AggregateSignature = &BLS48581AggregateSignature{}
		if err := t.AggregateSignature.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (g *GlobalFrame) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, GlobalFrameType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write header
	if g.Header != nil {
		headerBytes, err := g.Header.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(headerBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(headerBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write requests count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, request := range g.Requests {
		requestBytes, err := request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(requestBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(requestBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (g *GlobalFrame) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalFrameType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read header
	var headerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if headerLen > 21467 {
		return errors.Wrap(
			errors.New("invalid header length"),
			"from canonical bytes",
		)
	}
	if headerLen > 0 {
		headerBytes := make([]byte, headerLen)
		if _, err := buf.Read(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.Header = &GlobalFrameHeader{}
		if err := g.Header.FromCanonicalBytes(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read requests
	var requestsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if requestsCount > 100 {
		return errors.Wrap(
			errors.New("invalid requests count"),
			"from canonical bytes",
		)
	}
	g.Requests = make([]*MessageBundle, requestsCount)
	for i := uint32(0); i < requestsCount; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if requestLen > 75000 {
			return errors.Wrap(
				errors.New("invalid request length"),
				"from canonical bytes",
			)
		}
		requestBytes := make([]byte, requestLen)
		if _, err := buf.Read(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.Requests[i] = &MessageBundle{}
		if err := g.Requests[i].FromCanonicalBytes(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (a *AppShardFrame) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, AppShardFrameType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write header
	if a.Header != nil {
		headerBytes, err := a.Header.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(headerBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(headerBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write requests count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, request := range a.Requests {
		requestBytes, err := request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(requestBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(requestBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (a *AppShardFrame) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != AppShardFrameType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read header
	var headerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if headerLen > 34829 {
		return errors.Wrap(
			errors.New("invalid header length"),
			"from canonical bytes",
		)
	}
	if headerLen > 0 {
		headerBytes := make([]byte, headerLen)
		if _, err := buf.Read(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		a.Header = &FrameHeader{}
		if err := a.Header.FromCanonicalBytes(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read requests
	var requestsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if requestsCount > 100 {
		return errors.Wrap(
			errors.New("invalid requests length"),
			"from canonical bytes",
		)
	}
	a.Requests = make([]*MessageBundle, requestsCount)
	for i := uint32(0); i < requestsCount; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if requestLen > 74000 {
			return errors.Wrap(
				errors.New("invalid request size"),
				"from canonical bytes",
			)
		}
		requestBytes := make([]byte, requestLen)
		if _, err := buf.Read(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		a.Requests[i] = &MessageBundle{}
		if err := a.Requests[i].FromCanonicalBytes(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// Multiproof serialization methods
func (m *Multiproof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MultiproofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write multicommitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Multicommitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Multicommitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *Multiproof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MultiproofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read multicommitment
	var commitLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitLen != 74 {
		return errors.Wrap(
			errors.New("invalid multicommitment length"),
			"from canonical bytes",
		)
	}
	m.Multicommitment = make([]byte, commitLen)
	if _, err := buf.Read(m.Multicommitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proofLen != 74 {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"from canonical bytes",
		)
	}
	m.Proof = make([]byte, proofLen)
	if _, err := buf.Read(m.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// Path serialization methods
func (p *Path) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, PathType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write indices count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Indices)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each index
	for _, index := range p.Indices {
		if err := binary.Write(buf, binary.BigEndian, index); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *Path) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PathType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read indices count
	var indicesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &indicesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if indicesCount > 64 {
		return errors.Wrap(
			errors.New("invalid indices count"),
			"from canonical bytes",
		)
	}
	p.Indices = make([]uint64, indicesCount)
	// Read each index
	for i := uint32(0); i < indicesCount; i++ {
		if err := binary.Read(buf, binary.BigEndian, &p.Indices[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// TraversalSubProof serialization methods
func (t *TraversalSubProof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TraversalSubProofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commits count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Commits)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each commit
	for _, commit := range t.Commits {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(commit)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(commit); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write ys count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Ys)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each y
	for _, y := range t.Ys {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(y)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(y); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write paths count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Paths)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each path
	for _, path := range t.Paths {
		pathBytes, err := path.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(pathBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(pathBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TraversalSubProof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TraversalSubProofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read commits count
	var commitsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &commitsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitsCount > 64 {
		return errors.Wrap(
			errors.New("invalid commits length"),
			"from canonical bytes",
		)
	}
	t.Commits = make([][]byte, commitsCount)
	// Read each commit
	for i := uint32(0); i < commitsCount; i++ {
		var commitLen uint32
		if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if commitLen > 74 {
			return errors.Wrap(
				errors.New("invalid commitment length"),
				"from canonical bytes",
			)
		}
		t.Commits[i] = make([]byte, commitLen)
		if _, err := buf.Read(t.Commits[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read ys count
	var ysCount uint32
	if err := binary.Read(buf, binary.BigEndian, &ysCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if ysCount > 64 {
		return errors.Wrap(
			errors.New("invalid multicommitment length"),
			"from canonical bytes",
		)
	}
	t.Ys = make([][]byte, ysCount)
	// Read each y
	for i := uint32(0); i < ysCount; i++ {
		var yLen uint32
		if err := binary.Read(buf, binary.BigEndian, &yLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		// Not a normal length, but we're accounting for unusual scenarios, the
		// parent caller will be more limiting
		if yLen > 2000 {
			return errors.Wrap(
				errors.New("invalid y length"),
				"from canonical bytes",
			)
		}
		t.Ys[i] = make([]byte, yLen)
		if _, err := buf.Read(t.Ys[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read paths count
	var pathsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &pathsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if pathsCount > 64 {
		return errors.Wrap(
			errors.New("invalid paths count"),
			"from canonical bytes",
		)
	}
	t.Paths = make([]*Path, pathsCount)
	// Read each path
	for i := uint32(0); i < pathsCount; i++ {
		var pathLen uint32
		if err := binary.Read(buf, binary.BigEndian, &pathLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if pathLen > 4104 {
			return errors.Wrap(
				errors.New("invalid path length"),
				"from canonical bytes",
			)
		}
		pathBytes := make([]byte, pathLen)
		if _, err := buf.Read(pathBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Paths[i] = &Path{}
		if err := t.Paths[i].FromCanonicalBytes(pathBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// TraversalProof serialization methods
func (t *TraversalProof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TraversalProofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write multiproof
	if t.Multiproof != nil {
		multiproofBytes, err := t.Multiproof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(multiproofBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(multiproofBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write sub_proofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.SubProofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each sub proof
	for _, subProof := range t.SubProofs {
		subProofBytes, err := subProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(subProofBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(subProofBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TraversalProof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TraversalProofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read multiproof
	var multiproofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &multiproofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if multiproofLen > 160 {
		return errors.Wrap(
			errors.New("invalid multiproof length"),
			"from canonical bytes",
		)
	}
	if multiproofLen > 0 {
		multiproofBytes := make([]byte, multiproofLen)
		if _, err := buf.Read(multiproofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Multiproof = &Multiproof{}
		if err := t.Multiproof.FromCanonicalBytes(multiproofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read sub_proofs count
	var subProofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &subProofsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if subProofsCount > 100 {
		return errors.Wrap(
			errors.New("invalid subproofs count"),
			"from canonical bytes",
		)
	}
	t.SubProofs = make([]*TraversalSubProof, subProofsCount)
	// Read each sub proof
	for i := uint32(0); i < subProofsCount; i++ {
		var subProofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &subProofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if subProofLen > 43000 {
			return errors.Wrap(
				errors.New("invalid subproof length"),
				"from canonical bytes",
			)
		}
		subProofBytes := make([]byte, subProofLen)
		if _, err := buf.Read(subProofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.SubProofs[i] = &TraversalSubProof{}
		if err := t.SubProofs[i].FromCanonicalBytes(subProofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// ProverKick serialization methods
func (p *ProverKick) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverKickType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write kicked_prover_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.KickedProverPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.KickedProverPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write conflicting_frame_1
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.ConflictingFrame_1)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.ConflictingFrame_1); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write conflicting_frame_2
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.ConflictingFrame_2)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.ConflictingFrame_2); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write traversal_proof
	if p.TraversalProof != nil {
		traversalBytes, err := p.TraversalProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(traversalBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(traversalBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverKick) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverKickType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read kicked_prover_public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen != 585 {
		return errors.Wrap(
			errors.New("invalid key length"),
			"from canonical bytes",
		)
	}
	p.KickedProverPublicKey = make([]byte, keyLen)
	if _, err := buf.Read(p.KickedProverPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read conflicting_frame_1
	var frame1Len uint32
	if err := binary.Read(buf, binary.BigEndian, &frame1Len); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if frame1Len > 34825 {
		return errors.Wrap(
			errors.New("invalid frame1 length"),
			"from canonical bytes",
		)
	}
	p.ConflictingFrame_1 = make([]byte, frame1Len)
	if _, err := buf.Read(p.ConflictingFrame_1); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read conflicting_frame_2
	var frame2Len uint32
	if err := binary.Read(buf, binary.BigEndian, &frame2Len); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if frame2Len > 34825 {
		return errors.Wrap(
			errors.New("invalid frame1 length"),
			"from canonical bytes",
		)
	}
	p.ConflictingFrame_2 = make([]byte, frame2Len)
	if _, err := buf.Read(p.ConflictingFrame_2); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitmentLen > 74 {
		return errors.Wrap(
			errors.New("invalid commitment length"),
			"from canonical bytes",
		)
	}
	p.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(p.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proofLen > 160 {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"from canonical bytes",
		)
	}
	p.Proof = make([]byte, proofLen)
	if _, err := buf.Read(p.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read traversal_proof
	var traversalLen uint32
	if err := binary.Read(buf, binary.BigEndian, &traversalLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if traversalLen > 4000 {
		return errors.Wrap(
			errors.New("invalid traversal proof length"),
			"from canonical bytes",
		)
	}
	if traversalLen > 0 {
		traversalBytes := make([]byte, traversalLen)
		if _, err := buf.Read(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.TraversalProof = &TraversalProof{}
		if err := p.TraversalProof.FromCanonicalBytes(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (g *GlobalAlert) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, GlobalAlertType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write message
	msgBytes := []byte(g.Message)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(msgBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(msgBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (g *GlobalAlert) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalAlertType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read message
	var msgLen uint32
	if err := binary.Read(buf, binary.BigEndian, &msgLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if msgLen > 1000 {
		return errors.Wrap(
			errors.New("invalid message length"),
			"from canonical bytes",
		)
	}
	msgBytes := make([]byte, msgLen)
	if _, err := buf.Read(msgBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.Message = string(msgBytes)

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 114 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	g.Signature = make([]byte, sigLen)
	if _, err := buf.Read(g.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

var _ SignedMessage = (*LegacyProverRequest)(nil)

// ValidateSignature checks the signature of the announce prover request.
func (t *LegacyProverRequest) ValidateSignature() error {
	payload := []byte{}
	primary := t.PublicKeySignaturesEd448[0]
	for _, p := range t.PublicKeySignaturesEd448[1:] {
		payload = append(payload, p.PublicKey.KeyValue...)
		if err := p.verifyUnsafe(primary.PublicKey.KeyValue, []byte{}); err != nil {
			return errors.Wrap(err, "validate signature")
		}
	}
	if err := primary.verifyUnsafe(payload, []byte{}); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ ValidatableMessage = (*MessageRequest)(nil)

// Validate checks the message request.
func (m *MessageRequest) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil message request"), "validate")
	}
	switch {
	case m.GetJoin() != nil:
		return m.GetJoin().Validate()
	case m.GetLeave() != nil:
		return m.GetLeave().Validate()
	case m.GetPause() != nil:
		return m.GetPause().Validate()
	case m.GetResume() != nil:
		return m.GetResume().Validate()
	case m.GetConfirm() != nil:
		return m.GetConfirm().Validate()
	case m.GetReject() != nil:
		return m.GetReject().Validate()
	case m.GetKick() != nil:
		return m.GetKick().Validate()
	case m.GetUpdate() != nil:
		return m.GetUpdate().Validate()
	case m.GetTokenDeploy() != nil:
		return m.GetTokenDeploy().Validate()
	case m.GetTokenUpdate() != nil:
		return m.GetTokenUpdate().Validate()
	case m.GetTransaction() != nil:
		return m.GetTransaction().Validate()
	case m.GetPendingTransaction() != nil:
		return m.GetPendingTransaction().Validate()
	case m.GetMintTransaction() != nil:
		return m.GetMintTransaction().Validate()
	case m.GetHypergraphDeploy() != nil:
		return m.GetHypergraphDeploy().Validate()
	case m.GetHypergraphUpdate() != nil:
		return m.GetHypergraphUpdate().Validate()
	case m.GetVertexAdd() != nil:
		return m.GetVertexAdd().Validate()
	case m.GetVertexRemove() != nil:
		return m.GetVertexRemove().Validate()
	case m.GetHyperedgeAdd() != nil:
		return m.GetHyperedgeAdd().Validate()
	case m.GetHyperedgeRemove() != nil:
		return m.GetHyperedgeRemove().Validate()
	case m.GetComputeDeploy() != nil:
		return m.GetComputeDeploy().Validate()
	case m.GetComputeUpdate() != nil:
		return m.GetComputeUpdate().Validate()
	case m.GetCodeDeploy() != nil:
		return m.GetCodeDeploy().Validate()
	case m.GetCodeExecute() != nil:
		return m.GetCodeExecute().Validate()
	case m.GetCodeFinalize() != nil:
		return m.GetCodeFinalize().Validate()
	case m.GetShard() != nil:
		return m.GetShard().Validate()

	default:
		return nil
	}
}

var _ ValidatableMessage = (*MessageBundle)(nil)

// Validate checks the message bundle.
func (m *MessageBundle) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil message bundle"), "validate")
	}
	for i, request := range m.Requests {
		if request != nil {
			if err := request.Validate(); err != nil {
				return errors.Wrapf(err, "validate request at index %d", i)
			}
		}
	}
	if m.Timestamp == 0 {
		return errors.Wrap(errors.New("timestamp required"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*LegacyProverRequest)(nil)

// Validate checks the announce prover request.
func (t *LegacyProverRequest) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover request"), "validate")
	}
	if len(t.PublicKeySignaturesEd448) == 0 {
		return errors.Wrap(errors.New("invalid public key signatures"), "validate")
	}
	for _, p := range t.PublicKeySignaturesEd448 {
		if err := p.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "validate")
	}
	return nil
}

var _ ValidatableMessage = (*ProverJoin)(nil)

// Validate checks the announce prover join.
func (t *ProverJoin) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover join"), "validate")
	}
	if len(t.Filters) == 0 {
		return errors.Wrap(errors.New("no filters provided"), "validate")
	}
	if len(t.Filters) > 100 {
		return errors.Wrap(errors.New("too many filters provided"), "validate")
	}
	for _, filter := range t.Filters {
		if len(filter) < 32 || len(filter) > 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	if t.PublicKeySignatureBls48581 != nil {
		if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

var _ ValidatableMessage = (*ProverLeave)(nil)

// Validate checks the announce prover leave.
func (t *ProverLeave) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover leave"), "validate")
	}
	if len(t.Filters) == 0 {
		return errors.Wrap(errors.New("no filters provided"), "validate")
	}
	for _, filter := range t.Filters {
		if len(filter) < 32 || len(filter) > 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*ProverPause)(nil)

// Validate checks the announce prover pause.
func (t *ProverPause) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover pause"), "validate")
	}
	if len(t.Filter) < 32 || len(t.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}

	return nil
}

var _ ValidatableMessage = (*ProverResume)(nil)

// Validate checks the announce prover resume.
func (t *ProverResume) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover resume"), "validate")
	}
	if len(t.Filter) < 32 || len(t.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	return nil
}

// SignableED448Message is a message that can be signed.
type SignableED448Message interface {
	// SignED448 signs the message with the given key, modifying the message.
	// The message contents are expected to be valid - message contents must be
	// validated, or correctly constructed, before signing.
	SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error
}

func newED448Signature(publicKey, signature []byte) *Ed448Signature {
	return &Ed448Signature{
		PublicKey: &Ed448PublicKey{
			KeyValue: publicKey,
		},
		Signature: signature,
	}
}

type ED448SignHelper struct {
	PublicKey []byte
	Sign      func([]byte) ([]byte, error)
}

type BLS48581SignHelper struct {
	PublicKey []byte
	Sign      func([]byte) ([]byte, error)
}

// SignED448 signs the announce prover request with the given keys.
func (t *LegacyProverRequest) SignED448(helpers []ED448SignHelper) error {
	if len(helpers) == 0 {
		return errors.Wrap(errors.New("no keys"), "sign ed448")
	}
	payload := []byte{}
	primary := helpers[0]
	signatures := make([]*Ed448Signature, len(helpers))
	for i, k := range helpers[1:] {
		payload = append(payload, k.PublicKey...)
		signature, err := k.Sign(primary.PublicKey)
		if err != nil {
			return errors.Wrap(err, "sign ed448")
		}
		signatures[i+1] = newED448Signature(k.PublicKey, signature)
	}
	signature, err := primary.Sign(payload)
	if err != nil {
		return errors.Wrap(err, "sign ed448")
	}
	signatures[0] = newED448Signature(primary.PublicKey, signature)
	t.PublicKeySignaturesEd448 = signatures
	return nil
}

var _ ValidatableMessage = (*ProverConfirm)(nil)

// Validate checks the prover confirm.
func (t *ProverConfirm) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover confirm"), "validate")
	}
	if len(t.Filter) < 32 || len(t.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	for _, filter := range t.Filters {
		if len(filter) < 32 || len(filter) > 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*ProverReject)(nil)

// Validate checks the prover reject.
func (t *ProverReject) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover reject"), "validate")
	}
	if len(t.Filter) < 32 || len(t.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	for _, filter := range t.Filters {
		if len(filter) < 32 || len(filter) > 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*ProverUpdate)(nil)

// Validate checks the prover update.
func (p *ProverUpdate) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil prover update"), "validate")
	}
	if len(p.DelegateAddress) == 0 {
		return errors.Wrap(errors.New("delegate address is empty"), "validate")
	}
	if p.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("public key signature is nil"), "validate")
	}
	if err := p.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ ValidatableMessage = (*ProverKick)(nil)

// Validate checks the prover kick.
func (t *ProverKick) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover kick"), "validate")
	}
	if len(t.KickedProverPublicKey) == 0 {
		return errors.Wrap(
			errors.New("kicked prover public key is empty"),
			"validate",
		)
	}
	if len(t.ConflictingFrame_1) == 0 {
		return errors.Wrap(errors.New("conflicting frame 1 is empty"), "validate")
	}
	if len(t.ConflictingFrame_2) == 0 {
		return errors.Wrap(errors.New("conflicting frame 2 is empty"), "validate")
	}
	if len(t.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment is empty"), "validate")
	}
	if len(t.Proof) == 0 {
		return errors.Wrap(errors.New("proof is empty"), "validate")
	}
	// TraversalProof is optional
	if t.TraversalProof != nil {
		if err := t.TraversalProof.Validate(); err != nil {
			return errors.Wrap(err, "traversal proof")
		}
	}
	return nil
}

var _ ValidatableMessage = (*SeniorityMerge)(nil)

// Validate checks the seniority merge.
func (t *SeniorityMerge) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil seniority merge"), "validate")
	}
	if len(t.Signature) != 74 {
		return errors.Wrap(errors.New("invalid signature length"), "validate")
	}
	if len(t.ProverPublicKey) == 0 {
		return errors.Wrap(errors.New("prover public key is empty"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*Multiproof)(nil)

// Validate checks the multiproof.
func (t *Multiproof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil multiproof"), "validate")
	}
	if len(t.Multicommitment) == 0 {
		return errors.Wrap(errors.New("multicommitment is empty"), "validate")
	}
	if len(t.Proof) == 0 {
		return errors.Wrap(errors.New("proof is empty"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*Path)(nil)

// Validate checks the path.
func (t *Path) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil path"), "validate")
	}
	// Path can have empty indices
	return nil
}

var _ ValidatableMessage = (*TraversalSubProof)(nil)

// Validate checks the traversal sub proof.
func (t *TraversalSubProof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil traversal sub proof"), "validate")
	}
	if len(t.Commits) == 0 {
		return errors.Wrap(errors.New("no commits in sub proof"), "validate")
	}
	if len(t.Ys) == 0 {
		return errors.Wrap(errors.New("no ys in sub proof"), "validate")
	}
	if len(t.Paths) == 0 {
		return errors.Wrap(errors.New("no paths in sub proof"), "validate")
	}
	// All arrays should have the same length
	if len(t.Commits) != len(t.Ys) || len(t.Commits) != len(t.Paths) {
		return errors.Wrap(
			errors.New("mismatched array lengths in sub proof"),
			"validate",
		)
	}
	for _, path := range t.Paths {
		if err := path.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*TraversalProof)(nil)

// Validate checks the traversal proof.
func (t *TraversalProof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil traversal proof"), "validate")
	}
	if t.Multiproof == nil {
		return errors.Wrap(errors.New("nil multiproof"), "validate")
	}
	if err := t.Multiproof.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}
	if len(t.SubProofs) == 0 {
		return errors.Wrap(errors.New("no sub proofs"), "validate")
	}
	for _, subProof := range t.SubProofs {
		if err := subProof.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*GlobalFrameHeader)(nil)

func (h *GlobalFrameHeader) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil global frame header"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Timestamp should be reasonable (not 0, not too far in future)
	if h.Timestamp == 0 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Difficulty should be non-zero
	if h.Difficulty == 0 {
		return errors.Wrap(errors.New("invalid difficulty"), "validate")
	}

	// Output should be 516 bytes (258 byte Y + 258 byte proof)
	if len(h.Output) != 516 {
		return errors.Wrap(errors.New("invalid output length"), "validate")
	}

	// Parent selector should be 32 bytes
	if len(h.ParentSelector) != 32 {
		return errors.Wrap(errors.New("invalid parent selector length"), "validate")
	}

	// Global commitments should be exactly 256 entries
	if len(h.GlobalCommitments) != 256 {
		return errors.Wrap(
			errors.New("invalid global commitments count"),
			"validate",
		)
	}

	// Each commitment should be 64 or 74 bytes
	for i, commitment := range h.GlobalCommitments {
		if len(commitment) != 64 && len(commitment) != 74 {
			return errors.Wrapf(
				errors.New("invalid commitment length"),
				"validate: commitment %d",
				i,
			)
		}
	}

	// Prover tree commitment should be 64 or 74 bytes
	if len(h.ProverTreeCommitment) != 64 && len(h.ProverTreeCommitment) != 74 {
		return errors.Wrap(
			errors.New("invalid prover tree commitment length"),
			"validate",
		)
	}

	// Requests root commitment should be 64 or 74 bytes
	if len(h.RequestsRoot) != 64 && len(h.RequestsRoot) != 74 {
		return errors.Wrap(
			errors.New("invalid request root commitment length"),
			"validate",
		)
	}

	// Prover must be set
	if len(h.Prover) != 32 {
		return errors.Wrap(
			errors.New("invalid prover length"),
			"validate",
		)
	}

	// Signature must be present
	if h.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*FrameHeader)(nil)

func (h *FrameHeader) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil frame header"), "validate")
	}

	// Address should be 32 to 64 bytes
	if len(h.Address) < 32 || len(h.Address) > 64 {
		return errors.Wrap(errors.New("invalid address length"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Timestamp should be reasonable (not 0)
	if h.Timestamp == 0 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Difficulty should be non-zero
	if h.Difficulty == 0 {
		return errors.Wrap(errors.New("invalid difficulty"), "validate")
	}

	// Output should be 516 bytes
	if len(h.Output) != 516 {
		return errors.Wrap(errors.New("invalid output length"), "validate")
	}

	// Parent selector should be 32 bytes
	if len(h.ParentSelector) != 32 {
		return errors.Wrap(errors.New("invalid parent selector length"), "validate")
	}

	// Requests root should be 64 or 74 bytes
	if len(h.RequestsRoot) != 64 && len(h.RequestsRoot) != 74 {
		return errors.Wrap(errors.New("invalid requests root length"), "validate")
	}

	// State roots should be exactly 4 entries
	if len(h.StateRoots) != 4 {
		return errors.Wrap(errors.New("invalid state roots count"), "validate")
	}

	// Each state root should be 64 or 74 bytes
	for i, root := range h.StateRoots {
		if len(root) != 64 && len(root) != 74 {
			return errors.Wrapf(
				errors.New("invalid state root length"),
				"validate: state root %d",
				i,
			)
		}
	}

	// Prover should be 32 bytes
	if len(h.Prover) != 32 {
		return errors.Wrap(errors.New("invalid prover length"), "validate")
	}

	// Fee multiplier vote is uint64, any value is valid

	return nil
}

var _ ValidatableMessage = (*ProverLivenessCheck)(nil)

func (p *ProverLivenessCheck) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil prover liveness check"), "validate")
	}

	// Filter should be 64 bytes or fewer
	if len(p.Filter) < 32 || len(p.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter length"), "validate")
	}

	// Commitment hash should be at least 32 bytes
	if len(p.Filter) != 0 && len(p.CommitmentHash) < 32 {
		return errors.Wrap(errors.New("invalid commitment hash length"), "validate")
	}

	// Signature must be present
	if p.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	// Validate the signature payload (not the signature itself)
	if err := p.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

func (p *ProverLivenessCheck) ConstructSignaturePayload() ([]byte, error) {
	clone := proto.Clone(p).(*ProverLivenessCheck)
	clone.PublicKeySignatureBls48581 = nil
	cloneBytes, err := clone.ToCanonicalBytes()
	return cloneBytes, errors.Wrap(err, "construct signature payload")
}

func (p *ProverLivenessCheck) GetSignatureDomain() []byte {
	return slices.Concat([]byte("PROVER_LIVENESS"), p.Filter)
}

var _ ValidatableMessage = (*ProposalVote)(nil)

func (f *ProposalVote) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil frame vote"), "validate")
	}

	// Rank and frame number is uint64, any value is valid

	// Selector should be 32 bytes (proposal) or zero (timeout)
	if len(f.Selector) != 32 && len(f.Selector) != 0 {
		return errors.Wrap(
			errors.Errorf("invalid selector length: %d", len(f.Selector)),
			"validate",
		)
	}

	// Signature must be present
	if f.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	// Validate the signature
	if len(f.Filter) == 0 {
		if err := f.PublicKeySignatureBls48581.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	} else {
		if len(f.PublicKeySignatureBls48581.Address) != 32 {
			return errors.Wrap(errors.New("invalid address"), "validate")
		}
		// handle extended sig
		if len(f.PublicKeySignatureBls48581.Signature) != 74 &&
			len(f.PublicKeySignatureBls48581.Signature) != 590 {
			return errors.Wrap(errors.New("invalid bls48581 signature"), "validate")
		}
	}

	return nil
}

var _ ValidatableMessage = (*AppShardProposal)(nil)

func (f *AppShardProposal) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil proposal"), "validate")
	}

	if f.State == nil {
		return errors.Wrap(
			errors.New("missing state"),
			"validate",
		)
	}

	if err := f.State.Validate(); err != nil {
		return err
	}

	if f.ParentQuorumCertificate == nil {
		return errors.Wrap(
			errors.New("missing parent quorum certificate"),
			"validate",
		)
	}

	if err := f.ParentQuorumCertificate.Validate(); err != nil {
		return err
	}

	if f.PriorRankTimeoutCertificate != nil {
		if err := f.PriorRankTimeoutCertificate.Validate(); err != nil {
			return err
		}
	}

	if f.Vote == nil {
		return errors.Wrap(errors.New("missing vote"), "validate")
	}

	if err := f.Vote.Validate(); err != nil {
		return err
	}

	return nil
}

var _ ValidatableMessage = (*GlobalProposal)(nil)

func (f *GlobalProposal) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil proposal"), "validate")
	}

	if f.State == nil {
		return errors.Wrap(
			errors.New("missing state"),
			"validate",
		)
	}

	if err := f.State.Validate(); err != nil {
		return err
	}

	if f.ParentQuorumCertificate == nil {
		return errors.Wrap(
			errors.New("missing parent quorum certificate"),
			"validate",
		)
	}

	if err := f.ParentQuorumCertificate.Validate(); err != nil {
		return err
	}

	if f.PriorRankTimeoutCertificate != nil {
		if err := f.PriorRankTimeoutCertificate.Validate(); err != nil {
			return err
		}
	}

	if f.Vote == nil {
		return errors.Wrap(errors.New("missing vote"), "validate")
	}

	if err := f.Vote.Validate(); err != nil {
		return err
	}

	return nil
}

var _ ValidatableMessage = (*TimeoutState)(nil)

func (f *TimeoutState) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil timeout state"), "validate")
	}

	if f.LatestQuorumCertificate == nil {
		return errors.Wrap(errors.New("nil latest quorum certificate"), "validate")
	}

	if err := f.LatestQuorumCertificate.Validate(); err != nil {
		return err
	}

	if f.PriorRankTimeoutCertificate != nil {
		if err := f.PriorRankTimeoutCertificate.Validate(); err != nil {
			return err
		}
	}

	if f.Vote == nil {
		return errors.Wrap(errors.New("missing vote"), "validate")
	}

	if err := f.Vote.Validate(); err != nil {
		return err
	}

	return nil
}

var _ ValidatableMessage = (*QuorumCertificate)(nil)

func (f *QuorumCertificate) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil frame confirmation"), "validate")
	}

	// Rank and frame number is uint64, any value is valid

	// Selector should be 32 bytes
	if len(f.Selector) != 32 {
		return errors.Wrap(
			errors.Errorf("invalid selector length: %d", len(f.Selector)),
			"validate",
		)
	}

	// Aggregate signature must be present
	if f.AggregateSignature == nil {
		return errors.Wrap(errors.New("missing aggregate signature"), "validate")
	}

	if len(f.Filter) == 0 {
		return f.AggregateSignature.Validate()
	}

	// Signature should be 74 bytes
	if len(f.AggregateSignature.Signature) < 74 {
		return errors.Wrap(
			errors.Errorf(
				"bls48581 signature must be at least 74 bytes, got %d",
				len(f.AggregateSignature.Signature),
			),
			"validate",
		)
	}

	// Validate public key if present
	if f.AggregateSignature.PublicKey != nil {
		if err := f.AggregateSignature.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	// Bitmask can be variable length, but should not exceed 32
	if len(f.AggregateSignature.Bitmask) > 32 {
		return errors.Wrap(
			errors.New("invalid bitmask length"),
			"validate",
		)
	}

	return nil
}

var _ ValidatableMessage = (*TimeoutCertificate)(nil)

func (f *TimeoutCertificate) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil frame confirmation"), "validate")
	}

	if f.LatestQuorumCertificate != nil {
		if err := f.LatestQuorumCertificate.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	// Aggregate signature must be present
	if f.AggregateSignature == nil {
		return errors.Wrap(errors.New("missing aggregate signature"), "validate")
	}

	return f.AggregateSignature.Validate()
}

var _ ValidatableMessage = (*GlobalFrame)(nil)

func (g *GlobalFrame) Validate() error {
	if g == nil {
		return errors.Wrap(errors.New("nil global frame"), "validate")
	}

	// Header must be present and valid
	if g.Header == nil {
		return errors.Wrap(errors.New("missing header"), "validate")
	}
	if err := g.Header.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	// Validate each request
	for i, request := range g.Requests {
		if request == nil {
			return errors.Wrapf(
				errors.New("nil request"),
				"validate: request %d",
				i,
			)
		}
		if err := request.Validate(); err != nil {
			return errors.Wrapf(err, "validate: request %d", i)
		}
	}

	return nil
}

var _ ValidatableMessage = (*AppShardFrame)(nil)

func (a *AppShardFrame) Validate() error {
	if a == nil {
		return errors.Wrap(errors.New("nil app shard frame"), "validate")
	}

	// Header must be present and valid
	if a.Header == nil {
		return errors.Wrap(errors.New("missing header"), "validate")
	}
	if err := a.Header.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	// Validate each request
	for i, request := range a.Requests {
		if request == nil {
			return errors.Wrapf(
				errors.New("nil request"),
				"validate: request %d",
				i,
			)
		}
		if err := request.Validate(); err != nil {
			return errors.Wrapf(err, "validate: request %d", i)
		}
	}

	return nil
}

var _ ValidatableMessage = (*PeerInfo)(nil)

// Validate checks the PeerInfo message.
func (p *PeerInfo) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil peer info"), "validate")
	}

	// Validate peer_id
	if len(p.PeerId) == 0 {
		return errors.Wrap(errors.New("missing peer id"), "validate")
	}

	// Validate reachability entries
	for _, reach := range p.Reachability {
		if reach == nil {
			return errors.Wrap(errors.New("nil reachability entry"), "validate")
		}

		// Validate filter in reachability
		if len(reach.Filter) > 64 {
			return errors.Wrap(
				errors.New("invalid filter size in reachability"),
				"validate",
			)
		}

		// Validate pubsub multiaddrs
		for _, addr := range reach.PubsubMultiaddrs {
			if addr == "" {
				return errors.Wrap(errors.New("empty pubsub multiaddr"), "validate")
			}
			if _, err := multiaddr.StringCast(addr); err != nil {
				return errors.Wrap(err, "validate pubsub multiaddr")
			}
		}

		// Validate stream multiaddrs
		for _, addr := range reach.StreamMultiaddrs {
			if addr == "" {
				return errors.Wrap(errors.New("empty stream multiaddr"), "validate")
			}
			if _, err := multiaddr.StringCast(addr); err != nil {
				return errors.Wrap(err, "validate stream multiaddr")
			}
		}
	}

	now := time.Now().UnixMilli()

	// Timestamp is int64
	if p.Timestamp < now-5000 || p.Timestamp > now+5000 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Validate version
	if len(p.Version) == 0 {
		return errors.Wrap(errors.New("missing version"), "validate")
	}

	// Validate patch version
	if len(p.PatchNumber) == 0 {
		return errors.Wrap(errors.New("missing patch version"), "validate")
	}

	// Validate capabilities
	if len(p.Capabilities) == 0 {
		return errors.Wrap(errors.New("missing capabilities"), "validate")
	}

	for _, cap := range p.Capabilities {
		if cap == nil {
			return errors.Wrap(errors.New("nil capability"), "validate")
		}

		// Protocol identifier should be non-zero
		if cap.ProtocolIdentifier == 0 {
			return errors.Wrap(errors.New("invalid protocol identifier"), "validate")
		}
	}

	// Validate signature
	if len(p.Signature) != 114 {
		return errors.Wrap(errors.New("invalid signature length"), "validate")
	}

	// Validate public key (Ed448 public key should be 57 bytes)
	if len(p.PublicKey) != 57 {
		return errors.Wrap(errors.New("invalid public key length"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*GlobalAlert)(nil)

// Validate checks the GlobalAlert message.
func (g *GlobalAlert) Validate() error {
	if g == nil {
		return errors.Wrap(errors.New("nil global alert"), "validate")
	}

	// Validate message content
	if g.Message == "" {
		return errors.Wrap(errors.New("empty alert message"), "validate")
	}

	// Validate signature
	if len(g.Signature) != 114 {
		return errors.Wrap(errors.New("invalid signature"), "validate")
	}

	return nil
}

// ProverSeniorityMerge serialization methods

func (p *ProverSeniorityMerge) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverSeniorityMergeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write merge_targets count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.MergeTargets)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each merge target
	for _, mt := range p.MergeTargets {
		mtBytes, err := mt.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(mtBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(mtBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverSeniorityMerge) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverSeniorityMergeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 118 {
		return errors.Wrap(
			errors.New("invalid signature length"),
			"from canonical bytes",
		)
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read merge_targets count
	var mtCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mtCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if mtCount > 100 {
		return errors.Wrap(
			errors.New("too many merge targets"),
			"from canonical bytes",
		)
	}

	// Read each merge target
	p.MergeTargets = make([]*SeniorityMerge, mtCount)
	for i := uint32(0); i < mtCount; i++ {
		var mtLen uint32
		if err := binary.Read(buf, binary.BigEndian, &mtLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if mtLen > 1000 {
			return errors.Wrap(
				errors.New("invalid merge target length"),
				"from canonical bytes",
			)
		}
		mtBytes := make([]byte, mtLen)
		if _, err := buf.Read(mtBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.MergeTargets[i] = &SeniorityMerge{}
		if err := p.MergeTargets[i].FromCanonicalBytes(mtBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}
