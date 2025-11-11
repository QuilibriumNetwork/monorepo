package verification

import (
	"context"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// Signer creates votes for the collector clusters consensus. When a
// participant votes for a state, it _always_ provide the proving signature
// as part of their vote. Signer is responsible for creating correctly
// signed proposals and votes.
type Signer[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT]
}

var _ consensus.Signer[*nilUnique, *nilUnique] = (*Signer[*nilUnique, *nilUnique, *nilUnique])(nil)

// NewSigner instantiates a Signer, which signs votes and
// proposals with the proving key. The generated signatures are aggregatable.
func NewSigner[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	voter consensus.VotingProvider[StateT, VoteT, PeerIDT],
) *Signer[StateT, VoteT, PeerIDT] {

	sc := &Signer[StateT, VoteT, PeerIDT]{
		voter: voter,
	}
	return sc
}

// CreateVote will create a vote with a proving signature for the given state.
func (c *Signer[StateT, VoteT, PeerIDT]) CreateVote(
	state *models.State[StateT],
) (*VoteT, error) {

	// create the signature data
	vote, err := c.voter.SignVote(context.TODO(), state)
	if err != nil {
		return nil, fmt.Errorf("could not create signature: %w", err)
	}

	return vote, nil
}

// CreateTimeout will create a signed timeout state for the given rank.
func (c *Signer[StateT, VoteT, PeerIDT]) CreateTimeout(
	curRank uint64,
	newestQC models.QuorumCertificate,
	previousRankTimeoutCert models.TimeoutCertificate,
) (*models.TimeoutState[VoteT], error) {
	// create timeout state specific message
	vote, err := c.voter.SignTimeoutVote(
		context.TODO(),
		newestQC.GetFilter(),
		curRank,
		newestQC.GetRank(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not generate signature for timeout state at rank %d: %w",
			curRank,
			err,
		)
	}

	timeout := &models.TimeoutState[VoteT]{
		Rank:                        curRank,
		LatestQuorumCertificate:     newestQC,
		PriorRankTimeoutCertificate: previousRankTimeoutCert,
		Vote:                        vote,
		TimeoutTick:                 0,
	}

	return timeout, nil
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
