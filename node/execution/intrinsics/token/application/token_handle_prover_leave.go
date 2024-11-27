package application

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleDataAnnounceProverLeave(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverLeave,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	if currentFrameNumber < PROOF_FRAME_CUTOFF {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle leave")
	}

	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle leave")
	}

	if t.FrameNumber > currentFrameNumber {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle leave")
	}

	if _, touched := lockMap[string(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	)]; touched {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle leave")
	}

	address, err := a.getAddressFromSignature(t.PublicKeySignatureEd448)
	if err != nil {
		return nil, errors.Wrap(err, "handle leave")
	}

	inTries := false
	for _, t := range a.Tries {
		inTries = inTries || t.Contains(address)
	}

	lockMap[string(t.PublicKeySignatureEd448.PublicKey.KeyValue)] = struct{}{}
	if !inTries {
		return nil, errors.Wrap(errors.New("in prover trie"), "handle leave")
	}

	return []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Leave{
				Leave: t,
			},
		},
	}, nil
}
