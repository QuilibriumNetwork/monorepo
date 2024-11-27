package application

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleDataAnnounceProverPause(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverPause,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	if currentFrameNumber < PROOF_FRAME_CUTOFF {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	if t.FrameNumber > currentFrameNumber {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}
	if _, touched := lockMap[string(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	)]; touched {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	address, err := a.getAddressFromSignature(t.PublicKeySignatureEd448)
	if err != nil {
		return nil, errors.Wrap(err, "handle pause")
	}

	inTries := false
	for _, t := range a.Tries {
		inTries = inTries || t.Contains(address)
	}

	lockMap[string(t.PublicKeySignatureEd448.PublicKey.KeyValue)] = struct{}{}
	if !inTries {
		return nil, errors.Wrap(errors.New("in prover trie"), "handle pause")
	}
	return []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Pause{
				Pause: t,
			},
		},
	}, nil
}
