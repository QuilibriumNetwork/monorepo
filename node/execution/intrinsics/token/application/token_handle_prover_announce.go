package application

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleAnnounce(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverRequest,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
	}

	for _, p := range t.PublicKeySignaturesEd448 {
		if _, touched := lockMap[string(p.PublicKey.KeyValue)]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
		}
	}

	for _, p := range t.PublicKeySignaturesEd448[1:] {
		lockMap[string(p.PublicKey.KeyValue)] = struct{}{}
	}

	outputs := []*protobufs.TokenOutput{}
	if currentFrameNumber >= PROOF_FRAME_CUTOFF {
		outputs = append(outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Announce{
				Announce: t,
			},
		})
	}

	return outputs, nil
}
