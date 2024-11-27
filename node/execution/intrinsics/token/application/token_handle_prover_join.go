package application

import (
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return altAddr.FillBytes(make([]byte, 32)), nil
}

func (a *TokenApplication) handleDataAnnounceProverJoin(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverJoin,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	if currentFrameNumber < PROOF_FRAME_CUTOFF {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	if _, touched := lockMap[string(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	)]; touched {
		a.Logger.Debug("already attempted join")

		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	address, err := a.getAddressFromSignature(t.PublicKeySignatureEd448)
	if err != nil {
		a.Logger.Debug("can't get address from signature")
		return nil, errors.Wrap(err, "handle join")
	}

	if t.FrameNumber > currentFrameNumber {
		a.Logger.Debug(
			"bad payload",
			zap.Uint64("given_frame_number", t.FrameNumber),
			zap.Uint64("current_frame_number", currentFrameNumber),
			zap.Int("filter_length", len(t.Filter)),
		)

		pk, err := pcrypto.UnmarshalEd448PublicKey(
			t.PublicKeySignatureEd448.PublicKey.KeyValue,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get address from signature")
		}

		peerId, err := peer.IDFromPublicKey(pk)
		if err != nil {
			return nil, errors.Wrap(err, "get address from signature")
		}

		a.PubSub.AddPeerScore([]byte(peerId), -100000)
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	outputs := []*protobufs.TokenOutput{}
	if t.Announce != nil {
		outputs, err = a.handleAnnounce(currentFrameNumber, lockMap, t.Announce)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
		}
	}

	lockMap[string(t.PublicKeySignatureEd448.PublicKey.KeyValue)] = struct{}{}
	for _, t := range a.Tries {
		if t.Contains(address) {
			return nil, errors.Wrap(errors.New("in prover trie"), "handle join")
		}
	}

	outputs = append(
		outputs,
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Join{
				Join: t,
			},
		},
	)

	return outputs, nil
}
