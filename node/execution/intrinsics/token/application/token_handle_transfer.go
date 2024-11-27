package application

import (
	"bytes"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleTransfer(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.TransferCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	if _, touched := lockMap[string(t.OfCoin.Address)]; touched {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	coin, err := a.CoinStore.GetCoinByAddress(nil, t.OfCoin.Address)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	addr, err := poseidon.HashBytes(t.Signature.PublicKey.KeyValue)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	if !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		addr.FillBytes(make([]byte, 32)),
	) && !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		altAddr.FillBytes(make([]byte, 32)),
	) {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle transfer")
	}

	newIntersection := coin.Intersection
	for i, b := range p2p.GetBloomFilter(
		addr.FillBytes(make([]byte, 32)),
		1024,
		3,
	) {
		newIntersection[i] |= b
	}

	outputs := []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount:       coin.Amount,
					Intersection: newIntersection,
					Owner:        t.ToAccount,
				},
			},
		},
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: t.OfCoin,
			},
		},
	}

	lockMap[string(t.OfCoin.Address)] = struct{}{}
	return outputs, nil
}
