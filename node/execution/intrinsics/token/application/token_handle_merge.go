package application

import (
	"bytes"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleMerge(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MergeCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
	}

	newCoin := &protobufs.Coin{}
	newTotal := new(big.Int)
	newIntersection := make([]byte, 1024)

	addresses := [][]byte{}
	for _, c := range t.Coins {
		if _, touched := lockMap[string(c.Address)]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
		}

		for _, addr := range addresses {
			if bytes.Equal(addr, c.Address) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
			}
		}

		addresses = append(addresses, c.Address)
	}

	addr, err := poseidon.HashBytes(t.Signature.PublicKey.KeyValue)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
	}
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
	}

	owner := &protobufs.AccountRef{}
	deleted := []*protobufs.TokenOutput{}
	for _, c := range t.Coins {
		coin, err := a.CoinStore.GetCoinByAddress(nil, c.Address)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
		}

		if !bytes.Equal(
			coin.Owner.GetImplicitAccount().Address,
			addr.FillBytes(make([]byte, 32)),
		) && !bytes.Equal(
			coin.Owner.GetImplicitAccount().Address,
			altAddr.FillBytes(make([]byte, 32)),
		) {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle merge")
		}

		newTotal.Add(newTotal, new(big.Int).SetBytes(coin.Amount))
		for i := range coin.Intersection {
			newIntersection[i] |= coin.Intersection[i]
		}
		owner = coin.Owner
		deleted = append(deleted, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: c,
			},
		})
	}
	newCoin.Amount = newTotal.FillBytes(make([]byte, 32))
	newCoin.Intersection = newIntersection
	newCoin.Owner = owner
	outputs := []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: newCoin,
			},
		},
	}
	outputs = append(outputs, deleted...)

	for _, c := range t.Coins {
		lockMap[string(c.Address)] = struct{}{}
	}

	return outputs, nil
}
