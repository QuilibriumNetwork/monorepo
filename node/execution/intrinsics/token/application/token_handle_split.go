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

func (a *TokenApplication) handleSplit(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.SplitCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	newCoins := []*protobufs.Coin{}
	newAmounts := []*big.Int{}

	coin, err := a.CoinStore.GetCoinByAddress(nil, t.OfCoin.Address)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	if _, touched := lockMap[string(t.OfCoin.Address)]; touched {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	addr, err := poseidon.HashBytes(t.Signature.PublicKey.KeyValue)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	if !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		addr.FillBytes(make([]byte, 32)),
	) && !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		altAddr.FillBytes(make([]byte, 32)),
	) {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	original := new(big.Int).SetBytes(coin.Amount)
	amounts := t.Amounts
	total := new(big.Int)
	for _, amount := range amounts {
		amountBI := new(big.Int).SetBytes(amount)
		if amountBI.Cmp(original) >= 0 {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
		}

		newAmounts = append(newAmounts, amountBI)
		total.Add(total, amountBI)
		newCoins = append(newCoins, &protobufs.Coin{
			Amount:       amountBI.FillBytes(make([]byte, 32)),
			Owner:        coin.Owner,
			Intersection: coin.Intersection,
		})
	}
	if original.Cmp(total) != 0 {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle split")
	}

	outputs := []*protobufs.TokenOutput{}
	for _, c := range newCoins {
		outputs = append(outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: c,
			},
		})
	}

	outputs = append(
		outputs,
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: t.OfCoin,
			},
		},
	)

	lockMap[string(t.OfCoin.Address)] = struct{}{}

	return outputs, nil
}
