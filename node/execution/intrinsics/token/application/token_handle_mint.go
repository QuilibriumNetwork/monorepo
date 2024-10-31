package application

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MintCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	if t == nil || t.Proofs == nil || t.Signature == nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	if err := t.Signature.Verify(payload); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	addr, err := poseidon.HashBytes(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	// todo: set termination frame for this:
	if len(t.Proofs) == 1 && a.Tries[0].Contains(
		addr.FillBytes(make([]byte, 32)),
	) && bytes.Equal(t.Signature.PublicKey.KeyValue, a.Beacon) {
		if len(t.Proofs[0]) != 64 {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		if _, touched := lockMap[string(t.Proofs[0][32:])]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		_, pr, err := a.CoinStore.GetPreCoinProofsForOwner(t.Proofs[0][32:])
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		for _, p := range pr {
			if p.IndexProof == nil && bytes.Equal(p.Amount, t.Proofs[0][:32]) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}
		}

		lockMap[string(t.Proofs[0][32:])] = struct{}{}

		outputs := []*protobufs.TokenOutput{
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Proof{
					Proof: &protobufs.PreCoinProof{
						Amount: t.Proofs[0][:32],
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
						Proof: t.Signature.Signature,
					},
				},
			},
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount:       t.Proofs[0][:32],
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
					},
				},
			},
		}
		return outputs, nil
	} else if len(t.Proofs) != 3 && currentFrameNumber > 77000 {
		if _, touched := lockMap[string(t.Signature.PublicKey.KeyValue)]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}
		ring := -1
		addrBytes := addr.FillBytes(make([]byte, 32))
		for i, t := range a.Tries {
			n := t.FindNearest(addrBytes)
			if n != nil && bytes.Equal(n.External.Key, addrBytes) {
				ring = i
			}
		}
		if ring == -1 {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}
		outputs := []*protobufs.TokenOutput{}
		for _, p := range t.Proofs {
			if len(p) < 516+len(peerId)+8+32 {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			if !bytes.Equal(p[516:len(peerId)], []byte(peerId)) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)

			frameNumber := binary.BigEndian.Uint64(
				p[516+len(peerId) : 516+len(peerId)+8],
			)
			if frameNumber > currentFrameNumber {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			frames, proofs, err := a.CoinStore.GetPreCoinProofsForOwner(
				altAddr.FillBytes(make([]byte, 32)),
			)
			if err == nil {
				none := true
				for _, f := range frames {
					if f == frameNumber {
						none = false
						break
					}
				}

				if !none {
					for _, pr := range proofs {
						if bytes.Equal(pr.Proof, p) {
							return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
						}
					}
				}
			}

			if !wesoProver.VerifyChallengeProof(p[516:], a.Difficulty, p[:516]) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			scale := len(p2p.GetOnesIndices(p[516+len(peerId)+8 : 32]))
			if scale == 0 {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			ringFactor := big.NewInt(2)
			ringFactor.Exp(ringFactor, big.NewInt(int64(ring)), nil)
			storage := big.NewInt(int64(1024 / (256 / scale)))
			unitFactor := big.NewInt(8000000000)
			storage.Mul(storage, unitFactor)
			storage.Quo(storage, ringFactor)

			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Amount:     storage.FillBytes(make([]byte, 32)),
							Proof:      p,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      addr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Coin{
						Coin: &protobufs.Coin{
							Amount:       storage.FillBytes(make([]byte, 32)),
							Intersection: make([]byte, 1024),
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      addr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
			)
		}
		lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
		return outputs, nil
	}

	return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
}
