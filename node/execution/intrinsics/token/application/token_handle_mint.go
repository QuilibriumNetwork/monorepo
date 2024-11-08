package application

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type sortProofsByFrame struct {
	frameNumbers []uint64
	proofs       []*protobufs.PreCoinProof
}

var _ sort.Interface = (*sortProofsByFrame)(nil)

// Len implements sort.Interface.
func (s sortProofsByFrame) Len() int {
	return len(s.proofs)
}

// Less implements sort.Interface.
func (s sortProofsByFrame) Less(i, j int) bool {
	return s.frameNumbers[i] < s.frameNumbers[j]
}

// Swap implements sort.Interface.
func (s sortProofsByFrame) Swap(i, j int) {
	s.frameNumbers[i], s.frameNumbers[j] = s.frameNumbers[j], s.frameNumbers[i]
	s.proofs[i], s.proofs[j] = s.proofs[j], s.proofs[i]
}

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MintCoinRequest,
	frame *protobufs.ClockFrame,
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
	} else if len(t.Proofs) > 0 && currentFrameNumber > 0 {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		if _, touched := lockMap[string(t.Signature.PublicKey.KeyValue)]; touched {
			a.Logger.Debug(
				"already received",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}
		ring := -1
		proverSet := int64((len(a.Tries) - 1) * 1024)
		for i, t := range a.Tries[1:] {
			if t.Contains(altAddr.FillBytes(make([]byte, 32))) {
				ring = i
			}
		}
		if ring == -1 {
			a.Logger.Debug(
				"not in ring",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		prfsFrames, prfs, err := a.CoinStore.GetPreCoinProofsForOwner(
			altAddr.FillBytes(make([]byte, 32)),
		)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		sort.Sort(sortProofsByFrame{
			frameNumbers: prfsFrames,
			proofs:       prfs,
		})

		var delete *protobufs.PreCoinProof
		var commitment []byte
		var previousFrame *protobufs.ClockFrame
		for _, pr := range prfs {
			if len(pr.Proof) >= 3 && len(pr.Commitment) == 40 {
				delete = pr
				commitment = pr.Commitment[:32]
				previousFrameNumber := binary.BigEndian.Uint64(pr.Commitment[32:])
				previousFrame, _, err = a.ClockStore.GetDataClockFrame(
					frame.Filter,
					previousFrameNumber,
					true,
				)

				if err != nil {
					a.Logger.Debug(
						"invalid frame",
						zap.Error(err),
						zap.String("peer_id", base58.Encode([]byte(peerId))),
						zap.Uint64("frame_number", currentFrameNumber),
					)
					lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
					return []*protobufs.TokenOutput{&protobufs.TokenOutput{
						Output: &protobufs.TokenOutput_Penalty{
							Penalty: &protobufs.ProverPenalty{
								Quantity: 10,
								Account: &protobufs.AccountRef{
									Account: &protobufs.AccountRef_ImplicitAccount{
										ImplicitAccount: &protobufs.ImplicitAccount{
											ImplicitType: 0,
											Address:      altAddr.FillBytes(make([]byte, 32)),
										},
									},
								},
							},
						},
					}}, nil
				}
			}
		}

		newCommitment, parallelism, newFrameNumber, verified, err :=
			tries.UnpackAndVerifyOutput(commitment, t.Proofs)
		if err != nil {
			a.Logger.Debug(
				"mint error",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
			return []*protobufs.TokenOutput{&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Penalty{
					Penalty: &protobufs.ProverPenalty{
						Quantity: 10,
						Account: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      altAddr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			}}, nil
		}

		if !verified {
			a.Logger.Debug(
				"tree verification failed",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
		}

		if (previousFrame != nil && newFrameNumber <= previousFrame.FrameNumber) ||
			newFrameNumber < currentFrameNumber-10 {
			previousFrameNumber := uint64(0)
			if previousFrame != nil {
				previousFrameNumber = previousFrame.FrameNumber
			}
			a.Logger.Debug(
				"received out of order proofs, ignoring",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("previous_frame", previousFrameNumber),
				zap.Uint64("new_frame", newFrameNumber),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		if verified && delete != nil && len(t.Proofs) > 3 {
			newFrame, _, err := a.ClockStore.GetDataClockFrame(
				frame.Filter,
				newFrameNumber,
				true,
			)
			if err != nil {
				a.Logger.Debug(
					"invalid frame",
					zap.Error(err),
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
				return []*protobufs.TokenOutput{&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Penalty{
						Penalty: &protobufs.ProverPenalty{
							Quantity: 10,
							Account: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				}}, nil
			}
			hash := sha3.Sum256(newFrame.Output)
			pick := tries.BytesToUnbiasedMod(hash, uint64(parallelism))
			challenge := []byte{}
			challenge = append(challenge, peerId...)
			challenge = binary.BigEndian.AppendUint64(
				challenge,
				previousFrame.FrameNumber,
			)
			individualChallenge := append([]byte{}, challenge...)
			individualChallenge = binary.BigEndian.AppendUint32(
				individualChallenge,
				uint32(pick),
			)
			leaf := t.Proofs[len(t.Proofs)-1]
			individualChallenge = append(individualChallenge, previousFrame.Output...)
			if len(leaf) != 516 {
				a.Logger.Debug(
					"invalid size",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
					zap.Int("proof_size", len(leaf)),
				)
				lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
				return []*protobufs.TokenOutput{&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Penalty{
						Penalty: &protobufs.ProverPenalty{
							Quantity: 10,
							Account: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				}}, nil
			}

			wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)
			if bytes.Equal(leaf, bytes.Repeat([]byte{0x00}, 516)) ||
				!wesoProver.VerifyChallengeProof(
					individualChallenge,
					frame.Difficulty,
					leaf,
				) {
				a.Logger.Debug(
					"invalid proof",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				// we want this to still apply the next commit even if this proof failed
				verified = false
			}
		}

		outputs := []*protobufs.TokenOutput{}

		if delete != nil {
			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_DeletedProof{
						DeletedProof: delete,
					},
				},
			)
		}
		if verified && delete != nil && len(t.Proofs) > 3 {
			ringFactor := big.NewInt(2)
			ringFactor.Exp(ringFactor, big.NewInt(int64(ring)), nil)

			// const for testnet
			storage := big.NewInt(int64(256 * parallelism))
			unitFactor := big.NewInt(8000000000)
			storage.Mul(storage, unitFactor)
			storage.Quo(storage, big.NewInt(proverSet))
			storage.Quo(storage, ringFactor)

			a.Logger.Debug(
				"issued reward",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
				zap.String("reward", storage.String()),
			)

			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Commitment: binary.BigEndian.AppendUint64(
								append([]byte{}, newCommitment...),
								newFrameNumber,
							),
							Amount:     storage.FillBytes(make([]byte, 32)),
							Proof:      payload,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddr.FillBytes(make([]byte, 32)),
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
										Address:      altAddr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
			)
		} else {
			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Commitment: binary.BigEndian.AppendUint64(
								append([]byte{}, newCommitment...),
								newFrameNumber,
							),
							Proof:      payload,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
			)
			if !verified {
				outputs = append(outputs, &protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Penalty{
						Penalty: &protobufs.ProverPenalty{
							Quantity: 10,
							Account: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				})
			}
		}
		lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
		return outputs, nil
	}
	a.Logger.Debug(
		"could not find case for proof",
		zap.String("peer_id", base58.Encode([]byte(peerId))),
		zap.Uint64("frame_number", currentFrameNumber),
	)
	return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
}
