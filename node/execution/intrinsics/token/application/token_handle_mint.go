package application

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sync/atomic"

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

// for tests, these need to be var
const PROOF_FRAME_CUTOFF = 1
const PROOF_FRAME_RING_RESET = 5750
const PROOF_FRAME_RING_RESET_2 = 7650
const PROOF_FRAME_RING_RESET_3 = 13369
const PROOF_FRAME_SENIORITY_REPAIR = 25745

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	t *protobufs.MintCoinRequest,
	frame *protobufs.ClockFrame,
	parallelismMap map[int]uint64,
) ([]*protobufs.TokenOutput, error) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
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

		_, pr, err := a.CoinStore.GetPreCoinProofsForOwner(t.Proofs[0][32:])
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		for _, p := range pr {
			if p.IndexProof == nil && bytes.Equal(p.Amount, t.Proofs[0][:32]) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}
		}

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
	} else if len(t.Proofs) > 0 && currentFrameNumber > PROOF_FRAME_CUTOFF {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		ring := -1
		for i, t := range a.Tries[1:] {
			if t.Contains(altAddr.FillBytes(make([]byte, 32))) {
				ring = i
			}
		}

		_, prfs, err := a.CoinStore.GetPreCoinProofsForOwner(
			altAddr.FillBytes(make([]byte, 32)),
		)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

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
			atomic.AddUint64(&a.MintTreeVerificationFailure, 1)
			a.Logger.Debug(
				"tree verification failed",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
		}

		// Current frame - 2 is because the current frame is the newly created frame,
		// and the provers are submitting proofs on the frame preceding the one they
		// last saw. This enforces liveness and creates a punishment for being
		// late.
		if (previousFrame != nil && newFrameNumber <= previousFrame.FrameNumber) ||
			newFrameNumber < currentFrameNumber-2 {
			previousFrameNumber := uint64(0)
			if previousFrame != nil {
				previousFrameNumber = previousFrame.FrameNumber
			}
			if newFrameNumber < currentFrameNumber-2 {
				atomic.AddUint64(&a.MintTooOld, 1)
			} else {
				atomic.AddUint64(&a.MintOutOfOrder, 1)
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

		wesoVerified := true
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
				wesoVerified = false
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
		if verified && delete != nil && len(t.Proofs) > 3 && wesoVerified {
			storage := PomwBasis(1, ring, currentFrameNumber)
			m := parallelismMap[ring]
			if m == 0 {
				m = 1
			}
			storage.Quo(storage, big.NewInt(int64(m)))
			storage.Mul(storage, big.NewInt(int64(parallelism)))

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
			if !wesoVerified ||
				(currentFrameNumber < PROOF_FRAME_RING_RESET && !verified) {
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
		return outputs, nil
	}
	a.Logger.Debug(
		"could not find case for proof",
		zap.String("peer_id", base58.Encode([]byte(peerId))),
		zap.Uint64("frame_number", currentFrameNumber),
	)
	return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
}

func PomwBasis(generation uint64, ring int, currentFrameNumber uint64) *big.Int {
	prec := uint(53)

	one := new(big.Float).SetPrec(prec).SetInt64(1)
	divisor := new(big.Float).SetPrec(prec).SetInt64(1048576)

	normalized := new(big.Float).SetPrec(prec)
	// A simple hack for estimating state growth in terms of frames, based on
	// linear relationship of state growth:
	normalized.SetInt64(int64((737280 + currentFrameNumber) / 184320))
	normalized.Quo(normalized, divisor)

	// 1/2^n
	exp := new(big.Float).SetPrec(prec).SetInt64(1)
	if generation > 0 {
		powerOfTwo := new(big.Float).SetPrec(prec).SetInt64(2)
		powerOfTwo.SetInt64(1)
		for i := uint64(0); i < generation; i++ {
			powerOfTwo.Mul(powerOfTwo, big.NewFloat(2))
		}
		exp.Quo(one, powerOfTwo)
	}

	// (d/1048576)^(1/2^n)
	result := new(big.Float).Copy(normalized)
	if generation > 0 {
		for i := uint64(0); i < generation; i++ {
			result.Sqrt(result)
		}
	}

	// Calculate 1/result
	result.Quo(one, result)

	// Divide by 2^s
	if ring > 0 {
		divisor := new(big.Float).SetPrec(prec).SetInt64(1)
		for i := 0; i < ring; i++ {
			divisor.Mul(divisor, big.NewFloat(2))
		}
		result.Quo(result, divisor)
	}

	result.Mul(result, new(big.Float).SetPrec(prec).SetInt64(8000000000))

	out, _ := result.Int(new(big.Int))
	return out
}
