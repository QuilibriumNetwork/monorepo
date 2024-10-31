package data

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var ErrNoNewFrames = errors.New("peer reported no frames")

func (e *DataClockConsensusEngine) GetDataFrame(
	ctx context.Context,
	request *protobufs.GetDataFrameRequest,
) (*protobufs.DataFrameResponse, error) {
	e.logger.Debug(
		"received frame request",
		zap.Uint64("frame_number", request.FrameNumber),
	)
	var frame *protobufs.ClockFrame
	var err error
	if request.FrameNumber == 0 {
		frame, err = e.dataTimeReel.Head()
		if frame.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get data frame",
			)
		}
	} else {
		frame, _, err = e.clockStore.GetDataClockFrame(
			e.filter,
			request.FrameNumber,
			false,
		)
	}

	if err != nil {
		e.logger.Error(
			"received error while fetching time reel head",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get data frame")
	}

	return &protobufs.DataFrameResponse{
		ClockFrame: frame,
	}, nil
}

func (e *DataClockConsensusEngine) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return nil
}

// Deprecated: Use NegotiateCompressedSyncFrames.
// GetCompressedSyncFrames implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	e.logger.Debug(
		"received clock frame request",
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
	)

	if err := server.SendMsg(
		&protobufs.ClockFramesResponse{
			Filter:          request.Filter,
			FromFrameNumber: 0,
			ToFrameNumber:   0,
			ClockFrames:     []*protobufs.ClockFrame{},
		},
	); err != nil {
		return errors.Wrap(err, "get compressed sync frames")
	}

	return nil
}

func (e *DataClockConsensusEngine) HandlePreMidnightMint(
	ctx context.Context,
	t *protobufs.MintCoinRequest,
) (*protobufs.PreMidnightMintResponse, error) {
	addr, err := e.handleMint(t)
	if err != nil {
		e.logger.Error("error while handling pre-midnight mint", zap.Error(err))
		return nil, err
	}

	return &protobufs.PreMidnightMintResponse{Address: addr}, nil
}

func (e *DataClockConsensusEngine) GetPreMidnightMintStatus(
	ctx context.Context,
	t *protobufs.PreMidnightMintStatusRequest,
) (*protobufs.PreMidnightMintResponse, error) {
	if !e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
		return nil, errors.Wrap(
			errors.New("wrong destination"),
			"get pre midnight mint status",
		)
	}

	if len(t.Owner) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid data"),
			"get pre midnight mint status",
		)
	}
	fr, pre, err := e.coinStore.GetPreCoinProofsForOwner(t.Owner)
	if err != nil {
		return nil, errors.Wrap(
			errors.New("invalid data"),
			"get pre midnight mint status",
		)
	}

	if len(fr) == 0 {
		return &protobufs.PreMidnightMintResponse{
			Address:   make([]byte, 32),
			Increment: 0,
		}, nil
	} else {
		for _, pr := range pre {
			addr, err := GetAddressOfPreCoinProof(pr)
			if err != nil {
				if err != nil {
					return nil, errors.Wrap(
						errors.New("invalid data"),
						"get pre midnight mint status",
					)
				}
			}

			return &protobufs.PreMidnightMintResponse{
				Address:   addr,
				Increment: pr.Difficulty,
			}, nil
		}
	}

	return &protobufs.PreMidnightMintResponse{
		Address:   make([]byte, 32),
		Increment: 0,
	}, nil
}

func (e *DataClockConsensusEngine) handleMint(
	t *protobufs.MintCoinRequest,
) ([]byte, error) {
	if !e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
		return nil, errors.Wrap(errors.New("wrong destination"), "handle mint")
	}

	returnAddr := []byte{}
	e.preMidnightMintMx.Lock()
	if _, active := e.preMidnightMint[string(
		t.Signature.PublicKey.KeyValue,
	)]; active {
		return nil, errors.Wrap(errors.New("busy"), "handle mint")
	}
	e.preMidnightMint[string(
		t.Signature.PublicKey.KeyValue,
	)] = struct{}{}
	e.preMidnightMintMx.Unlock()

	defer func() {
		e.preMidnightMintMx.Lock()
		delete(e.preMidnightMint, string(
			t.Signature.PublicKey.KeyValue,
		))
		e.preMidnightMintMx.Unlock()
	}()

	head, err := e.dataTimeReel.Head()
	if err != nil {
		return nil, errors.Wrap(errors.New("busy"), "handle mint")
	}

	if t == nil || t.Proofs == nil {
		return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	if err := t.Signature.Verify(payload); err != nil {
		return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
	}
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
	}

	e.logger.Debug(
		"got pre-midnight mint request",
		zap.String("peer", peerId.String()),
	)

	if len(t.Proofs) >= 3 &&
		len(t.Proofs) < 204 &&
		bytes.Equal(
			t.Proofs[0],
			[]byte("pre-dusk"),
		) && (!bytes.Equal(t.Proofs[1], make([]byte, 32)) ||
		head.FrameNumber < 67000) && e.GetFrameProverTries()[0].Contains(
		e.provingKeyAddress,
	) {
		prevInput := []byte{}
		prevErrorMetric := uint32(0)
		highestIncrement := uint32(0)
		deletes := []*protobufs.TokenOutput{}
		if !bytes.Equal(t.Proofs[1], make([]byte, 32)) {
			pre, err := e.coinStore.GetPreCoinProofByAddress(t.Proofs[1])
			if err != nil {
				return nil, errors.Wrap(
					application.ErrInvalidStateTransition,
					"handle mint",
				)
			}
			if !bytes.Equal(
				pre.Owner.GetImplicitAccount().Address,
				altAddr.FillBytes(make([]byte, 32)),
			) {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}
			if pre.Difficulty == 0 {
				_, pr, err := e.coinStore.GetPreCoinProofsForOwner(
					altAddr.FillBytes(make([]byte, 32)),
				)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
				}

				for _, p := range pr {
					if p.IndexProof != nil {
						continue
					}
					if bytes.Equal(p.Amount, pre.Amount) {
						return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
					}
				}
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			} else {
				deletes = append(deletes, &protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_DeletedProof{
						DeletedProof: pre,
					},
				})
			}
			prevInput = pre.Proof[74:148]
			prevErrorMetric = binary.BigEndian.Uint32(pre.Proof[148:152])
			highestIncrement = binary.BigEndian.Uint32(pre.Proof[152:156])
		}

		var previousIncrement = uint32(0xFFFFFFFF)
		reward := new(big.Int)
		var index uint32
		var indexProof []byte
		var parallelism uint32
		var kzgCommitment []byte
		var kzgProof []byte
		for pi, data := range t.Proofs[2:] {
			if len(data) < 28 {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			increment := binary.BigEndian.Uint32(data[:4])
			parallelism = binary.BigEndian.Uint32(data[4:8])
			inputLen := binary.BigEndian.Uint64(data[8:16])

			if len(deletes) != 0 && pi == 0 {
				if deletes[0].GetDeletedProof().Difficulty-1 != increment {
					return nil, errors.Wrap(
						application.ErrInvalidStateTransition,
						"handle mint",
					)
				}
			} else if pi == 0 && bytes.Equal(t.Proofs[1], make([]byte, 32)) {
				frames, _, err := e.coinStore.GetPreCoinProofsForOwner(
					altAddr.FillBytes(make([]byte, 32)),
				)
				if err != nil || len(frames) != 0 {
					return nil, errors.Wrap(
						application.ErrInvalidStateTransition,
						"handle mint",
					)
				}
			} else if pi != 0 {
				if increment != previousIncrement-1 {
					return nil, errors.Wrap(
						application.ErrInvalidStateTransition,
						"handle mint",
					)
				}
			}
			previousIncrement = increment

			if uint64(len(data[16:])) < inputLen+8 {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			input := make([]byte, inputLen)
			copy(input[:], data[16:16+inputLen])

			outputLen := binary.BigEndian.Uint64(data[16+inputLen : 16+inputLen+8])

			if uint64(len(data[16+inputLen+8:])) < outputLen {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			output := make([]byte, outputLen)
			copy(output[:], data[16+inputLen+8:])
			dataProver := crypto.NewKZGInclusionProver(e.logger)
			wesoProver := crypto.NewWesolowskiFrameProver(e.logger)
			index = binary.BigEndian.Uint32(output[:4])
			indexProof = output[4:520]
			kzgCommitment = output[520:594]
			kzgProof = output[594:668]
			ip := sha3.Sum512(indexProof)

			v, err := dataProver.VerifyRaw(
				ip[:],
				kzgCommitment,
				int(index),
				kzgProof,
				nearestApplicablePowerOfTwo(uint64(parallelism)),
			)
			if err != nil {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			if !v {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			if len(prevInput) != 0 && !bytes.Equal(prevInput, kzgCommitment) {
				heuristic := uint64(highestIncrement) -
					(uint64(highestIncrement) * uint64(999) / uint64(1000))
				if highestIncrement != 0 && uint64(prevErrorMetric) > heuristic {
					return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
				} else {
					prevErrorMetric++
				}
			}

			wp := []byte{}
			wp = append(wp, peerId...)
			wp = append(wp, input...)
			v = wesoProver.VerifyPreDuskChallengeProof(
				wp,
				increment,
				index,
				indexProof,
			)
			if !v {
				return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
			}

			pomwBasis := big.NewInt(1200000)
			additional := new(big.Int).Mul(pomwBasis, big.NewInt(int64(parallelism)))
			reward.Add(
				reward,
				additional,
			)
			prevInput = input
		}

		if len(deletes) != 0 {
			reward.Add(
				reward,
				new(big.Int).SetBytes(deletes[0].GetDeletedProof().Amount),
			)
		}

		if previousIncrement == uint32(0xffffffff) {
			return nil, errors.Wrap(application.ErrInvalidStateTransition, "handle mint")
		}

		if previousIncrement > highestIncrement {
			highestIncrement = previousIncrement
		}

		txn, err := e.coinStore.NewTransaction()
		if err != nil {
			return nil, errors.Wrap(err, "handle mint")
		}
		if previousIncrement != 0 {
			add := &protobufs.PreCoinProof{
				Amount:     reward.FillBytes(make([]byte, 32)),
				Index:      index,
				IndexProof: indexProof,
				Commitment: kzgCommitment,
				Proof: binary.BigEndian.AppendUint32(
					binary.BigEndian.AppendUint32(
						append(
							append([]byte{}, kzgProof...),
							prevInput...,
						),
						prevErrorMetric,
					),
					highestIncrement,
				),
				Parallelism: parallelism,
				Difficulty:  previousIncrement,
				Owner: &protobufs.AccountRef{
					Account: &protobufs.AccountRef_ImplicitAccount{
						ImplicitAccount: &protobufs.ImplicitAccount{
							ImplicitType: 0,
							Address:      altAddr.FillBytes(make([]byte, 32)),
						},
					},
				},
			}
			proofAddr, err := GetAddressOfPreCoinProof(add)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
			returnAddr = proofAddr
			err = e.coinStore.PutPreCoinProof(
				txn,
				head.FrameNumber,
				proofAddr,
				add,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
		} else {
			proof := &protobufs.PreCoinProof{
				Amount:     reward.FillBytes(make([]byte, 32)),
				Index:      index,
				IndexProof: indexProof,
				Commitment: kzgCommitment,
				Proof: binary.BigEndian.AppendUint32(
					binary.BigEndian.AppendUint32(
						append(
							append([]byte{}, kzgProof...),
							prevInput...,
						),
						prevErrorMetric,
					),
					highestIncrement,
				),
				Parallelism: parallelism,
				Difficulty:  previousIncrement,
				Owner: &protobufs.AccountRef{
					Account: &protobufs.AccountRef_ImplicitAccount{
						ImplicitAccount: &protobufs.ImplicitAccount{
							ImplicitType: 0,
							Address:      altAddr.FillBytes(make([]byte, 32)),
						},
					},
				},
			}
			proofAddr, err := GetAddressOfPreCoinProof(proof)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
			returnAddr = proofAddr
			err = e.coinStore.PutPreCoinProof(
				txn,
				head.FrameNumber,
				proofAddr,
				proof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}

			mint := []byte{}
			mint = append(mint, reward.FillBytes(make([]byte, 32))...)
			mint = append(mint, altAddr.FillBytes(make([]byte, 32))...)
			sig := []byte("mint")
			sig = append(sig, mint...)
			out, err := e.pubSub.SignMessage(sig)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
			err = e.insertMessage(
				e.filter,
				&protobufs.TokenRequest{
					Request: &protobufs.TokenRequest_Mint{
						Mint: &protobufs.MintCoinRequest{
							Proofs: [][]byte{mint},
							Signature: &protobufs.Ed448Signature{
								Signature: out,
								PublicKey: &protobufs.Ed448PublicKey{
									KeyValue: e.provingKeyBytes,
								},
							},
						},
					},
				},
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
		}

		if len(deletes) == 1 {
			a, err := GetAddressOfPreCoinProof(deletes[0].GetDeletedProof())
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "handle mint")
			}
			e.coinStore.DeletePreCoinProof(
				txn,
				a,
				deletes[0].GetDeletedProof(),
			)
		}
		if err := txn.Commit(); err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "handle mint")
		}
	}
	return returnAddr, nil
}

type svr struct {
	protobufs.UnimplementedDataServiceServer
	svrChan chan protobufs.DataService_GetPublicChannelServer
}

func (e *svr) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	go func() {
		e.svrChan <- server
	}()
	<-server.Context().Done()
	return nil
}

func (e *DataClockConsensusEngine) GetPublicChannelForProvingKey(
	initiator bool,
	peerID []byte,
	provingKey []byte,
) (p2p.PublicChannelClient, error) {
	if initiator {
		svrChan := make(
			chan protobufs.DataService_GetPublicChannelServer,
		)
		after := time.After(20 * time.Second)
		go func() {
			server := grpc.NewServer(
				grpc.MaxSendMsgSize(600*1024*1024),
				grpc.MaxRecvMsgSize(600*1024*1024),
			)

			s := &svr{
				svrChan: svrChan,
			}
			protobufs.RegisterDataServiceServer(server, s)

			if err := e.pubSub.StartDirectChannelListener(
				peerID,
				base58.Encode(provingKey),
				server,
			); err != nil {
				e.logger.Error(
					"could not get public channel for proving key",
					zap.Error(err),
				)
				svrChan <- nil
			}
		}()
		select {
		case s := <-svrChan:
			return s, nil
		case <-after:
			return nil, errors.Wrap(
				errors.New("timed out"),
				"get public channel for proving key",
			)
		}
	} else {
		cc, err := e.pubSub.GetDirectChannel(peerID, base58.Encode(provingKey))
		if err != nil {
			e.logger.Error(
				"could not get public channel for proving key",
				zap.Error(err),
			)
			return nil, nil
		}
		client := protobufs.NewDataServiceClient(cc)
		s, err := client.GetPublicChannel(
			context.Background(),
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		)
		return s, errors.Wrap(err, "get public channel for proving key")
	}
}

// GetPublicChannel implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	return errors.New("not supported")
}
