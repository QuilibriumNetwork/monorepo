package data

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (e *DataClockConsensusEngine) runPreMidnightProofWorker() {
	e.logger.Info("checking for pre-2.0 proofs")

	increment, _, _, err := e.dataProofStore.GetLatestDataTimeProof(
		e.pubSub.GetPeerID(),
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			e.logger.Info("could not find pre-2.0 proofs")
			return
		}

		panic(err)
	}

	for {
		if e.state < consensus.EngineStateCollecting {
			e.logger.Info("waiting for node to finish starting")
			time.Sleep(10 * time.Second)
			continue
		}
		break
	}

	addrBI, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		panic(err)
	}

	addr := addrBI.FillBytes(make([]byte, 32))

	genesis := config.GetGenesis()
	pub, err := crypto.UnmarshalEd448PublicKey(genesis.Beacon)
	if err != nil {
		panic(err)
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	for {
		tries := e.GetFrameProverTries()

		if len(tries) == 0 || e.pubSub.GetNetworkPeersCount() < 3 {
			e.logger.Info("waiting for more peer info to appear")
			time.Sleep(10 * time.Second)
			continue
		}

		_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			e.logger.Error("error while fetching pre-coin proofs", zap.Error(err))
			return
		}

		if len(prfs) != 0 {
			e.logger.Info("already completed pre-midnight mint")
			return
		}

		break
	}

	resume := make([]byte, 32)
	cc, err := e.pubSub.GetDirectChannel([]byte(peerId), "worker")
	if err != nil {
		e.logger.Info(
			"could not establish direct channel, waiting...",
			zap.Error(err),
		)
		time.Sleep(10 * time.Second)
	}
	for {
		if e.state >= consensus.EngineStateStopping || e.state == consensus.EngineStateStopped {
			break
		}
		_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			e.logger.Error("error while fetching pre-coin proofs", zap.Error(err))
			return
		}

		if len(prfs) != 0 {
			e.logger.Info("already completed pre-midnight mint")
			return
		}

		if cc == nil {
			cc, err = e.pubSub.GetDirectChannel([]byte(peerId), "worker")
			if err != nil {
				e.logger.Info(
					"could not establish direct channel, waiting...",
					zap.Error(err),
				)
				cc = nil
				time.Sleep(10 * time.Second)
				continue
			}
		}

		client := protobufs.NewDataServiceClient(cc)

		if bytes.Equal(resume, make([]byte, 32)) {
			status, err := client.GetPreMidnightMintStatus(
				context.Background(),
				&protobufs.PreMidnightMintStatusRequest{
					Owner: addr,
				},
				grpc.MaxCallSendMsgSize(1*1024*1024),
				grpc.MaxCallRecvMsgSize(1*1024*1024),
			)
			if err != nil || status == nil {
				e.logger.Error(
					"got error response, waiting...",
					zap.Error(err),
				)
				time.Sleep(10 * time.Second)
				cc.Close()
				cc = nil
				err = e.pubSub.Reconnect([]byte(peerId))
				if err != nil {
					e.logger.Error(
						"got error response, waiting...",
						zap.Error(err),
					)
					time.Sleep(10 * time.Second)
				}
				continue
			}

			resume = status.Address

			if status.Increment != 0 {
				increment = status.Increment - 1
			} else if !bytes.Equal(status.Address, make([]byte, 32)) {
				increment = 0
			}
		}

		proofs := [][]byte{
			[]byte("pre-dusk"),
			resume,
		}

		batchCount := 0
		// the cast is important, it underflows without:
		for i := int(increment); i >= 0; i-- {
			_, parallelism, input, output, err := e.dataProofStore.GetDataTimeProof(
				e.pubSub.GetPeerID(),
				uint32(i),
			)
			if err == nil {
				p := []byte{}
				p = binary.BigEndian.AppendUint32(p, uint32(i))
				p = binary.BigEndian.AppendUint32(p, parallelism)
				p = binary.BigEndian.AppendUint64(p, uint64(len(input)))
				p = append(p, input...)
				p = binary.BigEndian.AppendUint64(p, uint64(len(output)))
				p = append(p, output...)

				proofs = append(proofs, p)
			} else {
				e.logger.Error(
					"could not find data time proof for peer and increment, stopping worker",
					zap.String("peer_id", peer.ID(e.pubSub.GetPeerID()).String()),
					zap.Int("increment", i),
				)
				cc.Close()
				cc = nil
				return
			}

			batchCount++
			if batchCount == 200 || i == 0 {
				e.logger.Info("publishing proof batch", zap.Int("increment", i))

				payload := []byte("mint")
				for _, i := range proofs {
					payload = append(payload, i...)
				}
				sig, err := e.pubSub.SignMessage(payload)
				if err != nil {
					cc.Close()
					panic(err)
				}

				resp, err := client.HandlePreMidnightMint(
					context.Background(),
					&protobufs.MintCoinRequest{
						Proofs: proofs,
						Signature: &protobufs.Ed448Signature{
							PublicKey: &protobufs.Ed448PublicKey{
								KeyValue: e.pubSub.GetPublicKey(),
							},
							Signature: sig,
						},
					},
					grpc.MaxCallSendMsgSize(1*1024*1024),
					grpc.MaxCallRecvMsgSize(1*1024*1024),
				)

				if err != nil {
					if strings.Contains(
						err.Error(),
						application.ErrInvalidStateTransition.Error(),
					) && i == 0 {
						resume = make([]byte, 32)
						e.logger.Info("pre-midnight proofs submitted, returning")
						cc.Close()
						cc = nil
						return
					}

					e.logger.Error(
						"got error response, waiting...",
						zap.Error(err),
					)

					resume = make([]byte, 32)
					cc.Close()
					cc = nil
					time.Sleep(10 * time.Second)
					err = e.pubSub.Reconnect([]byte(peerId))
					if err != nil {
						e.logger.Error(
							"got error response, waiting...",
							zap.Error(err),
						)
						time.Sleep(10 * time.Second)
					}
					break
				}

				resume = resp.Address
				batchCount = 0
				proofs = [][]byte{
					[]byte("pre-dusk"),
					resume,
				}

				if i == 0 {
					e.logger.Info("pre-midnight proofs submitted, returning")
					cc.Close()
					cc = nil
					return
				} else {
					increment = uint32(i) - 1
				}

				break
			}
		}
	}
}

func GetAddressOfPreCoinProof(
	proof *protobufs.PreCoinProof,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = append(eval, proof.Amount...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Index)
	eval = append(eval, proof.IndexProof...)
	eval = append(eval, proof.Commitment...)
	eval = append(eval, proof.Proof...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Parallelism)
	eval = binary.BigEndian.AppendUint32(eval, proof.Difficulty)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, proof.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}
