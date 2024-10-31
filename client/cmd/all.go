package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Mints all pre-2.0 rewards",

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			fmt.Println("command has no arguments")
			os.Exit(1)
		}

		if !LightNode {
			fmt.Println(
				"mint all cannot be run unless node is not running. ensure your node " +
					"is not running and your config.yml has grpc disabled",
			)
			os.Exit(1)
		}

		db := store.NewPebbleDB(NodeConfig.DB)
		logger, _ := zap.NewProduction()
		dataProofStore := store.NewPebbleDataProofStore(db, logger)
		peerId := GetPeerIDFromConfig(NodeConfig)
		privKey, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		pub, err := privKey.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		pubSub := p2p.NewBlossomSub(NodeConfig.P2P, logger)
		logger.Info("connecting to network")
		time.Sleep(5 * time.Second)

		increment, _, _, err := dataProofStore.GetLatestDataTimeProof(
			[]byte(peerId),
		)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				logger.Info("could not find pre-2.0 proofs")
				return
			}

			panic(err)
		}

		addrBI, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addr := addrBI.FillBytes(make([]byte, 32))

		genesis := config.GetGenesis()
		bpub, err := crypto.UnmarshalEd448PublicKey(genesis.Beacon)
		if err != nil {
			panic(err)
		}

		bpeerId, err := peer.IDFromPublicKey(bpub)
		if err != nil {
			panic(errors.Wrap(err, "error getting peer id"))
		}

		resume := make([]byte, 32)
		cc, err := pubSub.GetDirectChannel([]byte(bpeerId), "worker")
		if err != nil {
			logger.Info(
				"could not establish direct channel, waiting...",
				zap.Error(err),
			)
			time.Sleep(10 * time.Second)
		}
		for {
			if cc == nil {
				cc, err = pubSub.GetDirectChannel([]byte(bpeerId), "worker")
				if err != nil {
					logger.Info(
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
					logger.Error(
						"got error response, waiting...",
						zap.Error(err),
					)
					time.Sleep(10 * time.Second)
					cc.Close()
					cc = nil
					err = pubSub.Reconnect([]byte(peerId))
					if err != nil {
						logger.Error(
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
				_, parallelism, input, output, err := dataProofStore.GetDataTimeProof(
					[]byte(peerId),
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
					logger.Error(
						"could not find data time proof for peer and increment, stopping worker",
						zap.String("peer_id", peerId.String()),
						zap.Int("increment", i),
					)
					cc.Close()
					cc = nil
					return
				}

				batchCount++
				if batchCount == 200 || i == 0 {
					logger.Info("publishing proof batch", zap.Int("increment", i))

					payload := []byte("mint")
					for _, i := range proofs {
						payload = append(payload, i...)
					}
					sig, err := pubSub.SignMessage(payload)
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
									KeyValue: pub,
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
							logger.Info("pre-midnight proofs submitted, returning")
							cc.Close()
							cc = nil
							return
						}

						logger.Error(
							"got error response, waiting...",
							zap.Error(err),
						)

						resume = make([]byte, 32)
						cc.Close()
						cc = nil
						time.Sleep(10 * time.Second)
						err = pubSub.Reconnect([]byte(peerId))
						if err != nil {
							logger.Error(
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
						logger.Info("pre-midnight proofs submitted, returning")
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
	},
}

func init() {
	mintCmd.AddCommand(allCmd)
}
