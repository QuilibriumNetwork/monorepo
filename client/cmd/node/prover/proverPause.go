package prover

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	nodeConfig "source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var NodeConfig *nodeConfig.Config

var proverPauseCmd = &cobra.Command{
	Use:   "pause",
	Short: "Pauses a prover",
	Long: `Pauses a prover (use in emergency when a worker isn't coming back online):
	
	pause
	`,
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}

		NodeConfig, err = utils.LoadNodeConfig(ConfigDirectory)
		if err != nil {
			fmt.Printf("invalid config directory: %s\n", ConfigDirectory)
			os.Exit(1)
		}

		pubsub := p2p.NewBlossomSub(NodeConfig.P2P, logger)
		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)
		pubsub.Subscribe(
			append([]byte{0x00}, intrinsicFilter...),
			func(message *pb.Message) error { return nil },
		)
		key, err := utils.GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		payload := []byte("pause")
		filter := bytes.Repeat([]byte{0xff}, 32)

		payload = append(payload, filter...)

		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

	loop:
		for {
			peers := pubsub.GetBitmaskPeers()
			if len(peers) == 0 {
				fmt.Println("Waiting for peer list to form before broadcasting pause...")
				time.Sleep(5 * time.Second)
				continue loop
			}
			for _, set := range peers {
				if len(set) < 3 {
					fmt.Println("Waiting for more peers before broadcasting pause...")
					time.Sleep(5 * time.Second)
					continue loop
				}
				break loop
			}
		}

		err = publishMessage(
			key,
			pubsub,
			append([]byte{0x00}, intrinsicFilter...),
			&protobufs.AnnounceProverPause{
				Filter: filter,
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: pub,
					},
				},
			},
		)
		if err != nil {
			panic(err)
		}
	},
}

func publishMessage(
	key crypto.PrivKey,
	pubsub p2p.PubSub,
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	pub, err := key.GetPublic().Raw()
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	pbi, err := poseidon.HashBytes(pub)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	provingKeyAddress := pbi.FillBytes(make([]byte, 32))

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return pubsub.PublishToBitmask(filter, data)
}

func init() {
	ProverCmd.AddCommand(proverPauseCmd)
}
