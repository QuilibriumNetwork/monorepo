package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
)

func main() {
	flag.Parse()
	cfg, err := config.LoadConfig(*configDirectory, "", false)

	if err != nil {
		panic(err)
	}

	logger, _ := zap.NewProduction()
	pubsub := p2p.NewBlossomSub(cfg.P2P, cfg.Engine, logger, 0)
	fmt.Print("Enter bitmask in hex (no 0x prefix): ")
	reader := bufio.NewReader(os.Stdin)
	bitmaskHex, _ := reader.ReadString('\n')
	bitmaskHex = strings.TrimRight(bitmaskHex, "\n")
	logger.Info("subscribing to bitmask")

	bitmask, err := hex.DecodeString(bitmaskHex)
	if err != nil {
		panic(err)
	}

	err = pubsub.Subscribe(bitmask, func(message *pb.Message) error {
		logger.Info(
			"received message",
			zap.String("bitmask", hex.EncodeToString(message.Bitmask)),
			zap.String("peer", peer.ID(message.From).String()),
			zap.String("message", string(message.Data)),
		)
		return nil
	})
	if err != nil {
		panic(err)
	}

	for {
		fmt.Print(peer.ID(pubsub.GetPeerID()).String() + "> ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimRight(message, "\n")
		err = pubsub.PublishToBitmask(bitmask, []byte(message))
		if err != nil {
			logger.Error("error sending", zap.Error(err))
		}
	}
}
