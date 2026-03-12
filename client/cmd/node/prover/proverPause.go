package prover

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var NodeProverPauseCmd = &cobra.Command{
	Use:   "pause [filter]",
	Short: "Pauses a prover",
	Long: `Pauses a prover (use in emergency when a worker isn't coming back online).

	pause [filter]

	filter - optional hex-encoded shard filter (defaults to all-0xFF for all shards)
	`,
	Run: func(cmd *cobra.Command, args []string) {
		initKeyManager()
		if KeyManager == nil {
			fmt.Println("Failed to initialize key manager")
			os.Exit(1)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}

		filter := bytes.Repeat([]byte{0xff}, 32)
		if len(args) > 0 {
			filter, err = hex.DecodeString(args[0])
			if err != nil {
				fmt.Printf("Invalid filter hex: %v\n", err)
				os.Exit(1)
			}
		}

		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		pause, err := global.NewProverPause(
			filter,
			frameNumber,
			KeyManager,
			nil, // hypergraph not needed for Prove()
			nil, // rdfMultiprover not needed for Prove()
		)
		if err != nil {
			fmt.Printf("Failed to create pause: %v\n", err)
			os.Exit(1)
		}

		if err := pause.Prove(frameNumber); err != nil {
			fmt.Printf("Failed to prove pause: %v\n", err)
			os.Exit(1)
		}

		globalDomain := bytes.Repeat([]byte{0xff}, 32)

		err = sendProverMessage(
			client,
			globalDomain,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Pause{
					Pause: pause.ToProtobuf(),
				},
			},
		)
		if err != nil {
			fmt.Printf("Failed to send pause: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Prover pause sent successfully")
	},
}
