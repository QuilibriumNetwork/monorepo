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

var NodeProverConfirmCmd = &cobra.Command{
	Use:   "confirm [filter1] [filter2] ...",
	Short: "Confirms prover shard allocations",
	Long: `Confirms prover shard allocations for the specified shard filters.

	confirm [filter1] [filter2] ...

	If no filters are specified, confirms all shards (all-0xFF filter).
	Each filter is a hex-encoded 32-byte shard identifier.
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

		var filters [][]byte
		if len(args) > 0 {
			for _, arg := range args {
				f, err := hex.DecodeString(arg)
				if err != nil {
					fmt.Printf("Invalid filter hex %q: %v\n", arg, err)
					os.Exit(1)
				}
				filters = append(filters, f)
			}
		} else {
			filters = [][]byte{bytes.Repeat([]byte{0xff}, 32)}
		}

		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		confirm, err := global.NewProverConfirm(
			filters,
			frameNumber,
			KeyManager,
			nil, // hypergraph not needed for Prove()
			nil, // rdfMultiprover not needed for Prove()
		)
		if err != nil {
			fmt.Printf("Failed to create confirm: %v\n", err)
			os.Exit(1)
		}

		if err := confirm.Prove(frameNumber); err != nil {
			fmt.Printf("Failed to prove confirm: %v\n", err)
			os.Exit(1)
		}

		globalDomain := bytes.Repeat([]byte{0xff}, 32)

		err = sendProverMessage(
			client,
			globalDomain,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Confirm{
					Confirm: confirm.ToProtobuf(),
				},
			},
		)
		if err != nil {
			fmt.Printf("Failed to send confirm: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Prover confirm sent successfully")
	},
}
