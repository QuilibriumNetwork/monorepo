package token

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var AcceptCmd = &cobra.Command{
	Use:   "accept <PendingTransaction>",
	Short: "Accepts a pending transfer",
	Long: `Accepts a pending transfer:

	accept <PendingTransaction>

	PendingTransaction - the 0x-prefixed hex address of the pending transfer
	`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pendingAddr, err := parseCoinAddress(args[0])
		if err != nil {
			fmt.Printf("Invalid pending transaction address: %v\n", err)
			os.Exit(1)
		}

		conn, err := utils.GetGRPCClient(
			LightNode,
			ClientConfig.CustomRpc,
			NodeConfig,
		)
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		vk, sk := getOwnKeys()

		amount, err := getCoinBalance(client, vk, sk, pendingAddr)
		if err != nil {
			fmt.Printf("Failed to get pending transaction balance: %v\n", err)
			os.Exit(1)
		}

		tb, err := newTransactionBuilderFromClient(client, KeyManager)
		if err != nil {
			fmt.Printf("Failed to create transaction builder: %v\n", err)
			os.Exit(1)
		}

		tx, err := tb.BuildAcceptTransaction(
			pendingAddr, amount,
			vk.Public(), sk.Public(),
		)
		if err != nil {
			fmt.Printf("Failed to build accept transaction: %v\n", err)
			os.Exit(1)
		}

		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}

		provenTx, err := tb.ProveTransaction(tx, frameInfo.GetLastGlobalHeadFrame())
		if err != nil {
			fmt.Printf("Failed to prove transaction: %v\n", err)
			os.Exit(1)
		}

		err = SendTransaction(
			client,
			token.QUIL_TOKEN_ADDRESS,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Transaction{
					Transaction: provenTx,
				},
			},
			KeyManager,
		)
		if err != nil {
			fmt.Printf("Failed to send transaction: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Accept transaction sent successfully")
	},
}
