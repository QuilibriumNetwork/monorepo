package token

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var MergeCmd = &cobra.Command{
	Use:   "merge [all|<Coin Addresses>...]",
	Short: "Merges multiple coins",
	Long: `Merges multiple coins:

	merge all               - Merges all available coins
	merge <Coin Addresses>  - Merges specified coin addresses
	`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
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

		var coinAddresses [][]byte
		var totalAmount *big.Int

		if len(args) == 1 && args[0] == "all" {
			// Merge all coins
			txs, err := client.GetTokensByAccount(
				context.Background(),
				&protobufs.GetTokensByAccountRequest{
					Address: slices.Concat(vk.Public(), sk.Public()),
					Domain:  token.QUIL_TOKEN_ADDRESS[:],
				},
			)
			if err != nil {
				fmt.Printf("Failed to get coins: %v\n", err)
				os.Exit(1)
			}

			totalAmount = big.NewInt(0)
			for _, t := range txs.Transactions {
				coinAddresses = append(coinAddresses, t.Address)
				totalAmount.Add(totalAmount, new(big.Int).SetBytes(t.RawBalance))
			}

			if len(coinAddresses) < 2 {
				fmt.Println("Need at least 2 coins to merge")
				os.Exit(1)
			}
		} else {
			// Merge specified coins
			totalAmount = big.NewInt(0)
			for _, arg := range args {
				addrHex := strings.TrimPrefix(arg, "0x")
				addr, err := hex.DecodeString(addrHex)
				if err != nil {
					fmt.Printf("Invalid coin address '%s': %v\n", arg, err)
					os.Exit(1)
				}
				if len(addr) != 64 {
					fmt.Printf("Invalid coin address '%s': expected 64 bytes\n", arg)
					os.Exit(1)
				}
				coinAddresses = append(coinAddresses, addr)

				bal, err := getCoinBalance(client, vk, sk, addr)
				if err != nil {
					fmt.Printf("Failed to get balance for coin %s: %v\n", arg, err)
					os.Exit(1)
				}
				totalAmount.Add(totalAmount, bal)
			}
		}

		fmt.Printf("Merging %d coins (total: %s QUIL)\n", len(coinAddresses),
			func() string {
				cf, _ := new(big.Int).SetString("1DCD65000", 16)
				return new(big.Rat).SetFrac(totalAmount, cf).FloatString(12)
			}())

		tb, err := newTransactionBuilderFromClient(client, KeyManager)
		if err != nil {
			fmt.Printf("Failed to create transaction builder: %v\n", err)
			os.Exit(1)
		}

		tx, err := tb.BuildMergeTransaction(
			coinAddresses, totalAmount,
			vk.Public(), sk.Public(),
		)
		if err != nil {
			fmt.Printf("Failed to build merge transaction: %v\n", err)
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

		fmt.Println("Merge transaction sent successfully")
	},
}
