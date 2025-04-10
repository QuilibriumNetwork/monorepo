package token

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var mergeCmd = &cobra.Command{
	Use:   "merge [all|<Coin Addresses>...]",
	Short: "Merges multiple coins",
	Long: `Merges multiple coins:
	
	merge all               - Merges all available coins
	merge <Coin Addresses>  - Merges specified coin addresses
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}

		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		peerId := utils.GetPeerIDFromConfig(NodeConfig)
		privKey, err := utils.GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		pubKeyBytes, err := privKey.GetPublic().Raw()
		if err != nil {
			panic(err)
		}
		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))

		altAddr, err := poseidon.HashBytes([]byte(pubKeyBytes))
		if err != nil {
			panic(err)
		}

		altAddrBytes := altAddr.FillBytes(make([]byte, 32))

		var coinaddrs []*protobufs.CoinRef

		// Process for "merge all" command
		if len(args) == 1 && args[0] == "all" {
			// Make a new call to get all existing coins
			info, err := client.GetTokensByAccount(
				context.Background(),
				&protobufs.GetTokensByAccountRequest{
					Address: addrBytes,
				},
			)
			if err != nil {
				panic(err)
			}
			// Add all coins to the list
			for _, coin := range info.Addresses {
				coinaddrs = append(coinaddrs, &protobufs.CoinRef{
					Address: coin,
				})
			}
			info, err = client.GetTokensByAccount(
				context.Background(),
				&protobufs.GetTokensByAccountRequest{
					Address: altAddrBytes,
				},
			)
			if err != nil {
				panic(err)
			}
			// Add all coins to the list
			for _, coin := range info.Addresses {
				coinaddrs = append(coinaddrs, &protobufs.CoinRef{
					Address: coin,
				})
			}
			// Terminate if no coins available
			if len(coinaddrs) == 0 {
				println("No coins available to merge")
				return
			}
		} else {
			// Regular coin address processing logic
			for _, arg := range args {
				coinaddrHex, _ := strings.CutPrefix(arg, "0x")
				coinaddr, err := hex.DecodeString(coinaddrHex)
				if err != nil {
					panic(err)
				}
				coinaddrs = append(coinaddrs, &protobufs.CoinRef{
					Address: coinaddr,
				})
			}
		}

		merge := &protobufs.MergeCoinRequest{
			Coins: coinaddrs,
		}

		// Display merge details and confirmation prompt
		fmt.Printf("\nMerge Transaction Details:\n")
		fmt.Printf("Number of coins to merge: %d\n", len(coinaddrs))
		fmt.Println("Coins to be merged:")
		for i, coin := range coinaddrs {
			fmt.Printf("%d. 0x%x\n", i+1, coin.Address)
		}
		fmt.Print("\nDo you want to proceed with this merge? (yes/no): ")

		var response string
		fmt.Scanln(&response)

		if strings.ToLower(response) != "yes" {
			fmt.Println("Merge transaction cancelled by user.")
			return
		}

		// Create payload for merge operation
		payload := []byte("merge")
		for _, coinRef := range coinaddrs {
			payload = append(payload, coinRef.Address...)
		}
		if err := merge.SignED448(pubKeyBytes, privKey.Sign); err != nil {
			panic(err)
		}
		if err := merge.Validate(); err != nil {
			panic(err)
		}

		// Send merge request
		_, err = client.SendMessage(
			context.Background(),
			merge.TokenRequest(),
		)
		if err != nil {
			panic(err)
		}

		fmt.Println("Merge transaction sent successfully.")
	},
}

func init() {
	TokenCmd.AddCommand(mergeCmd)
}
