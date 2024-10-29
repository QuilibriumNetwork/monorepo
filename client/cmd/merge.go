package cmd

import (
	"context"
	"encoding/hex"
	"strings"
	"github.com/spf13/cobra"
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
		key, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		var coinaddrs []*protobufs.CoinRef

		// Process for "merge all" command
		if len(args) == 1 && args[0] == "all" {
			// Make a new call to get all existing coins
			ctx := context.Background()
			response, err := client.GetCoins(ctx, &protobufs.GetCoinsRequest{})
			if err != nil {
				panic(err)
			}

			// Terminate if no coins available
			if len(response.Coins) == 0 {
				println("No coins available to merge")
				return
			}

			// Add all coins to the list
			for _, coin := range response.Coins {
				coinaddrs = append(coinaddrs, &protobufs.CoinRef{
					Address: coin.Address,
				})
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

		// Create payload for merge operation
		payload := []byte("merge")
		for _, coinRef := range coinaddrs {
			payload = append(payload, coinRef.Address...)
		}

		// Signing process
		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		// Send merge request
		_, err = client.SendMessage(
			context.Background(),
			&protobufs.TokenRequest{
				Request: &protobufs.TokenRequest_Merge{
					Merge: &protobufs.MergeCoinRequest{
						Coins: coinaddrs,
						Signature: &protobufs.Ed448Signature{
							Signature: sig,
							PublicKey: &protobufs.Ed448PublicKey{
								KeyValue: pub,
							},
						},
					},
				},
			},
		)
		if err != nil {
			panic(err)
		}

		println("Merge request sent successfully")
	},
}

func init() {
	tokenCmd.AddCommand(mergeCmd)
}
