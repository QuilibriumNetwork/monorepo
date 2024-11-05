package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Creates a pending transfer of coin",
	Long: `Creates a pending transfer of coin:
	transfer <ToAccount> <OfCoin>
	ToAccount – account address, defaults to user's main account if not specified
	OfCoin – the address of the coin to send in whole, defaults to user's default coin if not specified`,
	Run: func(cmd *cobra.Command, args []string) {
		var toaddr, coinaddr string
		var err error

		// Prompt for to address if not provided
		toaddr, _ = cmd.Flags().GetString("to")
		if toaddr == "" {
			fmt.Print("Enter recipient address: ")
			fmt.Scanln(&toaddr)
		}

		// Prompt for coin address if not provided
		coinaddr, _ = cmd.Flags().GetString("coin")
		if coinaddr == "" {
			fmt.Print("Enter coin address: ")
			fmt.Scanln(&coinaddr)
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

		var coinRef *protobufs.CoinRef
		payload := []byte("transfer")

		toAddrBytes, err := hex.DecodeString(strings.TrimPrefix(toaddr, "0x"))
		if err != nil {
			panic(err)
		}

		coinAddrBytes, err := hex.DecodeString(strings.TrimPrefix(coinaddr, "0x"))
		if err != nil {
			panic(err)
		}

		coinRef = &protobufs.CoinRef{
			Address: coinAddrBytes,
		}
		payload = append(payload, toAddrBytes...)
		payload = append(payload, coinAddrBytes...)

		// Display transaction details and confirmation prompt
		fmt.Printf("\nTransaction Details:\n")
		fmt.Printf("To Address: 0x%x\n", toAddrBytes)
		fmt.Printf("Coin Address: 0x%x\n", coinAddrBytes)
		fmt.Print("\nDo you want to proceed with this transaction? (yes/no): ")

		var response string
		fmt.Scanln(&response)

		if strings.ToLower(response) != "yes" {
			fmt.Println("Transaction cancelled by user.")
			return
		}

		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		_, err = client.SendMessage(
			context.Background(),
			&protobufs.TokenRequest{
				Request: &protobufs.TokenRequest_Transfer{
					Transfer: &protobufs.TransferCoinRequest{
						OfCoin: coinRef,
						ToAccount: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: toAddrBytes,
								},
							},
						},
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

		fmt.Println("Transaction sent successfully.")
	},
}

func init() {
	transferCmd.Flags().StringP("to", "", "", "recipient account address")
	transferCmd.Flags().StringP("coin", "", "", "coin address to transfer")
	tokenCmd.AddCommand(transferCmd)
}
