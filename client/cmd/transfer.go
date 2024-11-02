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
ToAccount – account address, must be specified
OfCoin – the address of the coin to send in whole`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			panic("invalid arguments")
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

		var coinaddr *protobufs.CoinRef
		payload := []byte("transfer")
		toaddr := []byte{}

		for i, arg := range args {
			addrHex, _ := strings.CutPrefix(arg, "0x")
			addr, err := hex.DecodeString(addrHex)
			if err != nil {
				panic(err)
			}
			if i == 0 {
				toaddr = addr
				continue
			}
			coinaddr = &protobufs.CoinRef{
				Address: addr,
			}
			payload = append(payload, addr...)
		}
		payload = append(payload, toaddr...)

		// Display transaction details and confirmation prompt
		fmt.Printf("\nTransaction Details:\n")
		fmt.Printf("To Address: 0x%x\n", toaddr)
		fmt.Printf("Coin Address: 0x%x\n", coinaddr.Address)
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
						OfCoin: coinaddr,
						ToAccount: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: toaddr,
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
	tokenCmd.AddCommand(transferCmd)
}
