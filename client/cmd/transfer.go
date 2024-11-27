package cmd

import (
	"context"
	"encoding/hex"
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
	OfCoin – the address of the coin to send in whole
	`,
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
		privKey, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}
		pubKeyBytes, err := privKey.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		var coinaddr *protobufs.CoinRef
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
		}

		transfer := &protobufs.TransferCoinRequest{
			OfCoin: coinaddr,
			ToAccount: &protobufs.AccountRef{
				Account: &protobufs.AccountRef_ImplicitAccount{
					ImplicitAccount: &protobufs.ImplicitAccount{
						Address: toaddr,
					},
				},
			},
		}
		if err := transfer.SignED448(pubKeyBytes, privKey.Sign); err != nil {
			panic(err)
		}
		if err := transfer.Validate(); err != nil {
			panic(err)
		}

		_, err = client.SendMessage(
			context.Background(),
			transfer.TokenRequest(),
		)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	tokenCmd.AddCommand(transferCmd)
}
