package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Lists the total balance of tokens in the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		peerId := GetPeerIDFromConfig(NodeConfig)
		privKey, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		pub, err := privKey.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))
		info, err := client.GetTokenInfo(
			context.Background(),
			&protobufs.GetTokenInfoRequest{
				Address: addrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		tokens := new(big.Int).SetBytes(info.OwnedTokens)
		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		r := new(big.Rat).SetFrac(tokens, conversionFactor)

		altAddr, err := poseidon.HashBytes([]byte(pub))
		if err != nil {
			panic(err)
		}

		altAddrBytes := altAddr.FillBytes(make([]byte, 32))
		info, err = client.GetTokenInfo(
			context.Background(),
			&protobufs.GetTokenInfoRequest{
				Address: altAddrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		if info.OwnedTokens == nil {
			panic("invalid response from RPC")
		}

		tokens = new(big.Int).SetBytes(info.OwnedTokens)
		r2 := new(big.Rat).SetFrac(tokens, conversionFactor)
		fmt.Println("Total balance:", r.FloatString(12), fmt.Sprintf(
			"QUIL (Account 0x%x)",
			addrBytes,
		))
		if r2.Cmp(big.NewRat(0, 1)) != 0 {
			fmt.Println("Total balance:", r2.FloatString(12), fmt.Sprintf(
				"QUIL (Account 0x%x)",
				altAddrBytes,
			))
		}
	},
}

func init() {
	tokenCmd.AddCommand(balanceCmd)
}
