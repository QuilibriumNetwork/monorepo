package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var coinsCmd = &cobra.Command{
	Use:   "coins",
	Short: "Lists all coins under control of the managing account",
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
		resp, err := client.GetTokensByAccount(
			context.Background(),
			&protobufs.GetTokensByAccountRequest{
				Address: addrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		if len(resp.Coins) != len(resp.FrameNumbers) {
			panic("invalid response from RPC")
		}

		altAddr, err := poseidon.HashBytes([]byte(pub))
		if err != nil {
			panic(err)
		}

		altAddrBytes := altAddr.FillBytes(make([]byte, 32))
		resp2, err := client.GetTokensByAccount(
			context.Background(),
			&protobufs.GetTokensByAccountRequest{
				Address: altAddrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		if len(resp.Coins) != len(resp.FrameNumbers) {
			panic("invalid response from RPC")
		}

		for i, coin := range resp.Coins {
			amount := new(big.Int).SetBytes(coin.Amount)
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			fmt.Println(
				r.FloatString(12),
				fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
			)
		}
		for i, coin := range resp2.Coins {
			amount := new(big.Int).SetBytes(coin.Amount)
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			fmt.Println(
				r.FloatString(12),
				fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
			)
		}
	},
}

func init() {
	tokenCmd.AddCommand(coinsCmd)
}
