package token

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var coinsCmd = &cobra.Command{
	Use:   "coins",
	Short: "Lists all coins under control of the managing account",
	Long: `Lists all coins under control of the managing account.
	
	coins [metadata]
	
	When "metadata" is added to the command, includes timestamps and frame numbers.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		includeMetadata := false
		for _, arg := range args {
			if arg == "metadata" {
				includeMetadata = true
			}
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
				Address:         addrBytes,
				IncludeMetadata: includeMetadata,
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
				Address:         altAddrBytes,
				IncludeMetadata: includeMetadata,
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
			if !includeMetadata || len(resp.Timestamps) == 0 {
				fmt.Println(
					r.FloatString(12),
					fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
				)
			} else {
				frame := resp.FrameNumbers[i]
				timestamp := resp.Timestamps[i]

				t := time.UnixMilli(timestamp)

				fmt.Println(
					r.FloatString(12),
					fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
					fmt.Sprintf("Frame %d, Timestamp %s", frame, t.Format(time.RFC3339)),
				)
			}
		}
		for i, coin := range resp2.Coins {
			amount := new(big.Int).SetBytes(coin.Amount)
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			if !includeMetadata || len(resp.Timestamps) == 0 {
				fmt.Println(
					r.FloatString(12),
					fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
				)
			} else {
				frame := resp.FrameNumbers[i]
				timestamp := resp.Timestamps[i]

				t := time.UnixMilli(timestamp)

				fmt.Println(
					r.FloatString(12),
					fmt.Sprintf("QUIL (Coin 0x%x)", resp.Addresses[i]),
					fmt.Sprintf("Frame %d, Timestamp %s", frame, t.Format(time.RFC3339)),
				)
			}
		}
	},
}

func init() {
	TokenCmd.AddCommand(coinsCmd)
}
