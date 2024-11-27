package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Splits a coin into multiple coins",
	Long: `Splits a coin into multiple coins:
	
	split <OfCoin> <Amounts>...
	
	OfCoin - the address of the coin to split
	Amounts - the sets of amounts to split
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 3 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		coinaddrHex, _ := strings.CutPrefix(args[0], "0x")
		coinaddr, err := hex.DecodeString(coinaddrHex)
		if err != nil {
			panic(err)
		}
		coin := &protobufs.CoinRef{
			Address: coinaddr,
		}

		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		amounts := [][]byte{}
		for _, amt := range args[1:] {
			amount, err := decimal.NewFromString(amt)
			if err != nil {
				fmt.Println("invalid amount")
				os.Exit(1)
			}
			amount = amount.Mul(decimal.NewFromBigInt(conversionFactor, 0))
			amountBytes := amount.BigInt().FillBytes(make([]byte, 32))
			amounts = append(amounts, amountBytes)
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

		split := &protobufs.SplitCoinRequest{
			OfCoin:  coin,
			Amounts: amounts,
		}
		if err := split.SignED448(pubKeyBytes, privKey.Sign); err != nil {
			panic(err)
		}
		if err := split.Validate(); err != nil {
			panic(err)
		}

		_, err = client.SendMessage(
			context.Background(),
			split.TokenRequest(),
		)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	tokenCmd.AddCommand(splitCmd)
}
