package token

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var parts int
var partAmount string
var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Splits a coin into multiple coins",
	Long: `Splits a coin into multiple coins:

	split <OfCoin> <Amounts>...
	split <--parts PARTS> [--part-amount AMOUNT] <OfCoin>

	OfCoin - the address of the coin to split
	Amounts - the sets of amounts to split

	Example - Split a coin into the specified amounts:
		$ qclient token coins
		1.000000000000 QUIL (Coin 0x1234)
		$ qclient token split 0x1234 0.5 0.25 0.25
		$ qclient token coins
		0.250000000000 QUIL (Coin 0x1111)
		0.250000000000 QUIL (Coin 0x2222)
		0.500000000000 QUIL (Coin 0x3333)

	Example - Split a coin into three parts:
		$ qclient token coins
		1.000000000000 QUIL (Coin 0x1234)
		$ qclient token split 0x1234 --parts 3
		$ qclient token coins
		0.000000000250 QUIL (Coin 0x1111)
		0.333333333250 QUIL (Coin 0x2222)
		0.333333333250 QUIL (Coin 0x3333)
		0.333333333250 QUIL (Coin 0x4444)

		**Note:** Coin 0x1111 is the remainder.

	Example - Split a coin into two parts using the specified amounts:
		$ qclient token coins
		1.000000000000 QUIL (Coin 0x1234)
		$ qclient token split 0x1234 --parts 2 --part-amount 0.35
		$ qclient token coins
		0.300000000000 QUIL (Coin 0x1111)
		0.350000000000 QUIL (Coin 0x2222)
		0.350000000000 QUIL (Coin 0x3333)

		**Note:** Coin 0x1111 is the remainder.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 3 && parts == 1 {
			fmt.Println("did you forget to specify <OfCoin> and <Amounts>?")
			os.Exit(1)
		}
		if len(args) < 1 && parts > 1 {
			fmt.Println("did you forget to specify <OfCoin>?")
			os.Exit(1)
		}
		if len(args) > 1 && parts > 1 {
			fmt.Println("-p/--parts can't be combined with <Amounts>")
			os.Exit(1)
		}
		if len(args) > 1 && partAmount != "" {
			fmt.Println("-a/--part-amount can't be combined with <Amounts>")
			os.Exit(1)
		}
		if parts > 100 {
			fmt.Println("too many parts, maximum is 100")
			os.Exit(1)
		}

		payload := []byte("split")
		coinaddrHex, _ := strings.CutPrefix(args[0], "0x")
		coinaddr, err := hex.DecodeString(coinaddrHex)
		if err != nil {
			panic(err)
		}
		coin := &protobufs.CoinRef{
			Address: coinaddr,
		}
		payload = append(payload, coinaddr...)

		// Get the amount of the coin to be split
		totalAmount := getCoinAmount(coinaddr)

		amounts := [][]byte{}

		// Split the coin into the user specified amounts
		if parts == 1 {
			amounts, payload, err = Split(args[1:], amounts, payload, totalAmount)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		// Split the coin into parts
		if parts > 1 && partAmount == "" {
			amounts, payload = SplitIntoParts(amounts, payload, totalAmount, parts)
		}

		// Split the coin into parts of the user specified amount
		if parts > 1 && partAmount != "" {
			amounts, payload, err = SplitIntoPartsAmount(amounts, payload, totalAmount, parts, partAmount)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		key, err := utils.GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
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
				Request: &protobufs.TokenRequest_Split{
					Split: &protobufs.SplitCoinRequest{
						OfCoin:  coin,
						Amounts: amounts,
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
	},
}

func init() {
	splitCmd.Flags().IntVarP(&parts, "parts", "p", 1, "number of parts to split the coin into")
	splitCmd.Flags().StringVarP(&partAmount, "part-amount", "a", "", "amount of each part")
	TokenCmd.AddCommand(splitCmd)
}

func Split(args []string, amounts [][]byte, payload []byte, totalAmount *big.Int) ([][]byte, []byte, error) {
	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
	inputAmount := new(big.Int)
	for _, amt := range args {
		amount, err := decimal.NewFromString(amt)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid amount, must be a decimal number like 0.02 or 2")
		}
		amount = amount.Mul(decimal.NewFromBigInt(conversionFactor, 0))
		inputAmount = inputAmount.Add(inputAmount, amount.BigInt())
		amountBytes := amount.BigInt().FillBytes(make([]byte, 32))
		amounts = append(amounts, amountBytes)
		payload = append(payload, amountBytes...)
	}

	// Check if the user specified amounts sum to the total amount of the coin
	if inputAmount.Cmp(totalAmount) != 0 {
		return nil, nil, fmt.Errorf("the specified amounts must sum to the total amount of the coin")
	}
	return amounts, payload, nil
}

func SplitIntoParts(amounts [][]byte, payload []byte, totalAmount *big.Int, parts int) ([][]byte, []byte) {
	amount := new(big.Int).Div(totalAmount, big.NewInt(int64(parts)))
	amountBytes := amount.FillBytes(make([]byte, 32))
	for i := int64(0); i < int64(parts); i++ {
		amounts = append(amounts, amountBytes)
		payload = append(payload, amountBytes...)
	}

	// If there is a remainder, we need to add it as a separate amount
	// because the amounts must sum to the original coin amount.
	remainder := new(big.Int).Mod(totalAmount, big.NewInt(int64(parts)))
	if remainder.Cmp(big.NewInt(0)) != 0 {
		remainderBytes := remainder.FillBytes(make([]byte, 32))
		amounts = append(amounts, remainderBytes)
		payload = append(payload, remainderBytes...)
	}
	return amounts, payload
}

func SplitIntoPartsAmount(amounts [][]byte, payload []byte, totalAmount *big.Int, parts int, partAmount string) ([][]byte, []byte, error) {
	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
	amount, err := decimal.NewFromString(partAmount)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid amount, must be a decimal number like 0.02 or 2")
	}
	amount = amount.Mul(decimal.NewFromBigInt(conversionFactor, 0))
	inputAmount := new(big.Int).Mul(amount.BigInt(), big.NewInt(int64(parts)))
	amountBytes := amount.BigInt().FillBytes(make([]byte, 32))
	for i := int64(0); i < int64(parts); i++ {
		amounts = append(amounts, amountBytes)
		payload = append(payload, amountBytes...)
	}

	// If there is a remainder, we need to add it as a separate amount
	// because the amounts must sum to the original coin amount.
	remainder := new(big.Int).Sub(totalAmount, inputAmount)
	if remainder.Cmp(big.NewInt(0)) != 0 {
		remainderBytes := remainder.FillBytes(make([]byte, 32))
		amounts = append(amounts, remainderBytes)
		payload = append(payload, remainderBytes...)
	}

	// Check if the user specified amounts sum to the total amount of the coin
	if new(big.Int).Add(inputAmount, new(big.Int).Abs(remainder)).Cmp(totalAmount) != 0 {
		return nil, nil, fmt.Errorf("the specified amounts must sum to the total amount of the coin")
	}
	return amounts, payload, nil
}

func getCoinAmount(coinaddr []byte) *big.Int {
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

	var amount *big.Int
	for i, coin := range resp.Coins {
		if bytes.Equal(resp.Addresses[i], coinaddr) {
			amount = new(big.Int).SetBytes(coin.Amount)
		}
	}
	for i, coin := range resp2.Coins {
		if bytes.Equal(resp.Addresses[i], coinaddr) {
			amount = new(big.Int).SetBytes(coin.Amount)
		}
	}
	return amount
}
