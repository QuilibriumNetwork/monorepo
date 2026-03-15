package token

import (
	"context"
	"fmt"
	"math/big"
	"os"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var parts int
var partAmount string
var SplitCmd = &cobra.Command{
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
		if len(args) < 1 {
			fmt.Println("did you forget to specify <OfCoin>?")
			os.Exit(1)
		}
		if len(args) < 2 && parts <= 1 {
			fmt.Println("did you forget to specify <Amounts> or --parts?")
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

		coinAddr, err := parseCoinAddress(args[0])
		if err != nil {
			fmt.Printf("Invalid coin address: %v\n", err)
			os.Exit(1)
		}

		conn, err := utils.GetGRPCClient(
			LightNode,
			ClientConfig.CustomRpc,
			NodeConfig,
		)
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)

		vk, sk := getOwnKeys()

		totalAmount, err := getCoinBalance(client, vk, sk, coinAddr)
		if err != nil {
			fmt.Printf("Failed to get coin balance: %v\n", err)
			os.Exit(1)
		}

		var amounts []*big.Int

		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)

		if parts <= 1 {
			// Split into specified amounts
			for _, amt := range args[1:] {
				d, err := decimal.NewFromString(amt)
				if err != nil {
					fmt.Printf("Invalid amount '%s': must be a decimal number\n", amt)
					os.Exit(1)
				}
				amounts = append(amounts, d.Mul(decimal.NewFromBigInt(conversionFactor, 0)).BigInt())
			}

			// Verify sum
			sum := big.NewInt(0)
			for _, a := range amounts {
				sum.Add(sum, a)
			}
			if sum.Cmp(totalAmount) != 0 {
				fmt.Println("The specified amounts must sum to the total amount of the coin")
				os.Exit(1)
			}
		} else if partAmount == "" {
			// Split into N equal parts
			amount := new(big.Int).Div(totalAmount, big.NewInt(int64(parts)))
			for i := 0; i < parts; i++ {
				amounts = append(amounts, new(big.Int).Set(amount))
			}
			remainder := new(big.Int).Mod(totalAmount, big.NewInt(int64(parts)))
			if remainder.Cmp(big.NewInt(0)) != 0 {
				amounts = append(amounts, remainder)
			}
		} else {
			// Split into N parts of specified amount
			d, err := decimal.NewFromString(partAmount)
			if err != nil {
				fmt.Printf("Invalid part-amount: must be a decimal number\n")
				os.Exit(1)
			}
			amount := d.Mul(decimal.NewFromBigInt(conversionFactor, 0)).BigInt()
			for i := 0; i < parts; i++ {
				amounts = append(amounts, new(big.Int).Set(amount))
			}
			sumParts := new(big.Int).Mul(amount, big.NewInt(int64(parts)))
			remainder := new(big.Int).Sub(totalAmount, sumParts)
			if remainder.Sign() < 0 {
				fmt.Println("Total of parts exceeds coin balance")
				os.Exit(1)
			}
			if remainder.Sign() > 0 {
				amounts = append(amounts, remainder)
			}
		}

		tb, err := newTransactionBuilderFromClient(client, KeyManager)
		if err != nil {
			fmt.Printf("Failed to create transaction builder: %v\n", err)
			os.Exit(1)
		}

		tx, err := tb.BuildSplitTransaction(
			coinAddr, amounts,
			vk.Public(), sk.Public(),
		)
		if err != nil {
			fmt.Printf("Failed to build split transaction: %v\n", err)
			os.Exit(1)
		}

		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}

		provenTx, err := tb.ProveTransaction(tx, frameInfo.GetLastGlobalHeadFrame())
		if err != nil {
			fmt.Printf("Failed to prove transaction: %v\n", err)
			os.Exit(1)
		}

		err = SendTransaction(
			client,
			token.QUIL_TOKEN_ADDRESS,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Transaction{
					Transaction: provenTx,
				},
			},
			KeyManager,
		)
		if err != nil {
			fmt.Printf("Failed to send transaction: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Split transaction sent successfully (%d outputs)\n", len(amounts))
	},
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
