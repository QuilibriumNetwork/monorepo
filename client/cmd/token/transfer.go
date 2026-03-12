package token

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	chg "source.quilibrium.com/quilibrium/monorepo/client/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

var expiration string

var TransferCmd = &cobra.Command{
	Use:   "transfer <ToAccount> [RefundAccount] <OfCoin|Amount>",
	Short: "Creates a transfer of coin",
	Long: `Creates a transfer of coin with optional refund account and expiration.

Basic usage:
	transfer <ToAccount> <OfCoin|Amount>

With refund account (creates pending transaction):
	transfer <ToAccount> <RefundAccount> <OfCoin|Amount>

ToAccount and RefundAccount format: viewkey:spendkey (in hex)
OfCoin: a 0x-prefixed hex coin address
Amount: a decimal QUIL amount like 1.5`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		toAccount := args[0]
		var refundAccount, ofCoinOrAmount string

		if len(args) == 2 {
			ofCoinOrAmount = args[1]
		} else if len(args) == 3 {
			refundAccount = args[1]
			ofCoinOrAmount = args[2]
		} else {
			fmt.Println("Invalid number of arguments")
			cmd.Help()
			return
		}

		// Parse recipient account (viewkey:spendkey)
		toViewKey, toSpendKey, err := parseAccount(toAccount)
		if err != nil {
			fmt.Printf("Invalid ToAccount: %v\n", err)
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

		// Get own keys
		vk, sk := getOwnKeys()

		// Build the transaction builder
		tb, err := newTransactionBuilderFromClient(client, KeyManager)
		if err != nil {
			fmt.Printf("Failed to create transaction builder: %v\n", err)
			os.Exit(1)
		}

		// Get the current frame number
		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}
		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		// Determine if this is a coin address or an amount
		if isCoinAddress(ofCoinOrAmount) {
			coinAddr, err := parseCoinAddress(ofCoinOrAmount)
			if err != nil {
				fmt.Printf("Invalid coin address: %v\n", err)
				os.Exit(1)
			}

			// Get the coin balance to determine the amount
			amount, err := getCoinBalance(client, vk, sk, coinAddr)
			if err != nil {
				fmt.Printf("Failed to get coin balance: %v\n", err)
				os.Exit(1)
			}

			if refundAccount != "" {
				refundViewKey, refundSpendKey, err := parseAccount(refundAccount)
				if err != nil {
					fmt.Printf("Invalid RefundAccount: %v\n", err)
					os.Exit(1)
				}

				var expirationFrame uint64
				if expiration != "" {
					expirationFrame, err = strconv.ParseUint(expiration, 10, 64)
					if err != nil {
						fmt.Printf("Invalid expiration: %v\n", err)
						os.Exit(1)
					}
				} else {
					expirationFrame = frameNumber + 200
				}

				pendingTx, err := tb.BuildPendingTransaction(
					coinAddr, amount,
					toViewKey, toSpendKey,
					refundViewKey, refundSpendKey,
					expirationFrame,
				)
				if err != nil {
					fmt.Printf("Failed to build pending transaction: %v\n", err)
					os.Exit(1)
				}

				provenTx, err := tb.ProvePendingTransaction(pendingTx, frameNumber)
				if err != nil {
					fmt.Printf("Failed to prove pending transaction: %v\n", err)
					os.Exit(1)
				}

				err = SendTransaction(
					client,
					token.QUIL_TOKEN_ADDRESS,
					&protobufs.MessageRequest{
						Request: &protobufs.MessageRequest_PendingTransaction{
							PendingTransaction: provenTx,
						},
					},
					KeyManager,
				)
				if err != nil {
					fmt.Printf("Failed to send transaction: %v\n", err)
					os.Exit(1)
				}

				fmt.Println("Pending transfer sent successfully")
			} else {
				tx, err := tb.BuildTransferTransaction(
					coinAddr, amount,
					toViewKey, toSpendKey,
				)
				if err != nil {
					fmt.Printf("Failed to build transaction: %v\n", err)
					os.Exit(1)
				}

				provenTx, err := tb.ProveTransaction(tx, frameNumber)
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

				fmt.Println("Transfer sent successfully")
			}
		} else {
			// Parse as amount
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			d, err := decimal.NewFromString(ofCoinOrAmount)
			if err != nil {
				fmt.Printf("Invalid amount: %v\n", err)
				os.Exit(1)
			}
			amount := d.Mul(decimal.NewFromBigInt(conversionFactor, 0)).BigInt()

			// Find coins that cover the amount
			coinAddr, coinAmount, err := findCoinForAmount(client, vk, sk, amount)
			if err != nil {
				fmt.Printf("Failed to find coin: %v\n", err)
				os.Exit(1)
			}

			if coinAmount.Cmp(amount) == 0 {
				// Exact match - just transfer
				tx, err := tb.BuildTransferTransaction(
					coinAddr, amount,
					toViewKey, toSpendKey,
				)
				if err != nil {
					fmt.Printf("Failed to build transaction: %v\n", err)
					os.Exit(1)
				}

				provenTx, err := tb.ProveTransaction(tx, frameNumber)
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

				fmt.Println("Transfer sent successfully")
			} else {
				// Need to split: send amount to recipient, remainder to self
				remainder := new(big.Int).Sub(coinAmount, amount)
				amounts := []*big.Int{amount, remainder}
				viewKeys := [][]byte{toViewKey, vk.Public()}
				spendKeys := [][]byte{toSpendKey, sk.Public()}

				// Build as multi-output transaction
				input, err := token.NewTransactionInput(coinAddr)
				if err != nil {
					fmt.Printf("Failed to create input: %v\n", err)
					os.Exit(1)
				}

				outputs := make([]*token.TransactionOutput, 2)
				fees := make([]*big.Int, 2)
				for i := 0; i < 2; i++ {
					out, err := token.NewTransactionOutput(
						amounts[i], viewKeys[i], spendKeys[i],
					)
					if err != nil {
						fmt.Printf("Failed to create output: %v\n", err)
						os.Exit(1)
					}
					outputs[i] = out
					fees[i] = big.NewInt(0)
				}

				tx := token.NewTransaction(
					tb.domain,
					[]*token.TransactionInput{input},
					outputs,
					fees,
					tb.config,
					tb.hypergraph,
					tb.bulletproofProver,
					tb.inclusionProver,
					tb.verEnc,
					tb.decafConstructor,
					tb.keyRing,
					tb.rdfSchema,
					tb.rdfMultiprover,
				)

				provenTx, err := tb.ProveTransaction(tx, frameNumber)
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

				fmt.Println("Transfer sent successfully (with change output)")
			}
		}
	},
}

func parseAccount(account string) (viewKey, spendKey []byte, err error) {
	parts := strings.Split(account, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("expected viewkey:spendkey format")
	}

	viewKey, err = hex.DecodeString(strings.TrimPrefix(parts[0], "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid view key: %w", err)
	}

	spendKey, err = hex.DecodeString(strings.TrimPrefix(parts[1], "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid spend key: %w", err)
	}

	return viewKey, spendKey, nil
}

func parseCoinAddress(addr string) ([]byte, error) {
	addrHex := strings.TrimPrefix(addr, "0x")
	coinAddr, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(coinAddr) != 64 {
		return nil, fmt.Errorf("expected 64-byte address, got %d", len(coinAddr))
	}
	return coinAddr, nil
}

func isCoinAddress(s string) bool {
	trimmed := strings.TrimPrefix(s, "0x")
	if len(trimmed) != 128 {
		return false
	}
	_, err := hex.DecodeString(trimmed)
	return err == nil
}

func getOwnKeys() (crypto.Agreement, crypto.Agreement) {
	vk, err := KeyManager.GetAgreementKey("q-view-key")
	if err != nil {
		vk, err = KeyManager.CreateAgreementKey(
			"q-view-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			panic(err)
		}
	}

	sk, err := KeyManager.GetAgreementKey("q-spend-key")
	if err != nil {
		sk, err = KeyManager.CreateAgreementKey(
			"q-spend-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			panic(err)
		}
	}

	return vk, sk
}

func getCoinBalance(
	client protobufs.NodeServiceClient,
	vk, sk crypto.Agreement,
	coinAddr []byte,
) (*big.Int, error) {
	txs, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address: slices.Concat(vk.Public(), sk.Public()),
			Domain:  token.QUIL_TOKEN_ADDRESS[:],
		},
	)
	if err != nil {
		return nil, err
	}

	for _, t := range txs.Transactions {
		if slices.Equal(t.Address, coinAddr) {
			return new(big.Int).SetBytes(t.RawBalance), nil
		}
	}
	for _, t := range txs.PendingTransactions {
		if slices.Equal(t.Address, coinAddr) {
			return new(big.Int).SetBytes(t.RawBalance), nil
		}
	}

	return nil, fmt.Errorf("coin 0x%x not found", coinAddr)
}

func findCoinForAmount(
	client protobufs.NodeServiceClient,
	vk, sk crypto.Agreement,
	amount *big.Int,
) (coinAddr []byte, coinAmount *big.Int, err error) {
	txs, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address: slices.Concat(vk.Public(), sk.Public()),
			Domain:  token.QUIL_TOKEN_ADDRESS[:],
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// Try exact match first
	for _, t := range txs.Transactions {
		bal := new(big.Int).SetBytes(t.RawBalance)
		if bal.Cmp(amount) == 0 {
			return t.Address, bal, nil
		}
	}

	// Find smallest coin >= amount
	var bestAddr []byte
	var bestAmount *big.Int
	for _, t := range txs.Transactions {
		bal := new(big.Int).SetBytes(t.RawBalance)
		if bal.Cmp(amount) >= 0 {
			if bestAmount == nil || bal.Cmp(bestAmount) < 0 {
				bestAddr = t.Address
				bestAmount = bal
			}
		}
	}

	if bestAddr == nil {
		return nil, nil, fmt.Errorf("no coin with sufficient balance found")
	}

	return bestAddr, bestAmount, nil
}

func newTransactionBuilderFromClient(
	client protobufs.NodeServiceClient,
	keyManager tkeys.KeyManager,
) (*TransactionBuilder, error) {
	logger, _ := zap.NewProduction()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	bulletproofProver := bulletproofs.NewBulletproofProver()
	decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	verEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	var domain [32]byte
	copy(domain[:], token.QUIL_TOKEN_ADDRESS[:32])

	hg := chg.NewRemoteHypergraph(client, inclusionProver, domain)

	return NewTransactionBuilder(
		keyManager,
		hg,
		bulletproofProver,
		inclusionProver,
		verEncryptor,
		decafConstructor,
	)
}
