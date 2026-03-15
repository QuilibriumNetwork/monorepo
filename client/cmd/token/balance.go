package token

import (
	"context"
	"fmt"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

var BalanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Lists the total balance of tokens in the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := utils.GetGRPCClient(
			LightNode,
			ClientConfig.CustomRpc,
			NodeConfig,
		)
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		peerId := utils.GetPeerIDFromConfig(NodeConfig)

		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))
		info, err := client.GetTokensByAccount(
			context.Background(),
			&protobufs.GetTokensByAccountRequest{
				Address: addrBytes,
				Domain:  token.QUIL_TOKEN_ADDRESS[:],
			},
		)
		if err != nil {
			panic(err)
		}

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
		txs, err := client.GetTokensByAccount(
			context.Background(),
			&protobufs.GetTokensByAccountRequest{
				Address: slices.Concat(vk.Public(), sk.Public()),
				Domain:  token.QUIL_TOKEN_ADDRESS[:],
			},
		)
		if err != nil {
			panic(err)
		}

		sum := big.NewInt(0)
		for _, l := range info.LegacyCoins {
			sum = sum.Add(sum, new(big.Int).SetBytes(l.Coin.Amount))
		}
		for _, l := range txs.Transactions {
			sum = sum.Add(sum, new(big.Int).SetBytes(l.RawBalance))
		}
		for _, l := range txs.PendingTransactions {
			sum = sum.Add(sum, new(big.Int).SetBytes(l.RawBalance))
		}

		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		r := new(big.Rat).SetFrac(sum, conversionFactor)

		fmt.Println("Total balance:", r.FloatString(12), fmt.Sprintf(
			"QUIL (Account 0x%x)",
			slices.Concat(vk.Public(), sk.Public()),
		))
	},
}
