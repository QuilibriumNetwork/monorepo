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

var CoinsCmd = &cobra.Command{
	Use:   "coins",
	Short: "Lists all coins under control of the managing account",
	Long: `Lists all coins under control of the managing account.

	coins [domain]
	`,
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

		// Fetch legacy coins by peer ID address
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

		// Fetch coins by view+spend key
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

		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		count := 0

		for _, l := range info.LegacyCoins {
			amount := new(big.Int).SetBytes(l.Coin.Amount)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			fmt.Printf(
				"%s QUIL (Legacy Coin 0x%x)\n",
				r.FloatString(12),
				l.Address,
			)
			count++
		}

		for _, l := range txs.Transactions {
			amount := new(big.Int).SetBytes(l.RawBalance)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			fmt.Printf(
				"%s QUIL (Coin 0x%x)\n",
				r.FloatString(12),
				l.Address,
			)
			count++
		}

		for _, l := range txs.PendingTransactions {
			amount := new(big.Int).SetBytes(l.RawBalance)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			fmt.Printf(
				"%s QUIL (Pending 0x%x)\n",
				r.FloatString(12),
				l.Address,
			)
			count++
		}

		if count == 0 {
			fmt.Println("No coins found")
		}
	},
}
