package prover

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var NodeProverShardsCmd = &cobra.Command{
	Use:   "shards",
	Short: "List shards with estimated per-frame reward",
	Long: `Displays the shards the local prover is covering along with
estimated per-frame rewards based on ring position.

	shards
	`,
	Run: func(cmd *cobra.Command, args []string) {
		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		resp, err := client.GetShardInfo(
			context.Background(),
			&protobufs.GetShardInfoRequest{IncludeAll: false},
		)
		if err != nil {
			fmt.Printf("Failed to get shard info: %v\n", err)
			os.Exit(1)
		}

		if len(resp.GetShards()) == 0 {
			fmt.Println("No allocated shards")
			return
		}

		fmt.Printf("Shard Rewards (%d shards):\n", len(resp.GetShards()))

		totalReward := big.NewInt(0)
		for _, shard := range resp.GetShards() {
			filterHex := hex.EncodeToString(shard.GetFilter())
			if len(filterHex) > 16 {
				filterHex = filterHex[:16] + "..."
			}

			reward := new(big.Int).SetBytes(shard.GetEstimatedReward())
			totalReward.Add(totalReward, reward)

			fmt.Printf("  Filter: %s  Provers: %-4d Ring: %d  Reward: ~%s QUIL/frame\n",
				filterHex,
				shard.GetActiveProvers(),
				shard.GetRing(),
				formatQUIL(reward),
			)
		}

		fmt.Printf("\nTotal estimated: ~%s QUIL/frame\n", formatQUIL(totalReward))
		fmt.Printf("Difficulty: %d  Frame: %d\n",
			resp.GetDifficulty(),
			resp.GetFrameNumber(),
		)

		worldBytes := new(big.Int).SetBytes(resp.GetWorldStateBytes())
		if worldBytes.Sign() > 0 {
			fmt.Printf("World State: %s\n", formatStorage(worldBytes.Uint64()))
		}
	},
}

// formatQUIL converts raw reward units (1 QUIL = 10^8 units) to a
// human-readable decimal string.
func formatQUIL(raw *big.Int) string {
	if raw.Sign() == 0 {
		return "0.0000"
	}

	divisor := big.NewInt(100_000_000) // 10^8
	whole := new(big.Int).Div(raw, divisor)
	frac := new(big.Int).Mod(raw, divisor)

	// Ensure the fractional part is zero-padded to 8 digits, then truncate to 4.
	fracStr := fmt.Sprintf("%08d", frac.Int64())
	return fmt.Sprintf("%s.%s", whole.String(), fracStr[:4])
}
