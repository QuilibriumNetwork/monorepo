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

		workers := workerByFilter(client)

		fmt.Printf("Shard Rewards (%d shards):\n", len(resp.GetShards()))

		totalReward := big.NewInt(0)
		for _, shard := range resp.GetShards() {
			filterHex := hex.EncodeToString(shard.GetFilter())

			workerStr := ""
			if wid, ok := workers[filterHex]; ok {
				workerStr = fmt.Sprintf("  Worker: %d", wid)
			}

			reward := new(big.Int).SetBytes(shard.GetEstimatedReward())
			totalReward.Add(totalReward, reward)

			fmt.Printf("  Filter: %s  Shards: %-6d Provers: %-4d Ring: %d  Reward: ~%s QUIL/frame%s\n",
				filterHex,
				shard.GetDataShards(),
				shard.GetActiveProvers(),
				shard.GetRing(),
				formatQUIL(reward),
				workerStr,
			)
		}

		fmt.Printf("\nTotal estimated: ~%s QUIL/frame (~%s QUIL/day)\n",
			formatQUIL(totalReward), formatQUILDaily(totalReward))
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
// human-readable decimal string with full precision.
func formatQUIL(raw *big.Int) string {
	if raw.Sign() == 0 {
		return "0.00000000"
	}

	divisor := big.NewInt(100_000_000) // 10^8
	whole := new(big.Int).Div(raw, divisor)
	frac := new(big.Int).Mod(raw, divisor)

	return fmt.Sprintf("%s.%08d", whole.String(), frac.Int64())
}

// framesPerDay is the expected number of frames in 24 hours at the target
// frame time of 10 seconds.
const framesPerDay = 24 * 60 * 60 / 10 // 8640

// formatQUILDaily converts a per-frame reward to an estimated 24hr total.
func formatQUILDaily(perFrame *big.Int) string {
	daily := new(big.Int).Mul(perFrame, big.NewInt(framesPerDay))
	return formatQUIL(daily)
}
