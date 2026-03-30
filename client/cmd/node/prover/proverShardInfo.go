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

var NodeProverShardInfoCmd = &cobra.Command{
	Use:   "shardinfo",
	Short: "List all known shards with prover counts and estimated rewards",
	Long: `Displays all known shards with the number of active provers,
estimated per-frame reward, and whether the local prover is on each shard.

	shardinfo
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
			&protobufs.GetShardInfoRequest{IncludeAll: true},
		)
		if err != nil {
			fmt.Printf("Failed to get shard info: %v\n", err)
			os.Exit(1)
		}

		if len(resp.GetShards()) == 0 {
			fmt.Println("No shards found")
			return
		}

		workers := workerByFilter(client)

		fmt.Printf("All Shards (%d shards):\n", len(resp.GetShards()))

		for _, shard := range resp.GetShards() {
			filterHex := hex.EncodeToString(shard.GetFilter())

			suffix := ""
			if shard.GetIsAllocated() {
				if wid, ok := workers[filterHex]; ok {
					suffix = fmt.Sprintf("  [Worker %d]", wid)
				} else {
					suffix = "  [ACTIVE]"
				}
			}

			shardSize := new(big.Int).SetBytes(shard.GetShardSize())
			reward := new(big.Int).SetBytes(shard.GetEstimatedReward())

			fmt.Printf("  Filter: %s  Size: %-10s Shards: %-6d Provers: %-4d Ring: %d  Reward: ~%s QUIL/frame%s\n",
				filterHex,
				formatStorage(shardSize.Uint64()),
				shard.GetDataShards(),
				shard.GetActiveProvers(),
				shard.GetRing(),
				formatQUIL(reward),
				suffix,
			)
		}

		fmt.Printf("\nDifficulty: %d  Frame: %d\n",
			resp.GetDifficulty(),
			resp.GetFrameNumber(),
		)

		worldBytes := new(big.Int).SetBytes(resp.GetWorldStateBytes())
		if worldBytes.Sign() > 0 {
			fmt.Printf("World State: %s\n", formatStorage(worldBytes.Uint64()))
		}

		basis := new(big.Int).SetBytes(resp.GetPomwBasis())
		if basis.Sign() > 0 {
			fmt.Printf("PomW Basis: %s\n", basis.String())
		}
	},
}
