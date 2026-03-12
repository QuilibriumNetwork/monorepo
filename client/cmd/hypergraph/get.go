package hypergraph

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var GetCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve hypergraph data",
	Long:  `Retrieve vertex or hyperedge data from the hypergraph.`,
}

var GetVertexCmd = &cobra.Command{
	Use:   "vertex <FullAddress|Alias>",
	Short: "Retrieve and display vertex data",
	Long:  `Retrieves and displays vertex data from the hypergraph.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		addressBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("address: %w", err)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		resp, err := client.GetVertexData(
			context.Background(),
			&protobufs.GetVertexDataRequest{Address: addressBytes},
		)
		if err != nil {
			return fmt.Errorf("get vertex data: %w", err)
		}

		fmt.Printf("Address: %s\n", hex.EncodeToString(addressBytes))
		fmt.Printf("Type:    %s/%s\n", resp.SetType, resp.PhaseType)
		fmt.Printf("Shard:   L1=%s L2=%s\n",
			hex.EncodeToString(resp.ShardL1),
			hex.EncodeToString(resp.ShardL2),
		)
		fmt.Printf("Entries (%d):\n", len(resp.Entries))
		for i, entry := range resp.Entries {
			fmt.Printf("  [%d] %s = %s\n", i,
				hex.EncodeToString(entry.Key),
				hex.EncodeToString(entry.Value),
			)
		}

		return nil
	},
}

var GetHyperedgeCmd = &cobra.Command{
	Use:   "hyperedge <FullAddress|Alias>",
	Short: "Retrieve and display hyperedge data",
	Long:  `Retrieves and displays hyperedge extrinsic data from the hypergraph.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		addressBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("address: %w", err)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		resp, err := client.GetHyperedgeData(
			context.Background(),
			&protobufs.GetHyperedgeDataRequest{Address: addressBytes},
		)
		if err != nil {
			return fmt.Errorf("get hyperedge data: %w", err)
		}

		fmt.Printf("Address: %s\n", hex.EncodeToString(addressBytes))
		fmt.Printf("Type:    %s/%s\n", resp.SetType, resp.PhaseType)
		fmt.Printf("Shard:   L1=%s L2=%s\n",
			hex.EncodeToString(resp.ShardL1),
			hex.EncodeToString(resp.ShardL2),
		)
		fmt.Printf("Entries (%d):\n", len(resp.Entries))
		for i, entry := range resp.Entries {
			fmt.Printf("  [%d] %s = %s\n", i,
				hex.EncodeToString(entry.Key),
				hex.EncodeToString(entry.Value),
			)
		}

		return nil
	},
}

func init() {
	GetCmd.AddCommand(GetVertexCmd)
	GetCmd.AddCommand(GetHyperedgeCmd)
}
