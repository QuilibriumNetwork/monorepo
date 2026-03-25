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

var allocationStatusNames = map[uint32]string{
	0: "Unknown",
	1: "Joining",
	2: "Active",
	3: "Paused",
	4: "Leaving",
	5: "Rejected",
	6: "Kicked",
}

var NodeProverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "List prover status and shard allocations",
	Long: `Displays the current prover status including seniority, workers,
and shard allocations.

	status
	`,
	Run: func(cmd *cobra.Command, args []string) {
		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		info, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Peer ID:            %s\n", info.GetPeerId())

		version := info.GetVersion()
		if len(version) >= 3 {
			fmt.Printf("Version:            %d.%d.%d", version[0], version[1], version[2])
			patch := info.GetPatchNumber()
			if len(patch) > 0 {
				fmt.Printf(".%d", patch[0])
			}
			fmt.Println()
		}

		seniority := info.GetPeerSeniority()
		if len(seniority) > 0 {
			s := new(big.Int).SetBytes(seniority)
			fmt.Printf("Seniority:          %s\n", s.String())
		}

		fmt.Printf("Peer Score:         %d\n", info.GetPeerScore())
		fmt.Printf("Running Workers:    %d\n", info.GetRunningWorkers())
		fmt.Printf("Allocated Workers:  %d\n", info.GetAllocatedWorkers())
		fmt.Printf("Last Received:      %d\n", info.GetLastReceivedFrame())
		fmt.Printf("Last Global Head:   %d\n", info.GetLastGlobalHeadFrame())
		fmt.Printf("Reachable:          %v\n", info.GetReachable())

		allocations := info.GetShardAllocations()
		if len(allocations) == 0 {
			fmt.Println("\nNo shard allocations")
			return
		}

		workers := workerByFilter(client)
		headFrame := info.GetLastGlobalHeadFrame()

		fmt.Printf("\nShard Allocations:\n")
		for i, alloc := range allocations {
			// Skip expired joins (implicitly rejected after 720 frames)
			if alloc.GetStatus() == 1 && alloc.GetJoinFrameNumber() > 0 &&
				headFrame >= alloc.GetJoinFrameNumber()+720 {
				continue
			}
			// Skip expired leaves (implicitly left after 720 frames)
			if alloc.GetStatus() == 4 && alloc.GetLeaveFrameNumber() > 0 &&
				headFrame >= alloc.GetLeaveFrameNumber()+720 {
				continue
			}

			statusName, ok := allocationStatusNames[alloc.GetStatus()]
			if !ok {
				statusName = fmt.Sprintf("Unknown(%d)", alloc.GetStatus())
			}

			filter := alloc.GetFilter()
			filterHex := hex.EncodeToString(filter)

			workerStr := ""
			if wid, ok := workers[filterHex]; ok {
				workerStr = fmt.Sprintf("  Worker: %d", wid)
			}

			fmt.Printf("  [%d] Filter: %s  Status: %s%s\n", i, filterHex, statusName, workerStr)

			if alloc.GetJoinFrameNumber() > 0 {
				fmt.Printf("      Join Frame: %d", alloc.GetJoinFrameNumber())
				if alloc.GetJoinConfirmFrameNumber() > 0 {
					fmt.Printf("  Confirm Frame: %d", alloc.GetJoinConfirmFrameNumber())
				}
				fmt.Println()
			}
			if alloc.GetLeaveFrameNumber() > 0 {
				fmt.Printf("      Leave Frame: %d\n", alloc.GetLeaveFrameNumber())
			}
			if alloc.GetLastActiveFrameNumber() > 0 {
				fmt.Printf("      Last Active: %d\n", alloc.GetLastActiveFrameNumber())
			}
		}

		// Also display worker info
		workerInfo, err := client.GetWorkerInfo(
			context.Background(),
			&protobufs.GetWorkerInfoRequest{},
		)
		if err == nil && workerInfo != nil && len(workerInfo.GetWorkerInfo()) > 0 {
			fmt.Printf("\nWorkers (%d):\n", len(workerInfo.GetWorkerInfo()))
			for _, w := range workerInfo.GetWorkerInfo() {
				filterHex := hex.EncodeToString(w.GetFilter())
				fmt.Printf("  Core %d: Filter: %s  Storage: %s / %s\n",
					w.GetCoreId(),
					filterHex,
					formatStorage(w.GetAvailableStorage()),
					formatStorage(w.GetTotalStorage()),
				)
			}
		}
	},
}

func formatStorage(bytes uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	switch {
	case bytes >= tb:
		return fmt.Sprintf("%.1f TB", float64(bytes)/float64(tb))
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

