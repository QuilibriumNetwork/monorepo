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

		// Epoch context: the prover lifecycle is epoch-aligned (propose in
		// epoch E, confirm in E+1, take effect in E+2). Show where we are so
		// the confirm/reject windows below are interpretable.
		epochLength := info.GetEpochLengthFrames()
		curEpoch := info.GetCurrentEpoch()
		el := epochLen(epochLength)
		// Use last_received_frame as the "current frame" for effective-status
		// derivation — it is exactly the frame the node evaluated allocations
		// against, so the client's view matches the node's byte-for-byte.
		currentFrame := info.GetLastReceivedFrame()
		nextBoundary := (curEpoch + 1) * el
		fmt.Printf("Epoch:              %d  (length %d frames; next boundary @ frame %d)\n",
			curEpoch, el, nextBoundary)
		fmt.Printf("Reachable:          %v\n", info.GetReachable())

		allocations := info.GetShardAllocations()
		if len(allocations) == 0 {
			fmt.Println("\nNo shard allocations")
			return
		}

		workers := workerByFilter(client)

		fmt.Printf("\nShard Allocations:\n")
		for i, alloc := range allocations {
			eff := computeEffectiveStatus(
				alloc.GetStatus(),
				alloc.GetFilter(),
				alloc.GetJoinFrameNumber(),
				alloc.GetJoinConfirmFrameNumber(),
				alloc.GetLeaveFrameNumber(),
				alloc.GetLeaveConfirmFrameNumber(),
				alloc.GetEpoch(),
				currentFrame,
				epochLength,
			)

			filter := alloc.GetFilter()
			filterHex := hex.EncodeToString(filter)

			workerStr := ""
			if wid, ok := workers[filterHex]; ok {
				workerStr = fmt.Sprintf("  Worker: %d", wid)
			}

			fmt.Printf("  [%d] Filter: %s  Status: %s%s\n", i, filterHex, eff.String(), workerStr)

			// Confirm/reject window for a pending join or leave.
			if w, ok := allocConfirmWindow(alloc, epochLength); ok {
				fmt.Printf("      Action: %s | %s\n",
					w.label("Confirm", currentFrame, epochLength),
					w.label("Reject", currentFrame, epochLength))
			} else if eff == effActive && len(filter) > 0 {
				// Data-shard Active provers must re-confirm every epoch (X for
				// X+1). `epoch` is the highest epoch registered so far.
				fmt.Printf("      Re-confirm through epoch %d (renew before frame %d)\n",
					alloc.GetEpoch(), nextBoundary)
			} else if eff == effExpiredEpoch {
				fmt.Printf("      MISSED re-confirm (registered epoch %d < current %d) — confirm now to restore\n",
					alloc.GetEpoch(), curEpoch)
			}

			if alloc.GetJoinFrameNumber() > 0 {
				fmt.Printf("      Join Frame: %d (epoch %d)",
					alloc.GetJoinFrameNumber(), epochForFrame(alloc.GetJoinFrameNumber(), epochLength))
				if alloc.GetJoinConfirmFrameNumber() > 0 {
					fmt.Printf("  Confirm Frame: %d", alloc.GetJoinConfirmFrameNumber())
				}
				fmt.Println()
			}
			if alloc.GetLeaveFrameNumber() > 0 {
				fmt.Printf("      Leave Frame: %d (epoch %d)",
					alloc.GetLeaveFrameNumber(), epochForFrame(alloc.GetLeaveFrameNumber(), epochLength))
				if alloc.GetLeaveConfirmFrameNumber() > 0 {
					fmt.Printf("  Confirm Frame: %d", alloc.GetLeaveConfirmFrameNumber())
				}
				fmt.Println()
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

