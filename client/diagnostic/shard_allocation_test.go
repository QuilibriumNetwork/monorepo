package diagnostic

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/shopspring/decimal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// scoreShardRewardGreedy replicates the RewardGreedy scoring from
// node/consensus/provers/proposer.go:scoreShards without importing the node
// module (which has FFI link deps that prevent local test execution).
func scoreShardRewardGreedy(
	sizeBytes uint64,
	basis *big.Int,
	worldBytes *big.Int,
	ring uint8,
	dataShards uint64,
) *big.Int {
	if sizeBytes == 0 {
		return big.NewInt(0)
	}
	if dataShards == 0 {
		dataShards = 1
	}

	factor := decimal.NewFromUint64(sizeBytes)
	factor = factor.Mul(decimal.NewFromBigInt(basis, 0))
	factor = factor.Div(decimal.NewFromBigInt(worldBytes, 0))

	divisor := int64(1)
	for j := uint8(0); j < ring+1; j++ {
		divisor <<= 1
	}
	if divisor == 0 {
		return big.NewInt(0)
	}

	ringDiv := decimal.NewFromInt(divisor)

	shardsSqrt, err := decimal.NewFromUint64(dataShards).PowWithPrecision(
		decimal.NewFromBigRat(big.NewRat(1, 2), 53),
		53,
	)
	if err != nil || shardsSqrt.IsZero() {
		return big.NewInt(0)
	}

	factor = factor.Div(ringDiv)
	factor = factor.Div(shardsSqrt)
	return factor.BigInt()
}

// TestMainnetShardAllocationDiagnostic fetches live shard data from mainnet
// and runs the scoring + allocation pipeline to identify why certain shards
// never receive prover allocations.
//
// Run with:
//
//	cd client && go test -run TestMainnetShardAllocationDiagnostic -v -timeout 60s ./diagnostic/
func TestMainnetShardAllocationDiagnostic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mainnet diagnostic in short mode")
	}

	// --- 1. Fetch shard data ---
	// QUIL_RPC overrides the target. Default is localhost for a local node.
	// Set QUIL_RPC=rpc.quilibrium.com:8337 for the public mainnet endpoint.
	addr := os.Getenv("QUIL_RPC")
	if addr == "" {
		addr = "localhost:8337"
	}

	// Use TLS for known remote endpoints, insecure for localhost.
	var creds grpc.DialOption
	if addr == "localhost:8337" || addr == "127.0.0.1:8337" {
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		creds = grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{InsecureSkipVerify: false}),
		)
	}

	t.Logf("Connecting to %s ...", addr)
	conn, err := grpc.Dial(
		addr,
		creds,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(100*1024*1024),
			grpc.MaxCallRecvMsgSize(100*1024*1024),
		),
	)
	if err != nil {
		t.Fatalf("failed to connect to RPC at %s: %v", addr, err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.GetShardInfo(ctx, &protobufs.GetShardInfoRequest{
		IncludeAll: true,
	})
	if err != nil {
		t.Skipf("GetShardInfo failed (is a node running at %s?): %v", addr, err)
	}

	shards := resp.GetShards()
	difficulty := resp.GetDifficulty()
	worldBytes := new(big.Int).SetBytes(resp.GetWorldStateBytes())
	frameNumber := resp.GetFrameNumber()
	basis := new(big.Int).SetBytes(resp.GetPomwBasis())

	t.Logf("=== Mainnet Shard Snapshot ===")
	t.Logf("Frame:       %d", frameNumber)
	t.Logf("Difficulty:  %d", difficulty)
	t.Logf("World bytes: %s (%s)", worldBytes.String(), fmtStorage(worldBytes.Uint64()))
	t.Logf("PomW basis:  %s", basis.String())
	t.Logf("Total shards returned: %d", len(shards))

	if len(shards) == 0 {
		t.Fatal("no shards returned from mainnet")
	}

	// --- 2. Classify and score each shard ---
	type shardInfo struct {
		filter        string
		sizeBytes     uint64
		activeProvers uint32
		ring          uint32
		reward        *big.Int
		isAllocated   bool
		score         *big.Int
	}

	all := make([]shardInfo, 0, len(shards))
	for _, s := range shards {
		sizeBI := new(big.Int).SetBytes(s.GetShardSize())
		rewardBI := new(big.Int).SetBytes(s.GetEstimatedReward())

		score := scoreShardRewardGreedy(
			sizeBI.Uint64(), basis, worldBytes,
			uint8(s.GetRing()), 1, // DataShards not exposed via RPC, assume 1
		)

		all = append(all, shardInfo{
			filter:        hex.EncodeToString(s.GetFilter()),
			sizeBytes:     sizeBI.Uint64(),
			activeProvers: s.GetActiveProvers(),
			ring:          s.GetRing(),
			reward:        rewardBI,
			isAllocated:   s.GetIsAllocated(),
			score:         score,
		})
	}

	// --- 3. Statistical breakdown ---
	var (
		allocCount         int
		unallocCount       int
		zeroProverShards   int
		lowProverShards    int // 1-3
		zeroSizeCount      int
		zeroScoreCount     int
	)
	ringDist := map[uint32]int{}
	ringUnalloc := map[uint32]int{}
	ringZeroProver := map[uint32]int{}

	for _, a := range all {
		if a.isAllocated {
			allocCount++
		} else {
			unallocCount++
			ringUnalloc[a.ring]++
		}
		ringDist[a.ring]++
		if a.sizeBytes == 0 {
			zeroSizeCount++
		}
		if a.score.Sign() == 0 {
			zeroScoreCount++
		}
		if a.activeProvers == 0 {
			zeroProverShards++
			ringZeroProver[a.ring]++
		} else if a.activeProvers <= 3 {
			lowProverShards++
		}
	}

	t.Logf("\n=== Shard Classification ===")
	t.Logf("Allocated (to queried node): %d", allocCount)
	t.Logf("Unallocated:                 %d", unallocCount)
	t.Logf("Zero provers (network-wide): %d", zeroProverShards)
	t.Logf("Low provers (1-3):           %d", lowProverShards)
	t.Logf("Zero size:                   %d", zeroSizeCount)
	t.Logf("Zero score:                  %d", zeroScoreCount)

	// --- 4. Ring distribution ---
	t.Logf("\n=== Ring Distribution ===")
	ringKeys := sortedKeys(ringDist)
	for _, r := range ringKeys {
		t.Logf("  Ring %d: %4d total, %4d unalloc, %4d zero-prover",
			r, ringDist[r], ringUnalloc[r], ringZeroProver[r])
	}

	// --- 5. Score distribution and 67% threshold analysis ---
	sort.Slice(all, func(i, j int) bool {
		return all[i].score.Cmp(all[j].score) > 0
	})

	var bestScore *big.Int
	for _, a := range all {
		if a.score.Sign() > 0 {
			if bestScore == nil || a.score.Cmp(bestScore) > 0 {
				bestScore = new(big.Int).Set(a.score)
			}
		}
	}

	if bestScore == nil || bestScore.Sign() == 0 {
		t.Fatal("no shard has a positive score")
	}

	threshold67 := new(big.Int).Mul(bestScore, big.NewInt(67))
	threshold67.Div(threshold67, big.NewInt(100))

	above := 0
	below := 0
	for _, a := range all {
		if a.score.Sign() == 0 {
			continue
		}
		if a.score.Cmp(threshold67) >= 0 {
			above++
		} else {
			below++
		}
	}

	t.Logf("\n=== 67%% Threshold Analysis ===")
	t.Logf("Best score:        %s", bestScore.String())
	t.Logf("67%% threshold:     %s", threshold67.String())
	t.Logf("Above threshold:   %d shards (would be confirmed)", above)
	t.Logf("Below threshold:   %d shards (would be REJECTED)", below)
	t.Logf("Zero score:        %d shards (skipped)", zeroScoreCount)

	// --- 6. Top and bottom shards ---
	t.Logf("\n=== Top 20 Shards by Score ===")
	showN := min(20, len(all))
	for i := 0; i < showN; i++ {
		a := all[i]
		pct := pctOfBest(a.score, bestScore)
		t.Logf("  %s  size=%-10s provers=%-4d ring=%d score=%-20s (%3d%%) reward=%s alloc=%v",
			truncHex(a.filter), fmtStorage(a.sizeBytes), a.activeProvers,
			a.ring, a.score.String(), pct, fmtQUIL(a.reward), a.isAllocated)
	}

	// Find boundary around threshold
	t.Logf("\n=== Shards Near 67%% Threshold ===")
	threshIdx := -1
	for i, a := range all {
		if a.score.Cmp(threshold67) < 0 {
			threshIdx = i
			break
		}
	}
	if threshIdx > 0 {
		start := max(0, threshIdx-5)
		end := min(len(all), threshIdx+10)
		for i := start; i < end; i++ {
			a := all[i]
			pct := pctOfBest(a.score, bestScore)
			marker := "   "
			if i == threshIdx {
				marker = ">>>"
			}
			t.Logf("%s %s  size=%-10s provers=%-4d ring=%d score=%-20s (%3d%%)",
				marker, truncHex(a.filter), fmtStorage(a.sizeBytes), a.activeProvers,
				a.ring, a.score.String(), pct)
		}
	}

	// --- 7. Simulate DecideJoins ---
	// Build the "decideCandidates" list: unallocated shards + pending shards.
	// In practice, proposalDescriptors = unallocated shards, and
	// decideCandidates = proposalDescriptors + pending shards. The bestScore
	// is computed from ALL of decideCandidates.
	t.Logf("\n=== DecideJoins Simulation ===")

	// Filter to just unallocated non-zero-size shards (as proposalDescriptors)
	var unallocShards []shardInfo
	for _, a := range all {
		if !a.isAllocated && a.sizeBytes > 0 {
			unallocShards = append(unallocShards, a)
		}
	}
	t.Logf("Unallocated proposal candidates: %d", len(unallocShards))

	if len(unallocShards) > 0 {
		// Find best among unallocated
		var unallocBest *big.Int
		for _, a := range unallocShards {
			if unallocBest == nil || a.score.Cmp(unallocBest) > 0 {
				unallocBest = new(big.Int).Set(a.score)
			}
		}

		unallocThreshold := new(big.Int).Mul(unallocBest, big.NewInt(67))
		unallocThreshold.Div(unallocThreshold, big.NewInt(100))

		wouldConfirm := 0
		wouldReject := 0
		for _, a := range unallocShards {
			if a.score.Cmp(unallocThreshold) >= 0 {
				wouldConfirm++
			} else {
				wouldReject++
			}
		}

		t.Logf("Best unallocated score:   %s", unallocBest.String())
		t.Logf("67%% threshold:            %s", unallocThreshold.String())
		t.Logf("Would CONFIRM if pending: %d", wouldConfirm)
		t.Logf("Would REJECT if pending:  %d", wouldReject)

		// Score distribution buckets (relative to unallocated best)
		t.Logf("\n=== Unallocated Score Distribution ===")
		type bucket struct {
			label    string
			minPct   int64
			maxPct   int64
			count    int
			zeroProvers int
		}
		buckets := []bucket{
			{"90-100%%", 90, 101, 0, 0},
			{"80-90%%", 80, 90, 0, 0},
			{"67-80%%  (confirm zone)", 67, 80, 0, 0},
			{"50-67%%  (REJECT zone)", 50, 67, 0, 0},
			{"25-50%%  (REJECT zone)", 25, 50, 0, 0},
			{"10-25%%  (REJECT zone)", 10, 25, 0, 0},
			{" 1-10%%  (REJECT zone)", 1, 10, 0, 0},
			{"  <1%%   (REJECT zone)", 0, 1, 0, 0},
		}
		for _, a := range unallocShards {
			pct := pctOfBest(a.score, unallocBest)
			for bi := range buckets {
				if pct >= buckets[bi].minPct && pct < buckets[bi].maxPct {
					buckets[bi].count++
					if a.activeProvers == 0 {
						buckets[bi].zeroProvers++
					}
					break
				}
			}
		}
		for _, b := range buckets {
			if b.count > 0 {
				t.Logf("  %s: %4d shards (%d with zero provers)", b.label, b.count, b.zeroProvers)
			}
		}

		// Analyze rejected shards: what makes them score low?
		if wouldReject > 0 {
			t.Logf("\n=== Rejected Shard Characteristics ===")

			var rejected []shardInfo
			for _, a := range unallocShards {
				if a.score.Cmp(unallocThreshold) < 0 {
					rejected = append(rejected, a)
				}
			}

			// By ring
			rejByRing := map[uint32]int{}
			for _, r := range rejected {
				rejByRing[r.ring]++
			}
			t.Logf("Rejected by ring:")
			for _, r := range sortedKeys(rejByRing) {
				t.Logf("  Ring %d: %d rejected", r, rejByRing[r])
			}

			// By size bucket
			t.Logf("Rejected by size:")
			type sizeBucket struct {
				label string
				min   uint64
				max   uint64
				count int
			}
			sBuckets := []sizeBucket{
				{">1GB", 1 << 30, ^uint64(0), 0},
				{"100MB-1GB", 100 << 20, 1 << 30, 0},
				{"10MB-100MB", 10 << 20, 100 << 20, 0},
				{"1MB-10MB", 1 << 20, 10 << 20, 0},
				{"100KB-1MB", 100 << 10, 1 << 20, 0},
				{"<100KB", 0, 100 << 10, 0},
			}
			for _, r := range rejected {
				for bi := range sBuckets {
					if r.sizeBytes >= sBuckets[bi].min && r.sizeBytes < sBuckets[bi].max {
						sBuckets[bi].count++
						break
					}
				}
			}
			for _, b := range sBuckets {
				if b.count > 0 {
					t.Logf("  %s: %d rejected", b.label, b.count)
				}
			}

			// Show a few examples
			sort.Slice(rejected, func(i, j int) bool {
				return rejected[i].score.Cmp(rejected[j].score) > 0
			})
			showN := min(20, len(rejected))
			t.Logf("\nTop %d rejected (closest to threshold):", showN)
			for i := 0; i < showN; i++ {
				r := rejected[i]
				pct := pctOfBest(r.score, unallocBest)
				t.Logf("  %s size=%-10s provers=%-4d ring=%d score=%s (%d%%)",
					truncHex(r.filter), fmtStorage(r.sizeBytes), r.activeProvers, r.ring,
					r.score.String(), pct)
			}

			if len(rejected) > showN {
				t.Logf("\nBottom 10 rejected (worst):")
				bottom := max(showN, len(rejected)-10)
				for i := bottom; i < len(rejected); i++ {
					r := rejected[i]
					pct := pctOfBest(r.score, unallocBest)
					t.Logf("  %s size=%-10s provers=%-4d ring=%d score=%s (%d%%)",
						truncHex(r.filter), fmtStorage(r.sizeBytes), r.activeProvers, r.ring,
						r.score.String(), pct)
				}
			}
		}
	}

	// --- 8. DataShards impact analysis ---
	// The RPC doesn't expose DataShards, but if a shard has been split into
	// multiple data shards, each sub-shard's score gets divided by
	// sqrt(DataShards). We can detect this by comparing the RPC-reported
	// estimated_reward with what we'd compute at DataShards=1. If the actual
	// reward is significantly lower, DataShards > 1 is the likely cause.
	t.Logf("\n=== DataShards Impact (reward anomalies) ===")
	anomalies := 0
	for _, a := range all {
		if a.sizeBytes == 0 || a.reward.Sign() == 0 {
			continue
		}
		// Expected reward at ring=a.ring, dataShards=1
		expected := scoreShardRewardGreedy(a.sizeBytes, basis, worldBytes, uint8(a.ring), 1)
		if expected.Sign() == 0 {
			continue
		}
		ratio := new(big.Int).Mul(a.reward, big.NewInt(100))
		ratio.Div(ratio, expected)
		// If actual reward < 40% of expected at DataShards=1, flag it
		if ratio.Int64() < 40 && anomalies < 15 {
			anomalies++
			t.Logf("  %s size=%-10s provers=%-4d ring=%d reward=%s expected(ds=1)=%s ratio=%d%%",
				truncHex(a.filter), fmtStorage(a.sizeBytes), a.activeProvers,
				a.ring, fmtQUIL(a.reward), fmtQUIL(expected), ratio.Int64())
		}
	}
	if anomalies == 0 {
		t.Logf("  (no anomalies found — DataShards=1 seems consistent)")
	}

	// --- 9. Summary ---
	t.Logf("\n" + "=" + "== DIAGNOSTIC SUMMARY ===")
	t.Logf("Total shards:      %d", len(all))
	t.Logf("Zero size (never scored): %d", zeroSizeCount)
	t.Logf("Zero provers:      %d", zeroProverShards)
	t.Logf("")
	t.Logf("The 67%% rejection threshold in DecideJoins compares every pending")
	t.Logf("join against the single best scoring shard in decideCandidates")
	t.Logf("(which is proposalDescriptors + pending shards). Any shard scoring")
	t.Logf("below 67%% of that best score gets rejected every cycle, creating")
	t.Logf("a permanent allocation gap.")
	t.Logf("")
	t.Logf("Additionally, PlanAndAllocate proposes joins for the TOP-k shards")
	t.Logf("only (k = number of free workers). If a prover has few free workers,")
	t.Logf("it will always pick the highest-scored shards and never propose for")
	t.Logf("lower-scored ones — those shards never even get to the DecideJoins")
	t.Logf("stage.")
}

// --- helpers ---

func truncHex(f string) string {
	if len(f) > 16 {
		return f[:16] + "..."
	}
	return fmt.Sprintf("%-19s", f)
}

func fmtQUIL(r *big.Int) string {
	divisor := big.NewInt(100_000_000)
	whole := new(big.Int).Div(r, divisor)
	frac := new(big.Int).Mod(r, divisor)
	fracAbs := new(big.Int).Abs(frac)
	return fmt.Sprintf("%s.%04d", whole.String(), fracAbs.Int64()/10000)
}

func fmtStorage(bytes uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

func pctOfBest(score, best *big.Int) int64 {
	if best.Sign() == 0 {
		return 0
	}
	p := new(big.Int).Mul(score, big.NewInt(100))
	p.Div(p, best)
	return p.Int64()
}

func sortedKeys(m map[uint32]int) []uint32 {
	keys := make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// TestScoreThresholdAnalysis runs without any RPC connection. It generates
// synthetic shards covering the size/ring distributions typical of mainnet
// and shows how the 67% threshold + top-k selection create permanent gaps.
//
// Run with:
//
//	cd client && go test -run TestScoreThresholdAnalysis -v ./diagnostic/
func TestScoreThresholdAnalysis(t *testing.T) {
	// --- Parameters matching typical mainnet ---
	worldBytes := new(big.Int).SetUint64(500 * 1024 * 1024 * 1024) // 500 GB
	difficulty := uint64(200_000)
	units := uint64(8_000_000_000)
	basis := pomwBasis(difficulty, worldBytes.Uint64(), units)

	t.Logf("=== Synthetic Mainnet Parameters ===")
	t.Logf("World bytes:  %s", fmtStorage(worldBytes.Uint64()))
	t.Logf("Difficulty:   %d", difficulty)
	t.Logf("PomW basis:   %s", basis.String())

	// Generate synthetic shards: a mix of sizes and rings.
	type syntheticShard struct {
		label string
		size  uint64 // bytes
		ring  uint8
		ds    uint64 // dataShards
	}

	shards := []syntheticShard{
		// Large shards at ring 0 — the "best" shards
		{"large-r0-A", 20 * 1024 * 1024 * 1024, 0, 1},
		{"large-r0-B", 15 * 1024 * 1024 * 1024, 0, 1},
		{"large-r0-C", 12 * 1024 * 1024 * 1024, 0, 1},

		// Medium shards at ring 0
		{"med-r0-A", 5 * 1024 * 1024 * 1024, 0, 1},
		{"med-r0-B", 3 * 1024 * 1024 * 1024, 0, 1},

		// Large shards at ring 1 (8-15 provers above seniority)
		{"large-r1-A", 20 * 1024 * 1024 * 1024, 1, 1},
		{"large-r1-B", 10 * 1024 * 1024 * 1024, 1, 1},

		// Small shards at ring 0
		{"small-r0-A", 1 * 1024 * 1024 * 1024, 0, 1},
		{"small-r0-B", 500 * 1024 * 1024, 0, 1},
		{"small-r0-C", 200 * 1024 * 1024, 0, 1},
		{"small-r0-D", 100 * 1024 * 1024, 0, 1},
		{"small-r0-E", 50 * 1024 * 1024, 0, 1},

		// Tiny shards at ring 0 — the "forgotten" shards
		{"tiny-r0-A", 20 * 1024 * 1024, 0, 1},
		{"tiny-r0-B", 10 * 1024 * 1024, 0, 1},
		{"tiny-r0-C", 5 * 1024 * 1024, 0, 1},
		{"tiny-r0-D", 2 * 1024 * 1024, 0, 1},
		{"tiny-r0-E", 1 * 1024 * 1024, 0, 1},
		{"tiny-r0-F", 512 * 1024, 0, 1},

		// Shards with multiple data shards (e.g. split into 4)
		{"split-r0-A", 10 * 1024 * 1024 * 1024, 0, 4},
		{"split-r0-B", 5 * 1024 * 1024 * 1024, 0, 4},

		// Medium shards at higher rings
		{"med-r2-A", 5 * 1024 * 1024 * 1024, 2, 1},
		{"med-r3-A", 5 * 1024 * 1024 * 1024, 3, 1},
	}

	// Score all shards
	type result struct {
		label string
		size  uint64
		ring  uint8
		ds    uint64
		score *big.Int
	}
	results := make([]result, 0, len(shards))
	for _, s := range shards {
		score := scoreShardRewardGreedy(s.size, basis, worldBytes, s.ring, s.ds)
		results = append(results, result{s.label, s.size, s.ring, s.ds, score})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score.Cmp(results[j].score) > 0
	})

	bestScore := results[0].score

	threshold67 := new(big.Int).Mul(bestScore, big.NewInt(67))
	threshold67.Div(threshold67, big.NewInt(100))

	t.Logf("\n=== All Shards Scored (sorted best to worst) ===")
	t.Logf("%-15s %10s  ring  ds  %-20s  pct   status", "label", "size", "score")

	aboveCount := 0
	belowCount := 0
	for _, r := range results {
		pct := pctOfBest(r.score, bestScore)
		status := "CONFIRM"
		if r.score.Cmp(threshold67) < 0 {
			status = "REJECT"
			belowCount++
		} else {
			aboveCount++
		}
		t.Logf("%-15s %10s  r=%d   %d  %-20s  %3d%%  %s",
			r.label, fmtStorage(r.size), r.ring, r.ds,
			r.score.String(), pct, status)
	}

	t.Logf("\n=== 67%% Threshold ===")
	t.Logf("Best score:  %s", bestScore.String())
	t.Logf("Threshold:   %s (67%% of best)", threshold67.String())
	t.Logf("Would CONFIRM: %d", aboveCount)
	t.Logf("Would REJECT:  %d (permanently stuck)", belowCount)

	// --- PlanAndAllocate simulation ---
	t.Logf("\n=== PlanAndAllocate Simulation ===")
	freeWorkers := []int{2, 4, 8, 16}
	for _, k := range freeWorkers {
		proposed := min(k, len(results))
		minProposed := results[proposed-1]
		t.Logf("  %d free workers: proposes top %d shards, worst proposed = %s (%s, %d%% of best)",
			k, proposed, minProposed.label, minProposed.score.String(),
			pctOfBest(minProposed.score, bestScore))

		neverProposed := len(results) - proposed
		if neverProposed > 0 {
			t.Logf("    → %d shards NEVER PROPOSED (below top-%d), never reach DecideJoins", neverProposed, k)
		}
	}

	// --- Show the double-filter effect ---
	t.Logf("\n=== Combined Effect: Top-k + 67%% threshold ===")
	t.Logf("For a prover with 4 free workers:")
	t.Logf("  Step 1 (PlanAndAllocate): only top-4 scored shards get proposed")
	t.Logf("  Step 2 (DecideJoins): of those 4 pending, any < 67%% of best gets REJECTED")
	t.Logf("")
	t.Logf("Shards ranked 5th and below NEVER enter the pipeline at all.")
	t.Logf("Even if they enter (because a worker freed up), shards scoring < 67%%")
	t.Logf("of the best shard get perpetually rejected in DecideJoins.")
	t.Logf("")
	t.Logf("With the distribution above, %d/%d shards would be permanently skipped.", belowCount, len(results))

	// --- Break-even ring analysis ---
	t.Logf("\n=== Ring Break-Even ===")
	t.Logf("At what ring does a 20GB shard score equal a 1GB ring-0 shard?")
	ref := scoreShardRewardGreedy(1*1024*1024*1024, basis, worldBytes, 0, 1)
	for ring := uint8(0); ring < 10; ring++ {
		s := scoreShardRewardGreedy(20*1024*1024*1024, basis, worldBytes, ring, 1)
		t.Logf("  20GB ring=%d: %s  (%d%% of 1GB-r0=%s)", ring, s.String(),
			pctOfBest(s, ref), ref.String())
		if s.Cmp(ref) < 0 {
			t.Logf("    ↑ crosses below 1GB-ring-0 here")
			break
		}
	}
}

// pomwBasis replicates reward.PomwBasis inline to avoid node module dep.
// Simplified from the real formula — for threshold analysis, only relative
// scores matter and those depend on size/(2^(ring+1)*sqrt(ds)), not basis.
func pomwBasis(difficulty, worldBytesVal, units uint64) *big.Int {
	if worldBytesVal == 0 {
		return big.NewInt(0)
	}

	// normalized = 1_125_899_906_842_624 / worldStateBytes
	normalized := decimal.NewFromInt(1_125_899_906_842_624)
	normalized = normalized.Div(decimal.NewFromUint64(worldBytesVal))

	// generation = floor(log_10000(difficulty))
	generation := 0
	difflog := difficulty
	for difflog >= 10000 {
		difflog /= 10000
		generation++
	}

	expdenom := int64(1)
	for i := 0; i < generation; i++ {
		expdenom *= 2
	}

	exp := decimal.NewFromInt(1).Div(decimal.NewFromInt(expdenom))
	result, err := normalized.PowWithPrecision(exp, 53)
	if err != nil {
		return big.NewInt(0)
	}

	result = result.Mul(decimal.NewFromUint64(units))
	return result.BigInt()
}
