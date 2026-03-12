package global

import (
	"bytes"
	"math/big"
	"slices"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// GetShardInfo implements typesconsensus.ShardInfoProvider.
// Returns: shardDetails, difficulty, pomwBasis, frameNumber, error.
func (e *GlobalConsensusEngine) GetShardInfo(
	includeAll bool,
) ([]*typesconsensus.ShardDetail, uint64, *big.Int, uint64, error) {
	frame, err := e.clockStore.GetLatestGlobalClockFrame()
	if err != nil {
		return nil, 0, nil, 0, errors.Wrap(err, "get shard info: latest frame")
	}

	difficulty := uint64(frame.Header.Difficulty)
	frameNumber := frame.Header.FrameNumber

	self, _ := e.allocationContext()

	// Build a set of filters this prover is allocated to.
	allocatedFilters := map[string]bool{}
	if self != nil {
		currentFrame := e.proverRegistry.CurrentFrame()
		for _, alloc := range self.Allocations {
			if alloc.Status == typesconsensus.ProverStatusJoining &&
				currentFrame > alloc.JoinFrameNumber+720 {
				continue
			}
			if alloc.Status == typesconsensus.ProverStatusLeaving &&
				currentFrame > alloc.LeaveFrameNumber+720 {
				continue
			}
			if alloc.Status == typesconsensus.ProverStatusActive ||
				alloc.Status == typesconsensus.ProverStatusJoining {
				allocatedFilters[string(alloc.ConfirmationFilter)] = true
			}
		}
	}

	appShards, err := e.shardsStore.RangeAppShards()
	if err != nil {
		return nil, 0, nil, 0, errors.Wrap(err, "get shard info: range shards")
	}

	// Consolidate into high-level L2 shards.
	shardMap := map[string]store.ShardInfo{}
	for _, s := range appShards {
		shardMap[string(s.L2)] = s
	}

	shards := make([]store.ShardInfo, 0, len(shardMap))
	for _, s := range shardMap {
		shards = append(shards, store.ShardInfo{
			L1: s.L1,
			L2: s.L2,
		})
	}

	hg, ok := e.hypergraph.(*hypergraph.HypergraphCRDT)
	if !ok {
		return nil, 0, nil, 0, errors.New("get shard info: hypergraph type unsupported")
	}

	worldBytes := big.NewInt(0)

	type shardEntry struct {
		filter      []byte
		size        *big.Int
		dataShards  uint64
		totalActive int
		isAllocated bool
	}
	var entries []shardEntry

	for _, shardInfo := range shards {
		shardKey := slices.Concat(shardInfo.L1, shardInfo.L2)
		resp, err := e.getLocalAppShards(hg, shardKey, shardInfo)
		if err != nil {
			continue
		}

		for _, shard := range resp {
			size := new(big.Int).SetBytes(shard.Size)
			if size.Cmp(big.NewInt(0)) == 0 {
				continue
			}
			worldBytes.Add(worldBytes, size)

			bp := slices.Clone(shardInfo.L2)
			for _, p := range shard.Prefix {
				bp = append(bp, byte(p))
			}

			isAlloc := allocatedFilters[string(bp)]

			if !includeAll && !isAlloc {
				continue
			}

			prs, err := e.proverRegistry.GetProvers(bp)
			if err != nil {
				continue
			}

			totalActive := 0
			for _, i := range prs {
				for _, a := range i.Allocations {
					if !bytes.Equal(a.ConfirmationFilter, bp) {
						continue
					}
					if a.Status == typesconsensus.ProverStatusActive ||
						a.Status == typesconsensus.ProverStatusJoining {
						totalActive++
					}
					break
				}
			}

			entries = append(entries, shardEntry{
				filter:      bp,
				size:        size,
				dataShards:  shard.DataShards,
				totalActive: totalActive,
				isAllocated: isAlloc,
			})
		}
	}

	if worldBytes.Cmp(big.NewInt(0)) == 0 {
		return nil, difficulty, big.NewInt(0), frameNumber, nil
	}

	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), 8_000_000_000)

	details := make([]*typesconsensus.ShardDetail, 0, len(entries))
	for _, entry := range entries {
		// Ring matches the actual assignment in computeRingAssignments:
		// floor(totalActiveJoining / 8) for current members, +1 for a
		// new joiner.
		ring := uint8(entry.totalActive / 8)
		if !entry.isAllocated && includeAll {
			ring = uint8((entry.totalActive + 1) / 8)
		}

		est := computeShardReward(basis, entry.size, worldBytes, ring, entry.dataShards)

		details = append(details, &typesconsensus.ShardDetail{
			Filter:          entry.filter,
			ShardSize:       entry.size,
			ActiveProvers:   entry.totalActive,
			Ring:            ring,
			EstimatedReward: est,
			IsAllocated:     entry.isAllocated,
		})
	}

	return details, difficulty, basis, frameNumber, nil
}

// getLocalAppShards retrieves app shard info from the local cache/hypergraph.
func (e *GlobalConsensusEngine) getLocalAppShards(
	hg *hypergraph.HypergraphCRDT,
	shardKey []byte,
	shardInfo store.ShardInfo,
) ([]*shardInfoEntry, error) {
	subShards, err := e.shardsStore.GetAppShards(shardKey, nil)
	if err != nil {
		return nil, err
	}

	if len(subShards) == 0 {
		subShards = []store.ShardInfo{shardInfo}
	}

	var result []*shardInfoEntry
	for _, sub := range subShards {
		info := e.getAppShardInfoForShard(hg, sub, false)
		if info == nil {
			continue
		}
		result = append(result, &shardInfoEntry{
			Prefix:     info.Prefix,
			Size:       info.Size,
			DataShards: info.DataShards,
		})
	}
	return result, nil
}

type shardInfoEntry struct {
	Prefix     []uint32
	Size       []byte
	DataShards uint64
}

// computeShardReward computes the per-frame reward estimate for a single shard.
// Formula matches proof_of_meaningful_work.go:
//
//	(basis * shardSize / worldBytes) / (2^(ring+1) * sqrt(activeProvers))
func computeShardReward(
	basis *big.Int,
	shardSize *big.Int,
	worldBytes *big.Int,
	ring uint8,
	activeProvers uint64,
) *big.Int {
	if basis.Sign() == 0 || worldBytes.Sign() == 0 || activeProvers == 0 {
		return big.NewInt(0)
	}

	// Use the same decimal math as the reward module.
	// factor = shardSize * basis / worldBytes
	factor := new(big.Int).Mul(shardSize, basis)
	factor.Div(factor, worldBytes)

	// divisor = 2^(ring+1)
	divisor := int64(1)
	for i := uint8(0); i < ring+1; i++ {
		divisor <<= 1
	}
	if divisor == 0 {
		return big.NewInt(0)
	}
	factor.Div(factor, big.NewInt(divisor))

	// Approximate sqrt(activeProvers) using integer math:
	// Newton's method for isqrt.
	if activeProvers > 1 {
		sqrtVal := isqrt(activeProvers)
		if sqrtVal > 0 {
			factor.Div(factor, big.NewInt(int64(sqrtVal)))
		}
	}

	return factor
}

// isqrt returns the integer square root of n using Newton's method.
func isqrt(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	x := n
	y := (x + 1) / 2
	for y < x {
		x = y
		y = (x + n/x) / 2
	}
	return x
}
