package provers

import (
	"bytes"
	"math/big"
	"sort"

	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
)

type Strategy int

const (
	RewardGreedy Strategy = iota
	DataGreedy
)

// WorldSizer provides the total world-state size (bytes).
type WorldSizer interface {
	// GetSize returns the total world state size in bytes.
	GetSize(key *tries.ShardKey, path []int) *big.Int
}

// ShardDescriptor describes a candidate shard allocation target.
type ShardDescriptor struct {
	// Confirmation filter for the shard (routing key). Must be non-empty.
	Filter []byte
	// Size in bytes of this shard’s state (for reward proportionality).
	Size uint64
	// Ring attenuation factor (reward is divided by 2^Ring). Usually 0 unless
	// you intentionally place on outer rings.
	Ring uint8
	// Logical shard-group participation count for sqrt divisor (>=1).
	// If you’re assigning a worker to exactly one shard, use 1.
	Shards uint64
}

// Proposal is a plan to allocate a specific worker to a shard filter.
type Proposal struct {
	WorkerId          uint
	Filter            []byte
	ExpectedReward    *big.Int // in base units
	WorldStateBytes   uint64
	ShardSizeBytes    uint64
	Ring              uint8
	ShardsDenominator uint64
}

// Manager ranks shards and assigns free workers to the best ones.
type Manager struct {
	logger    *zap.Logger
	world     WorldSizer
	store     store.WorkerStore
	workerMgr worker.WorkerManager

	// Static issuance parameters for planning
	Units    uint64
	Strategy Strategy
}

// NewManager wires up a planning manager
func NewManager(
	logger *zap.Logger,
	world WorldSizer,
	ws store.WorkerStore,
	wm worker.WorkerManager,
	units uint64,
	strategy Strategy,
) *Manager {
	return &Manager{
		logger:    logger.Named("allocation_manager"),
		world:     world,
		store:     ws,
		workerMgr: wm,
		Units:     units,
		Strategy:  strategy,
	}
}

// PlanAndAllocate picks up to maxAllocations of the best shard filters and
// calls WorkerManager.AllocateWorker for each selected free worker.
// If maxAllocations == 0, it will use as many free workers as available.
func (m *Manager) PlanAndAllocate(
	difficulty uint64,
	shards []ShardDescriptor,
	maxAllocations int,
) ([]Proposal, error) {
	if len(shards) == 0 {
		return nil, nil
	}

	// Enumerate free workers (unallocated).
	all, err := m.store.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "plan and allocate")
	}
	free := make([]uint, 0, len(all))
	for _, w := range all {
		if !w.Allocated {
			free = append(free, w.CoreId)
		}
	}

	if len(free) == 0 {
		return nil, nil
	}

	worldBytes := m.world.GetSize(nil, nil)
	if worldBytes.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.Wrap(
			errors.New("world size is zero"),
			"plan and allocate",
		)
	}

	// Pre-compute basis (independent of shard specifics).
	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), m.Units)

	// Score each shard by expected reward for a single allocation.
	type scored struct {
		idx   int
		score *big.Int
	}
	scores := make([]scored, 0, len(shards))

	for i, s := range shards {
		if len(s.Filter) == 0 || s.Size == 0 {
			continue
		}
		if s.Shards == 0 {
			s.Shards = 1
		}
		var score *big.Int
		switch m.Strategy {
		case DataGreedy:
			// Pure data coverage: larger shards first.
			score = big.NewInt(int64(s.Size))
		default:
			// factor = (stateSize / worldBytes)
			factor := big.NewInt(int64(s.Size))
			factor.Quo(
				factor,
				worldBytes,
			)

			// ring divisor = 2^Ring
			divisor := int64(1)
			for j := uint8(0); j < s.Ring+1; j++ {
				divisor <<= 1
			}
			ringDiv := big.NewInt(divisor)

			// shard factor = sqrt(Shards)
			shardsSqrt, err := decimal.NewFromUint64(s.Shards).PowWithPrecision(
				decimal.NewFromBigRat(big.NewRat(1, 2), 53),
				53,
			)
			if err != nil {
				return nil, errors.Wrap(err, "plan and allocate")
			}
			if shardsSqrt.IsZero() {
				return nil, errors.New("plan and allocate")
			}

			score := basis.Mul(basis, factor)
			score.Quo(score, ringDiv)
			score.Quo(score, shardsSqrt.BigInt())
		}
		scores = append(scores, scored{idx: i, score: score})
	}

	if len(scores) == 0 {
		return nil, nil
	}

	// Sort by score desc, then lexicographically by filter to keep order
	// stable/deterministic.
	sort.Slice(scores, func(i, j int) bool {
		cmp := scores[i].score.Cmp(scores[j].score)
		if cmp != 0 {
			return cmp > 0
		}
		fi := shards[scores[i].idx].Filter
		fj := shards[scores[j].idx].Filter
		return bytes.Compare(fi, fj) < 0
	})

	// Determine how many allocations we’ll attempt.
	limit := len(free)
	if maxAllocations > 0 && maxAllocations < limit {
		limit = maxAllocations
	}
	if limit > len(scores) {
		limit = len(scores)
	}

	proposals := make([]Proposal, 0, limit)

	// Assign top-k scored shards to the first k free workers.
	for k := 0; k < limit; k++ {
		sel := shards[scores[k].idx]

		// Copy filter so we don't leak underlying slices.
		filterCopy := make([]byte, len(sel.Filter))
		copy(filterCopy, sel.Filter)

		// Convert expected reward to *big.Int to match issuance style.
		expBI := scores[k].score

		proposals = append(proposals, Proposal{
			WorkerId:          free[k],
			Filter:            filterCopy,
			ExpectedReward:    expBI,
			WorldStateBytes:   worldBytes.Uint64(),
			ShardSizeBytes:    sel.Size,
			Ring:              sel.Ring,
			ShardsDenominator: sel.Shards,
		})
	}

	// Perform allocations (best-effort, continue on per-worker error).
	out := make([]Proposal, 0, len(proposals))
	for _, p := range proposals {
		if err := m.workerMgr.ProposeAllocation(p.WorkerId, p.Filter); err != nil {
			// Keep going; return successful ones plus the error at the end.
			m.logger.Warn("allocate worker failed",
				zap.Uint("worker_id", p.WorkerId),
				zap.Error(err),
			)
			continue
		}
		out = append(out, p)
	}

	return out, nil
}
