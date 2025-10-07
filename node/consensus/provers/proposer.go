package provers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sort"
	"sync"

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

// scored is an internal struct for ranking proposals
type scored struct {
	idx   int
	score *big.Int
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

	mu         sync.Mutex
	isPlanning bool
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
	m.mu.Lock()
	isPlanning := m.isPlanning
	m.mu.Unlock()
	if isPlanning {
		m.logger.Debug("planning already in progress")
		return []Proposal{}, nil
	}
	m.mu.Lock()
	m.isPlanning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.isPlanning = false
		m.mu.Unlock()
	}()

	if len(shards) == 0 {
		m.logger.Debug("no shards to allocate")
		return nil, nil
	}

	// Enumerate free workers (unallocated).
	all, err := m.workerMgr.RangeWorkers()
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
		m.logger.Debug("no workers free")
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

	scores, err := m.scoreShards(shards, basis, worldBytes)
	if err != nil {
		return nil, errors.Wrap(err, "plan and allocate")
	}

	if len(scores) == 0 {
		m.logger.Debug("no scores")
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

	// For reward-greedy strategy, randomize within equal-score groups so equally
	// good shards are chosen fairly instead of skewing toward lexicographically
	// earlier filters.
	if m.Strategy != DataGreedy && len(scores) > 1 {
		for start := 0; start < len(scores); {
			end := start + 1
			// Find run [start,end) where scores are equal.
			for end < len(scores) && scores[end].score.Cmp(scores[start].score) == 0 {
				end++
			}

			// Shuffle the run with Fisher–Yates:
			if end-start > 1 {
				for i := end - 1; i > start; i-- {
					n := big.NewInt(int64(i - start + 1))
					r, err := rand.Int(rand.Reader, n)
					if err == nil {
						j := start + int(r.Int64())
						scores[i], scores[j] = scores[j], scores[i]
					}
				}
			}
			start = end
		}
	}

	// Determine how many allocations we’ll attempt.
	limit := len(free)
	if maxAllocations > 0 && maxAllocations < limit {
		limit = maxAllocations
	}
	if limit > len(scores) {
		limit = len(scores)
	}
	m.logger.Debug(
		"deciding on scored proposals",
		zap.Int("free_workers", len(free)),
		zap.Int("max_allocations", maxAllocations),
		zap.Int("scores", len(scores)),
		zap.Int("limit", limit),
	)

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

	// Perform allocations
	workerIds := []uint{}
	filters := [][]byte{}
	for _, p := range proposals {
		workerIds = append(workerIds, p.WorkerId)
		filters = append(filters, p.Filter)
	}

	m.logger.Debug("proposals collated", zap.Int("count", len(proposals)))

	err = m.workerMgr.ProposeAllocations(workerIds, filters)
	if err != nil {
		m.logger.Warn("allocate worker failed",
			zap.Error(err),
		)
	}

	return proposals, errors.Wrap(err, "plan and allocate")
}

func (m *Manager) scoreShards(
	shards []ShardDescriptor,
	basis *big.Int,
	worldBytes *big.Int,
) ([]scored, error) {
	scores := make([]scored, 0, len(shards))
	for i, s := range shards {
		if len(s.Filter) == 0 || s.Size == 0 {
			m.logger.Debug(
				"filtering out empty shard",
				zap.String("filter", hex.EncodeToString(s.Filter)),
				zap.Uint64("size", s.Size),
			)
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
			factor := decimal.NewFromUint64(s.Size)
			factor = factor.Mul(decimal.NewFromBigInt(basis, 0))
			factor = factor.Div(decimal.NewFromBigInt(worldBytes, 0))

			// ring divisor = 2^Ring
			divisor := int64(1)
			for j := uint8(0); j < s.Ring+1; j++ {
				divisor <<= 1
			}
			ringDiv := decimal.NewFromInt(divisor)

			// shard factor = sqrt(Shards)
			shardsSqrt, err := decimal.NewFromUint64(s.Shards).PowWithPrecision(
				decimal.NewFromBigRat(big.NewRat(1, 2), 53),
				53,
			)
			if err != nil {
				return nil, errors.Wrap(err, "score shards")
			}

			if shardsSqrt.IsZero() {
				return nil, errors.New("score shards")
			}

			m.logger.Debug(
				"calculating score",
				zap.Int("index", i),
				zap.String("basis", basis.String()),
				zap.String("size", big.NewInt(int64(s.Size)).String()),
				zap.String("worldBytes", worldBytes.String()),
				zap.String("factor", factor.String()),
				zap.String("divisor", ringDiv.String()),
				zap.String("shardsSqrt", shardsSqrt.String()),
			)
			factor = factor.Div(ringDiv)
			factor = factor.Div(shardsSqrt)
			score = factor.BigInt()
		}

		m.logger.Debug(
			"adding score proposal",
			zap.Int("index", i),
			zap.String("score", score.String()),
		)
		scores = append(scores, scored{idx: i, score: score})
	}
	return scores, nil
}

// DecideJoins evaluates pending shard joins using the latest shard view. It
// uses the same scoring basis as initial planning. For each pending join:
//   - If there exists a strictly better shard in the latest view, reject the
//     existing one (this will result in a new join attempt).
//   - Otherwise (tie or better), confirm the existing one.
func (m *Manager) DecideJoins(
	difficulty uint64,
	shards []ShardDescriptor,
	pending [][]byte,
) error {
	if len(pending) == 0 {
		return nil
	}

	// If no shards remain, we should warn
	if len(shards) == 0 {
		m.logger.Warn("no shards available to decide")
		return nil
	}

	worldBytes := m.world.GetSize(nil, nil)

	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), m.Units)

	scores, err := m.scoreShards(shards, basis, worldBytes)
	if err != nil {
		return errors.Wrap(err, "decide joins")
	}

	type srec struct {
		desc  ShardDescriptor
		score *big.Int
	}
	byHex := make(map[string]srec, len(shards))
	var bestScore *big.Int
	for _, sc := range scores {
		s := shards[sc.idx]
		key := hex.EncodeToString(s.Filter)
		byHex[key] = srec{desc: s, score: sc.score}
		if bestScore == nil || sc.score.Cmp(bestScore) > 0 {
			bestScore = sc.score
		}
	}

	// If nothing valid, reject everything.
	if bestScore == nil {
		reject := make([][]byte, 0, len(pending))
		for _, p := range pending {
			if len(p) == 0 {
				continue
			}
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
		}
		return m.workerMgr.DecideAllocations(reject, nil)
	}

	reject := make([][]byte, 0, len(pending))
	confirm := make([][]byte, 0, len(pending))

	for _, p := range pending {
		if len(p) == 0 {
			continue
		}

		key := hex.EncodeToString(p)
		rec, ok := byHex[key]
		if !ok {
			// If a pending shard is missing, we should reject it. This could happen
			// if shard-out produces a bunch of divisions.
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
			continue
		}

		// Reject only if there exists a strictly better score.
		if rec.score.Cmp(bestScore) < 0 {
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
		} else {
			// Otherwise confirm
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
		}
	}

	return m.workerMgr.DecideAllocations(reject, confirm)
}
