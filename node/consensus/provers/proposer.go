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
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
)

type Strategy int

const (
	RewardGreedy Strategy = iota
	DataGreedy
)

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
	ws store.WorkerStore,
	wm worker.WorkerManager,
	units uint64,
	strategy Strategy,
) *Manager {
	return &Manager{
		logger:    logger.Named("allocationManager"),
		store:     ws,
		workerMgr: wm,
		Units:     units,
		Strategy:  strategy,
	}
}

// PlanAndAllocate picks up to maxAllocations of the best shard filters and
// updates the filter in the worker manager for each selected free worker.
// If maxAllocations == 0, it will use as many free workers as available.
// frameNumber is recorded so pending joins survive restarts while the network
// processes the request.
func (m *Manager) PlanAndAllocate(
	difficulty uint64,
	shards []ShardDescriptor,
	maxAllocations int,
	worldBytes *big.Int,
	frameNumber uint64,
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

	// Enumerate free workers (unallocated, not manually managed).
	all, err := m.workerMgr.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "plan and allocate")
	}
	free := make([]uint, 0, len(all))
	for _, w := range all {
		if len(w.Filter) == 0 && !w.ManuallyManaged {
			free = append(free, w.CoreId)
		}
	}

	if len(free) == 0 {
		m.logger.Debug("no workers free")
		return nil, nil
	}

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
		return proposals, errors.Wrap(err, "plan and allocate")
	}

	// Persist filters only after successful publication — if the join
	// fails to publish, we don't want workers stuck with filters that
	// block them for proposalTimeoutFrames.
	workerLookup := make(map[uint]*store.WorkerInfo, len(all))
	for _, w := range all {
		workerLookup[w.CoreId] = w
	}
	m.persistPlannedFilters(proposals, workerLookup, frameNumber)

	return proposals, nil
}

func (m *Manager) persistPlannedFilters(
	proposals []Proposal,
	workers map[uint]*store.WorkerInfo,
	frameNumber uint64,
) {
	for _, proposal := range proposals {
		info, ok := workers[proposal.WorkerId]
		if !ok {
			var err error
			info, err = m.store.GetWorker(proposal.WorkerId)
			if err != nil {
				m.logger.Warn(
					"failed to load worker for planned allocation",
					zap.Uint("core_id", proposal.WorkerId),
					zap.Error(err),
				)
				continue
			}
			workers[proposal.WorkerId] = info
		}

		if bytes.Equal(info.Filter, proposal.Filter) {
			continue
		}

		filterCopy := make([]byte, len(proposal.Filter))
		copy(filterCopy, proposal.Filter)
		info.Filter = filterCopy
		info.Allocated = false
		info.PendingFilterFrame = frameNumber

		if err := m.workerMgr.RegisterWorker(info); err != nil {
			m.logger.Warn(
				"failed to persist worker filter",
				zap.Uint("core_id", info.CoreId),
				zap.Error(err),
			)
			continue
		}

		m.logger.Info(
			"reassigning worker to new filter",
			zap.Uint("core_id", info.CoreId),
			zap.String("filter", hex.EncodeToString(filterCopy)),
		)
		if err := m.workerMgr.RespawnWorker(info.CoreId, filterCopy); err != nil {
			m.logger.Warn(
				"failed to respawn worker with new filter",
				zap.Uint("core_id", info.CoreId),
				zap.Error(err),
			)
		}
	}
}

func (m *Manager) scoreShards(
	shards []ShardDescriptor,
	basis *big.Int,
	worldBytes *big.Int,
) ([]scored, error) {
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
			factor := decimal.NewFromUint64(s.Size)
			factor = factor.Mul(decimal.NewFromBigInt(basis, 0))
			factor = factor.Div(decimal.NewFromBigInt(worldBytes, 0))

			// ring divisor = 2^Ring
			divisor := int64(1)
			for j := uint8(0); j < s.Ring+1; j++ {
				divisor <<= 1
			}

			// shard is oversubscribed, treat as no rewards
			if divisor == 0 {
				scores = append(scores, scored{idx: i, score: big.NewInt(0)})
				continue
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

			factor = factor.Div(ringDiv)
			factor = factor.Div(shardsSqrt)
			score = factor.BigInt()
		}

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
	worldBytes *big.Int,
) error {
	if len(pending) == 0 {
		return nil
	}

	availableWorkers, err := m.unallocatedWorkerCount()
	if err != nil {
		return errors.Wrap(err, "decide joins")
	}

	// If no shards remain, we should warn
	if len(shards) == 0 {
		m.logger.Warn("no shards available to decide")
		return nil
	}

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
			if len(reject) > 99 {
				break
			}
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
			m.logger.Debug("added shard to reject list", zap.String("shard", hex.EncodeToString(p)))
		}
		m.logger.Info("rejecting all pending allocations")
		return m.workerMgr.DecideAllocations(reject, nil)
	}

	reject := make([][]byte, 0, len(pending))
	confirm := make([][]byte, 0, len(pending))

	// Calculate rejection threshold: only reject if bestScore is significantly
	// better (at least 50% higher) than the pending shard's score. This prevents
	// churn from minor score fluctuations.
	// threshold = bestScore * 0.67 (i.e., reject if pending score < 67% of best,
	// which means best is ~50% better than pending)
	rejectThreshold := new(big.Int).Mul(bestScore, big.NewInt(67))
	rejectThreshold.Div(rejectThreshold, big.NewInt(100))

	for _, p := range pending {
		if len(p) == 0 {
			continue
		}
		if len(reject) > 99 {
			break
		}
		if len(confirm) > 99 {
			break
		}

		key := hex.EncodeToString(p)
		rec, ok := byHex[key]
		if !ok {
			// If a pending shard is missing, we should reject it. This could happen
			// if shard-out produces a bunch of divisions.
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
			m.logger.Debug("added shard to reject list", zap.String("shard", hex.EncodeToString(p)))
			continue
		}

		// Reject only if the pending shard's score is significantly worse than
		// the best available (below 90% of the best score). This prevents churn
		// from minor score differences.
		if rec.score.Cmp(rejectThreshold) < 0 {
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
			m.logger.Debug("added shard to reject list", zap.String("shard", hex.EncodeToString(p)),
				zap.String("score", rec.score.String()), zap.String("threashold", rejectThreshold.String()))
		} else {
			// Otherwise confirm - score is within acceptable range of best
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
			m.logger.Debug("added shard to confirm list", zap.String("shard", hex.EncodeToString(p)),
				zap.String("score", rec.score.String()), zap.String("threashold", rejectThreshold.String()))
		}
	}

	if len(reject) > 0 {
		m.logger.Info("rejecting some pending allocations")
		return m.workerMgr.DecideAllocations(reject, nil)
	} else {
		if availableWorkers == 0 && len(confirm) > 0 {
			m.logger.Info(
				"skipping confirmations due to lack of available workers",
				zap.Int("pending_confirmations", len(confirm)),
			)
			confirm = nil
		} else if availableWorkers > 0 && len(confirm) > availableWorkers {
			m.logger.Warn(
				"limiting confirmations due to worker capacity",
				zap.Int("pending_confirmations", len(confirm)),
				zap.Int("available_workers", availableWorkers),
			)
			confirm = confirm[:availableWorkers]
		}
		m.logger.Info("confirming some pending allocations")
		return m.workerMgr.DecideAllocations(nil, confirm)
	}
}

func (m *Manager) unallocatedWorkerCount() (int, error) {
	workers, err := m.workerMgr.RangeWorkers()
	if err != nil {
		return 0, err
	}

	count := 0
	for _, worker := range workers {
		if worker == nil {
			continue
		}
		if !worker.Allocated {
			count++
		}
	}
	return count, nil
}

// PlanLeaves identifies Active allocations that are on overcrowded shards
// (high Ring) when significantly better unallocated shards exist. Returns up
// to 3 filters to propose leaving.
func (m *Manager) PlanLeaves(
	difficulty uint64,
	allocatedShards []ShardDescriptor,
	unallocatedShards []ShardDescriptor,
	worldBytes *big.Int,
) ([][]byte, error) {
	if len(allocatedShards) == 0 || len(unallocatedShards) == 0 {
		return nil, nil
	}

	if worldBytes.Cmp(big.NewInt(0)) == 0 {
		return nil, nil
	}

	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), m.Units)

	unallocatedScores, err := m.scoreShards(unallocatedShards, basis, worldBytes)
	if err != nil {
		return nil, errors.Wrap(err, "plan leaves")
	}

	// Find best unallocated score.
	var bestUnallocatedScore *big.Int
	for _, sc := range unallocatedScores {
		if bestUnallocatedScore == nil || sc.score.Cmp(bestUnallocatedScore) > 0 {
			bestUnallocatedScore = sc.score
		}
	}

	if bestUnallocatedScore == nil || bestUnallocatedScore.Sign() == 0 {
		return nil, nil
	}

	allocatedScores, err := m.scoreShards(allocatedShards, basis, worldBytes)
	if err != nil {
		return nil, errors.Wrap(err, "plan leaves")
	}

	// Leave threshold: allocated shard must score below 67% of best unallocated
	// (i.e., the alternative is ~50% better).
	leaveThreshold := new(big.Int).Mul(bestUnallocatedScore, big.NewInt(67))
	leaveThreshold.Div(leaveThreshold, big.NewInt(100))

	// Collect leave candidates.
	type candidate struct {
		filter []byte
		score  *big.Int
	}
	candidates := make([]candidate, 0)
	for _, sc := range allocatedScores {
		if sc.score.Cmp(leaveThreshold) < 0 {
			candidates = append(candidates, candidate{
				filter: allocatedShards[sc.idx].Filter,
				score:  sc.score,
			})
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// Sort by score ascending (worst shards first).
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score.Cmp(candidates[j].score) < 0
	})

	// Return up to 3 filters.
	limit := 3
	if limit > len(candidates) {
		limit = len(candidates)
	}

	filters := make([][]byte, 0, limit)
	for i := 0; i < limit; i++ {
		fc := make([]byte, len(candidates[i].filter))
		copy(fc, candidates[i].filter)
		filters = append(filters, fc)
		m.logger.Debug("added shard to leave list", zap.String("shard", hex.EncodeToString(fc)),
			zap.String("score", candidates[i].score.String()), zap.String("leaveThreashold", leaveThreshold.String()))
	}

	err = m.workerMgr.ProposeLeave(filters)
	if err != nil {
		return nil, errors.Wrap(err, "plan leaves")
	}
	m.logger.Info("proposed leaves")
	return filters, nil
}

// DecideLeaves confirms or rejects pending leaves after 360 frames. For each
// pending leave filter:
//   - If the shard's score is competitive (>= 67% of best), reject the leave
//     (the shard improved, stay on it).
//   - If the shard's score is still poor (< 67% of best), confirm the leave
//     (better alternatives still exist).
//   - If the filter is not found in shards, confirm (shard disappeared).
func (m *Manager) DecideLeaves(
	difficulty uint64,
	shards []ShardDescriptor,
	pendingLeaves [][]byte,
	worldBytes *big.Int,
) error {
	if len(pendingLeaves) == 0 {
		return nil
	}

	if len(shards) == 0 {
		// No shards to score — confirm all leaves.
		confirm := make([][]byte, 0, len(pendingLeaves))
		for _, p := range pendingLeaves {
			if len(p) == 0 {
				continue
			}
			if len(confirm) > 99 {
				break
			}
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
		}
		return m.workerMgr.DecideLeave(nil, confirm)
	}

	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), m.Units)

	scores, err := m.scoreShards(shards, basis, worldBytes)
	if err != nil {
		return errors.Wrap(err, "decide leaves")
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

	if bestScore == nil {
		// Nothing scored — confirm all leaves.
		confirm := make([][]byte, 0, len(pendingLeaves))
		for _, p := range pendingLeaves {
			if len(p) == 0 {
				continue
			}
			if len(confirm) > 99 {
				break
			}
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
		}
		return m.workerMgr.DecideLeave(nil, confirm)
	}

	// Reject threshold: if the leaving shard's score >= 67% of best, reject
	// the leave (the shard has improved enough to stay).
	rejectThreshold := new(big.Int).Mul(bestScore, big.NewInt(67))
	rejectThreshold.Div(rejectThreshold, big.NewInt(100))

	reject := make([][]byte, 0, len(pendingLeaves))
	confirm := make([][]byte, 0, len(pendingLeaves))

	for _, p := range pendingLeaves {
		if len(p) == 0 {
			continue
		}
		if len(reject) > 99 {
			break
		}
		if len(confirm) > 99 {
			break
		}

		key := hex.EncodeToString(p)
		rec, ok := byHex[key]
		if !ok {
			// Shard disappeared — confirm the leave.
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
			continue
		}

		if rec.score.Cmp(rejectThreshold) >= 0 {
			// Shard is now competitive — reject the leave (stay).
			pc := make([]byte, len(p))
			copy(pc, p)
			reject = append(reject, pc)
		} else {
			// Still a bad shard — confirm the leave.
			pc := make([]byte, len(p))
			copy(pc, p)
			confirm = append(confirm, pc)
		}
	}

	return m.workerMgr.DecideLeave(reject, confirm)
}
