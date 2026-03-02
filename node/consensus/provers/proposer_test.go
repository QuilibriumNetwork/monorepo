package provers

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"go.uber.org/zap"

	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type mockWorkerManager struct {
	workers        []*store.WorkerInfo
	lastWorkers    []uint
	lastFiltersHex []string
	rejected       [][]byte
	confirmed      [][]byte

	// Leave tracking
	leaveProposed      [][]byte
	leaveRejected      [][]byte
	leaveConfirmed     [][]byte
}

// CheckWorkersConnected implements worker.WorkerManager.
func (m *mockWorkerManager) CheckWorkersConnected() ([]uint, error) {
	panic("unimplemented")
}

func (m *mockWorkerManager) DecideAllocations(reject [][]byte, confirm [][]byte) error {
	m.rejected = reject
	m.confirmed = confirm
	return nil
}

func (m *mockWorkerManager) ProposeLeave(filters [][]byte) error {
	m.leaveProposed = filters
	return nil
}

func (m *mockWorkerManager) DecideLeave(reject [][]byte, confirm [][]byte) error {
	m.leaveRejected = reject
	m.leaveConfirmed = confirm
	return nil
}

func (m *mockWorkerManager) AllocateWorker(coreId uint, filter []byte) error {
	panic("unimplemented")
}

func (m *mockWorkerManager) DeallocateWorker(coreId uint) error {
	panic("unimplemented")
}

func (m *mockWorkerManager) GetFilterByWorkerId(coreId uint) ([]byte, error) {
	panic("unimplemented")
}

func (m *mockWorkerManager) GetWorkerIdByFilter(filter []byte) (uint, error) {
	panic("unimplemented")
}

func (m *mockWorkerManager) RegisterWorker(info *store.WorkerInfo) error {
	for i, worker := range m.workers {
		if worker.CoreId == info.CoreId {
			m.workers[i] = info
			return nil
		}
	}
	m.workers = append(m.workers, info)
	return nil
}

func (m *mockWorkerManager) Start(ctx context.Context) error {
	panic("unimplemented")
}

func (m *mockWorkerManager) Stop() error {
	panic("unimplemented")
}
func (m *mockWorkerManager) RespawnWorker(coreId uint, filter []byte) error {
	return nil
}

func (m *mockWorkerManager) RangeWorkers() ([]*store.WorkerInfo, error) {
	out := make([]*store.WorkerInfo, len(m.workers))
	copy(out, m.workers)
	return out, nil
}

func (m *mockWorkerManager) ProposeAllocations(workerIds []uint, filters [][]byte) error {
	m.lastWorkers = append([]uint(nil), workerIds...)
	m.lastFiltersHex = make([]string, len(filters))
	for i := range filters {
		m.lastFiltersHex[i] = hex.EncodeToString(filters[i])
	}
	return nil
}

func newTestManager(t *testing.T, strategy Strategy, wm *mockWorkerManager) *Manager {
	t.Helper()
	logger := zap.NewNop()
	const units = 8000000000

	return NewManager(logger, nil, wm, units, strategy)
}

func createWorkers(n int) []*store.WorkerInfo {
	ws := make([]*store.WorkerInfo, n)
	for i := 0; i < n; i++ {
		ws[i] = &store.WorkerInfo{
			CoreId:             uint(i + 1),
			Allocated:          false,
			PendingFilterFrame: 0,
		}
	}
	return ws
}

func createShard(filter []byte, size uint64, ring uint8, shards uint64) ShardDescriptor {
	return ShardDescriptor{
		Filter: filter,
		Size:   size,
		Ring:   ring,
		Shards: shards,
	}
}

func TestPlanAndAllocate_EqualScores_RandomizedWhenNotDataGreedy(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(1)}
	m := newTestManager(t, RewardGreedy, wm)

	// 4 equal-score shards: identical size, ring, shards. only filter differs
	shards := []ShardDescriptor{
		createShard([]byte{0x01}, 10_000, 0, 1),
		createShard([]byte{0x02}, 10_000, 0, 1),
		createShard([]byte{0x03}, 10_000, 0, 1),
		createShard([]byte{0x04}, 10_000, 0, 1),
	}

	firstPickCounts := map[string]int{
		"01": 0, "02": 0, "03": 0, "04": 0,
	}

	// Run multiple times to confirm randomness.
	const runs = 64
	for i := 0; i < runs; i++ {
		time.Sleep(5 * time.Millisecond)

		wm.lastFiltersHex = nil
		_, err := m.PlanAndAllocate(100, shards, 1, big.NewInt(40000), uint64(i+1))
		if err != nil {
			t.Fatalf("PlanAndAllocate failed: %v", err)
		}
		if len(wm.lastFiltersHex) != 1 {
			t.Fatalf("expected one allocation, got %d", len(wm.lastFiltersHex))
		}
		firstPickCounts[wm.lastFiltersHex[0]]++

		// Reset worker filter to simulate completion
		for _, worker := range wm.workers {
			worker.Filter = nil
			worker.PendingFilterFrame = 0
		}
	}

	distinct := 0
	for _, c := range firstPickCounts {
		if c > 0 {
			distinct++
		}
	}
	if distinct < 4 {
		t.Fatalf("expected randomized tie-break; got counts: %+v", firstPickCounts)
	}
}

func TestPlanAndAllocate_EqualSizes_DeterministicWhenDataGreedy(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(1)}
	m := newTestManager(t, DataGreedy, wm)

	shards := []ShardDescriptor{
		createShard([]byte{0x02}, 10_000, 0, 1),
		createShard([]byte{0x01}, 10_000, 0, 1),
		createShard([]byte{0x04}, 10_000, 0, 1),
		createShard([]byte{0x03}, 10_000, 0, 1),
	}

	const runs = 16
	for i := 0; i < runs; i++ {
		wm.lastFiltersHex = nil
		_, err := m.PlanAndAllocate(100, shards, 1, big.NewInt(40000), uint64(i+1))
		if err != nil {
			t.Fatalf("PlanAndAllocate failed: %v", err)
		}
		if len(wm.lastFiltersHex) != 1 {
			t.Fatalf("expected one allocation, got %d", len(wm.lastFiltersHex))
		}
		if wm.lastFiltersHex[0] != "01" {
			t.Fatalf("expected deterministic lexicographic first (01) in DataGreedy, got %s", wm.lastFiltersHex[0])
		}

		// Reset worker filter to simulate completion
		for _, worker := range wm.workers {
			worker.Filter = nil
			worker.PendingFilterFrame = 0
		}
	}
}

func TestPlanAndAllocate_UnequalScores_PicksMax(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(1)}
	m := newTestManager(t, RewardGreedy, wm)

	// Make one shard clearly better by size, keep others smaller.
	best := createShard([]byte{0x0A}, 200_000, 0, 1)
	other1 := createShard([]byte{0x01}, 50_000, 0, 1)
	other2 := createShard([]byte{0x02}, 50_000, 0, 1)
	shards := []ShardDescriptor{other1, other2, best}

	_, err := m.PlanAndAllocate(100, shards, 1, big.NewInt(300000), 1)
	if err != nil {
		t.Fatalf("PlanAndAllocate failed: %v", err)
	}
	if len(wm.lastFiltersHex) != 1 {
		t.Fatalf("expected one allocation, got %d", len(wm.lastFiltersHex))
	}
	if !bytes.Equal([]byte{0x0A}, mustDecodeHex(t, wm.lastFiltersHex[0])) {
		t.Fatalf("expected best shard 0x0A to be selected, got %s", wm.lastFiltersHex[0])
	}
}

// Confirm when pending is best (RewardGreedy)
func TestDecideJoins_ConfirmWhenBest_RewardGreedy(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(1)}
	m := newTestManager(t, RewardGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "01"), Size: 50_000, Ring: 0, Shards: 1},
		{Filter: mustDecodeHex(t, "02"), Size: 200_000, Ring: 0, Shards: 1}, // best
		{Filter: mustDecodeHex(t, "03"), Size: 50_000, Ring: 0, Shards: 1},
	}
	pending := [][]byte{mustDecodeHex(t, "02")}

	err := m.DecideJoins(100, shards, pending, big.NewInt(300000))
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.rejected) != 0 || len(wm.confirmed) != 1 || hex.EncodeToString(wm.confirmed[0]) != "02" {
		t.Fatalf("expected confirm 02, got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

// Reject when a strictly better shard exists (RewardGreedy)
func TestDecideJoins_RejectWhenBetterExists_RewardGreedy(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "0a"), Size: 200_000, Ring: 0, Shards: 1}, // best
		{Filter: mustDecodeHex(t, "01"), Size: 50_000, Ring: 0, Shards: 1},
	}
	pending := [][]byte{mustDecodeHex(t, "01")}

	err := m.DecideJoins(100, shards, pending, big.NewInt(250000))
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.rejected) != 1 || hex.EncodeToString(wm.rejected[0]) != "01" || len(wm.confirmed) != 0 {
		t.Fatalf("expected reject 01, got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

// Tie -> confirm (RewardGreedy)
func TestDecideJoins_TieConfirms_RewardGreedy(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(1)}
	m := newTestManager(t, RewardGreedy, wm)
	// Same size/ring/shards -> same score
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "01"), Size: 100_000, Ring: 1, Shards: 4},
		{Filter: mustDecodeHex(t, "02"), Size: 100_000, Ring: 1, Shards: 4},
	}
	pending := [][]byte{mustDecodeHex(t, "02")}

	err := m.DecideJoins(100, shards, pending, big.NewInt(200000))
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.rejected) != 0 || len(wm.confirmed) != 1 || hex.EncodeToString(wm.confirmed[0]) != "02" {
		t.Fatalf("expected confirm 02 on tie, got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

func TestDecideJoins_DataGreedy_SizeOnly(t *testing.T) {
	wm := &mockWorkerManager{workers: createWorkers(3)}
	m := newTestManager(t, DataGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 10_000, Ring: 3, Shards: 16}, // worse by size
		{Filter: mustDecodeHex(t, "bb"), Size: 80_000, Ring: 0, Shards: 1},  // best by size
		{Filter: mustDecodeHex(t, "cc"), Size: 80_000, Ring: 5, Shards: 64}, // tie by size
	}
	// Pending on aa (worse), bb (best), cc (tie-best)
	pending := [][]byte{mustDecodeHex(t, "aa"), mustDecodeHex(t, "bb"), mustDecodeHex(t, "cc")}
	err := m.DecideJoins(100, shards, pending, big.NewInt(170000))
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	rej := setOf(toHex(wm.rejected))
	// When any rejections exist, DecideJoins sends only rejections (confirms
	// wait for the next cycle). So we only check that aa was rejected and
	// bb/cc were NOT rejected.
	if !rej["aa"] || rej["bb"] || rej["cc"] {
		t.Fatalf("expected reject{aa} only; got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

// Missing/invalid pending -> reject
func TestDecideJoins_PendingMissingOrInvalid_Reject(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "01"), Size: 100_000, Ring: 0, Shards: 1},
	}
	pending := [][]byte{mustDecodeHex(t, "deadbeef"), nil, {}}

	err := m.DecideJoins(100, shards, pending, big.NewInt(100000))
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.confirmed) != 0 || len(wm.rejected) != 1 || hex.EncodeToString(wm.rejected[0]) != "deadbeef" {
		t.Fatalf("expected only deadbeef rejected; got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func toHex(bs [][]byte) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, hex.EncodeToString(b))
	}
	return out
}

func setOf(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// --- PlanLeaves tests ---

// PlanLeaves should propose leaving a shard when a significantly better
// unallocated shard exists.
func TestPlanLeaves_LeavesWhenBetterExists(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Allocated shard: small, high ring → low score
	allocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 50_000, Ring: 3, Shards: 1},
	}
	// Unallocated shard: large, ring 0 → high score
	unallocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "bb"), Size: 200_000, Ring: 0, Shards: 1},
	}

	filters, err := m.PlanLeaves(100, allocated, unallocated, big.NewInt(250000))
	if err != nil {
		t.Fatalf("PlanLeaves error: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 leave filter, got %d", len(filters))
	}
	if hex.EncodeToString(filters[0]) != "aa" {
		t.Fatalf("expected leave filter aa, got %s", hex.EncodeToString(filters[0]))
	}
	if len(wm.leaveProposed) != 1 {
		t.Fatalf("expected ProposeLeave called with 1 filter, got %d", len(wm.leaveProposed))
	}
}

// PlanLeaves should not propose leaving when the allocated shard is competitive.
func TestPlanLeaves_StaysWhenCompetitive(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Allocated shard: same score as unallocated
	allocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 100_000, Ring: 0, Shards: 1},
	}
	unallocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "bb"), Size: 100_000, Ring: 0, Shards: 1},
	}

	filters, err := m.PlanLeaves(100, allocated, unallocated, big.NewInt(200000))
	if err != nil {
		t.Fatalf("PlanLeaves error: %v", err)
	}
	if len(filters) != 0 {
		t.Fatalf("expected no leave filters when competitive, got %d", len(filters))
	}
}

// PlanLeaves should not propose leaving when no unallocated shards exist.
func TestPlanLeaves_NilWhenNoUnallocated(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	allocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 50_000, Ring: 3, Shards: 1},
	}

	filters, err := m.PlanLeaves(100, allocated, nil, big.NewInt(50000))
	if err != nil {
		t.Fatalf("PlanLeaves error: %v", err)
	}
	if filters != nil {
		t.Fatalf("expected nil when no unallocated shards, got %v", toHex(filters))
	}
}

// PlanLeaves caps at 3 leave proposals.
func TestPlanLeaves_CapsAt3(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// 5 bad allocated shards (high ring, low score)
	allocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "a1"), Size: 50_000, Ring: 4, Shards: 1},
		{Filter: mustDecodeHex(t, "a2"), Size: 50_000, Ring: 4, Shards: 1},
		{Filter: mustDecodeHex(t, "a3"), Size: 50_000, Ring: 4, Shards: 1},
		{Filter: mustDecodeHex(t, "a4"), Size: 50_000, Ring: 4, Shards: 1},
		{Filter: mustDecodeHex(t, "a5"), Size: 50_000, Ring: 4, Shards: 1},
	}
	// 1 great unallocated shard
	unallocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "bb"), Size: 200_000, Ring: 0, Shards: 1},
	}

	filters, err := m.PlanLeaves(100, allocated, unallocated, big.NewInt(450000))
	if err != nil {
		t.Fatalf("PlanLeaves error: %v", err)
	}
	if len(filters) != 3 {
		t.Fatalf("expected 3 leave filters (cap), got %d", len(filters))
	}
}

// PlanLeaves sorts worst-first: the worst scoring shard should be first.
func TestPlanLeaves_WorstFirst(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Two bad shards, one worse than the other
	allocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "a1"), Size: 50_000, Ring: 2, Shards: 1}, // bad
		{Filter: mustDecodeHex(t, "a2"), Size: 50_000, Ring: 4, Shards: 1}, // worse
	}
	unallocated := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "bb"), Size: 200_000, Ring: 0, Shards: 1},
	}

	filters, err := m.PlanLeaves(100, allocated, unallocated, big.NewInt(300000))
	if err != nil {
		t.Fatalf("PlanLeaves error: %v", err)
	}
	if len(filters) < 2 {
		t.Fatalf("expected at least 2 leave filters, got %d", len(filters))
	}
	// a2 (ring 4) should be first (worst score)
	if hex.EncodeToString(filters[0]) != "a2" {
		t.Fatalf("expected worst shard a2 first, got %s", hex.EncodeToString(filters[0]))
	}
}

// --- DecideLeaves tests ---

// DecideLeaves should confirm a leave when the shard is still bad.
func TestDecideLeaves_ConfirmWhenStillBad(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Leaving shard is much worse than the best
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 50_000, Ring: 3, Shards: 1},  // leaving this (bad)
		{Filter: mustDecodeHex(t, "bb"), Size: 200_000, Ring: 0, Shards: 1}, // best available
	}
	pendingLeaves := [][]byte{mustDecodeHex(t, "aa")}

	err := m.DecideLeaves(100, shards, pendingLeaves, big.NewInt(250000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if len(wm.leaveConfirmed) != 1 || hex.EncodeToString(wm.leaveConfirmed[0]) != "aa" {
		t.Fatalf("expected confirm aa, got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
	if len(wm.leaveRejected) != 0 {
		t.Fatalf("expected no rejections, got %v", toHex(wm.leaveRejected))
	}
}

// DecideLeaves should reject a leave when the shard has improved (others left,
// Ring dropped).
func TestDecideLeaves_RejectWhenShardImproved(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Now the leaving shard is the best (same as the alternative)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 100_000, Ring: 0, Shards: 1}, // leaving this (now good)
		{Filter: mustDecodeHex(t, "bb"), Size: 100_000, Ring: 0, Shards: 1}, // alternative
	}
	pendingLeaves := [][]byte{mustDecodeHex(t, "aa")}

	err := m.DecideLeaves(100, shards, pendingLeaves, big.NewInt(200000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if len(wm.leaveRejected) != 1 || hex.EncodeToString(wm.leaveRejected[0]) != "aa" {
		t.Fatalf("expected reject aa (shard improved), got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
	if len(wm.leaveConfirmed) != 0 {
		t.Fatalf("expected no confirmations, got %v", toHex(wm.leaveConfirmed))
	}
}

// DecideLeaves should confirm a leave when the shard disappeared from the view.
func TestDecideLeaves_ConfirmWhenShardDisappeared(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// Only other shards exist — the leaving shard is gone
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "bb"), Size: 100_000, Ring: 0, Shards: 1},
	}
	pendingLeaves := [][]byte{mustDecodeHex(t, "aa")}

	err := m.DecideLeaves(100, shards, pendingLeaves, big.NewInt(100000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if len(wm.leaveConfirmed) != 1 || hex.EncodeToString(wm.leaveConfirmed[0]) != "aa" {
		t.Fatalf("expected confirm aa (disappeared), got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
}

// DecideLeaves should confirm all when no shards exist at all.
func TestDecideLeaves_ConfirmAllWhenNoShards(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	pendingLeaves := [][]byte{mustDecodeHex(t, "aa"), mustDecodeHex(t, "bb")}

	err := m.DecideLeaves(100, nil, pendingLeaves, big.NewInt(100000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if len(wm.leaveConfirmed) != 2 {
		t.Fatalf("expected 2 confirmations, got %d", len(wm.leaveConfirmed))
	}
}

// DecideLeaves with mixed results: some shards improved, some still bad.
func TestDecideLeaves_MixedDecisions(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	// aa: 150k at ring 0 → 75% of best (200k ring 0) → above 67% threshold → reject leave (stay)
	// bb: 50k at ring 3 → tiny score → well below 67% threshold → confirm leave
	// cc: 200k at ring 0 → best score
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 150_000, Ring: 0, Shards: 1}, // improved
		{Filter: mustDecodeHex(t, "bb"), Size: 50_000, Ring: 3, Shards: 1},  // still bad
		{Filter: mustDecodeHex(t, "cc"), Size: 200_000, Ring: 0, Shards: 1}, // best alternative
	}
	pendingLeaves := [][]byte{mustDecodeHex(t, "aa"), mustDecodeHex(t, "bb")}

	err := m.DecideLeaves(100, shards, pendingLeaves, big.NewInt(400000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}

	rejSet := setOf(toHex(wm.leaveRejected))
	cfmSet := setOf(toHex(wm.leaveConfirmed))

	// aa improved (ring 0, 150k) is 75% of best (200k) → above 67% → reject leave (stay)
	if !rejSet["aa"] {
		t.Fatalf("expected aa rejected (shard improved), got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
	// bb still bad (ring 3, 50k) → confirm leave
	if !cfmSet["bb"] {
		t.Fatalf("expected bb confirmed (still bad), got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
}

// DecideLeaves with no pending leaves should be a no-op.
func TestDecideLeaves_NoPending(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)

	err := m.DecideLeaves(100, nil, nil, big.NewInt(100000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if wm.leaveRejected != nil || wm.leaveConfirmed != nil {
		t.Fatalf("expected no calls, got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
}

// DecideLeaves DataGreedy: size-only scoring means ring doesn't matter.
func TestDecideLeaves_DataGreedy(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, DataGreedy, wm)

	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 10_000, Ring: 0, Shards: 1},  // small → still bad
		{Filter: mustDecodeHex(t, "bb"), Size: 80_000, Ring: 0, Shards: 1},  // best by size
	}
	pendingLeaves := [][]byte{mustDecodeHex(t, "aa")}

	err := m.DecideLeaves(100, shards, pendingLeaves, big.NewInt(90000))
	if err != nil {
		t.Fatalf("DecideLeaves error: %v", err)
	}
	if len(wm.leaveConfirmed) != 1 || hex.EncodeToString(wm.leaveConfirmed[0]) != "aa" {
		t.Fatalf("expected confirm aa (small shard), got reject=%v confirm=%v",
			toHex(wm.leaveRejected), toHex(wm.leaveConfirmed))
	}
}
