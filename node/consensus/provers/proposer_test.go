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
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type mockSizer struct {
	n *big.Int
}

func (m *mockSizer) GetSize(_ *tries.ShardKey, _ []int) *big.Int {
	return new(big.Int).Set(m.n)
}

type mockWorkerManager struct {
	workers        []*store.WorkerInfo
	lastWorkers    []uint
	lastFiltersHex []string
	rejected       [][]byte
	confirmed      [][]byte
}

func (m *mockWorkerManager) DecideAllocations(reject [][]byte, confirm [][]byte) error {
	m.rejected = reject
	m.confirmed = confirm
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
	panic("unimplemented")
}

func (m *mockWorkerManager) Start(ctx context.Context) error {
	panic("unimplemented")
}

func (m *mockWorkerManager) Stop() error {
	panic("unimplemented")
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
	world := &mockSizer{n: big.NewInt(1 << 30)} // 1 GB
	const units = 8000000000

	return NewManager(logger, world, nil, wm, units, strategy)
}

func createWorkers(n int) []*store.WorkerInfo {
	ws := make([]*store.WorkerInfo, n)
	for i := 0; i < n; i++ {
		ws[i] = &store.WorkerInfo{
			CoreId:    uint(i + 1),
			Allocated: false,
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
		_, err := m.PlanAndAllocate(100, shards, 1)
		if err != nil {
			t.Fatalf("PlanAndAllocate failed: %v", err)
		}
		if len(wm.lastFiltersHex) != 1 {
			t.Fatalf("expected one allocation, got %d", len(wm.lastFiltersHex))
		}
		firstPickCounts[wm.lastFiltersHex[0]]++
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
		_, err := m.PlanAndAllocate(100, shards, 1)
		if err != nil {
			t.Fatalf("PlanAndAllocate failed: %v", err)
		}
		if len(wm.lastFiltersHex) != 1 {
			t.Fatalf("expected one allocation, got %d", len(wm.lastFiltersHex))
		}
		if wm.lastFiltersHex[0] != "01" {
			t.Fatalf("expected deterministic lexicographic first (01) in DataGreedy, got %s", wm.lastFiltersHex[0])
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

	_, err := m.PlanAndAllocate(100, shards, 1)
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
	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "01"), Size: 50_000, Ring: 0, Shards: 1},
		{Filter: mustDecodeHex(t, "02"), Size: 200_000, Ring: 0, Shards: 1}, // best
		{Filter: mustDecodeHex(t, "03"), Size: 50_000, Ring: 0, Shards: 1},
	}
	pending := [][]byte{mustDecodeHex(t, "02")}

	err := m.DecideJoins(100, shards, pending)
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

	err := m.DecideJoins(100, shards, pending)
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.rejected) != 1 || hex.EncodeToString(wm.rejected[0]) != "01" || len(wm.confirmed) != 0 {
		t.Fatalf("expected reject 01, got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

// Tie -> confirm (RewardGreedy)
func TestDecideJoins_TieConfirms_RewardGreedy(t *testing.T) {

	wm := &mockWorkerManager{}
	m := newTestManager(t, RewardGreedy, wm)
	// Same size/ring/shards -> same score
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "01"), Size: 100_000, Ring: 1, Shards: 4},
		{Filter: mustDecodeHex(t, "02"), Size: 100_000, Ring: 1, Shards: 4},
	}
	pending := [][]byte{mustDecodeHex(t, "02")}

	err := m.DecideJoins(100, shards, pending)
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	if len(wm.rejected) != 0 || len(wm.confirmed) != 1 || hex.EncodeToString(wm.confirmed[0]) != "02" {
		t.Fatalf("expected confirm 02 on tie, got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
	}
}

func TestDecideJoins_DataGreedy_SizeOnly(t *testing.T) {
	wm := &mockWorkerManager{}
	m := newTestManager(t, DataGreedy, wm)
	shards := []ShardDescriptor{
		{Filter: mustDecodeHex(t, "aa"), Size: 10_000, Ring: 3, Shards: 16}, // worse by size
		{Filter: mustDecodeHex(t, "bb"), Size: 80_000, Ring: 0, Shards: 1},  // best by size
		{Filter: mustDecodeHex(t, "cc"), Size: 80_000, Ring: 5, Shards: 64}, // tie by size
	}
	// Pending on aa (worse), bb (best), cc (tie-best)
	pending := [][]byte{mustDecodeHex(t, "aa"), mustDecodeHex(t, "bb"), mustDecodeHex(t, "cc")}
	err := m.DecideJoins(100, shards, pending)
	if err != nil {
		t.Fatalf("DecideJoins error: %v", err)
	}
	rej := setOf(toHex(wm.rejected))
	cfm := setOf(toHex(wm.confirmed))
	if !(rej["aa"] && !rej["bb"] && !rej["cc"] && cfm["bb"] && cfm["cc"]) {
		t.Fatalf("expected reject{aa} confirm{bb,cc}; got reject=%v confirm=%v", toHex(wm.rejected), toHex(wm.confirmed))
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

	err := m.DecideJoins(100, shards, pending)
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
