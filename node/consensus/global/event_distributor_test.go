package global

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
)

// mockWorkerManager is a simple mock for testing reconcileWorkerAllocations
type mockWorkerManager struct {
	workers map[uint]*store.WorkerInfo
}

func newMockWorkerManager() *mockWorkerManager {
	return &mockWorkerManager{
		workers: make(map[uint]*store.WorkerInfo),
	}
}

func (m *mockWorkerManager) Start(ctx context.Context) error { return nil }
func (m *mockWorkerManager) Stop() error                     { return nil }
func (m *mockWorkerManager) AllocateWorker(coreId uint, filter []byte) error {
	if w, ok := m.workers[coreId]; ok {
		w.Filter = slices.Clone(filter)
		w.Allocated = true
	}
	return nil
}
func (m *mockWorkerManager) DeallocateWorker(coreId uint) error {
	if w, ok := m.workers[coreId]; ok {
		w.Filter = nil
		w.Allocated = false
	}
	return nil
}
func (m *mockWorkerManager) CheckWorkersConnected() ([]uint, error) { return nil, nil }
func (m *mockWorkerManager) GetWorkerIdByFilter(filter []byte) (uint, error) {
	for _, w := range m.workers {
		if string(w.Filter) == string(filter) {
			return w.CoreId, nil
		}
	}
	return 0, nil
}
func (m *mockWorkerManager) GetFilterByWorkerId(coreId uint) ([]byte, error) {
	if w, ok := m.workers[coreId]; ok {
		return w.Filter, nil
	}
	return nil, nil
}
func (m *mockWorkerManager) RegisterWorker(info *store.WorkerInfo) error {
	m.workers[info.CoreId] = info
	return nil
}
func (m *mockWorkerManager) ProposeAllocations(coreIds []uint, filters [][]byte) error {
	return nil
}
func (m *mockWorkerManager) DecideAllocations(reject [][]byte, confirm [][]byte) error {
	return nil
}
func (m *mockWorkerManager) RangeWorkers() ([]*store.WorkerInfo, error) {
	result := make([]*store.WorkerInfo, 0, len(m.workers))
	for _, w := range m.workers {
		result = append(result, w)
	}
	return result, nil
}

var _ worker.WorkerManager = (*mockWorkerManager)(nil)

func TestReconcileWorkerAllocations_RejectedAllocationClearsFilter(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with an assigned filter (simulating a pending join)
	filter1 := []byte("shard-filter-1")
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          false,
		PendingFilterFrame: 100, // join was proposed at frame 100
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	// Create the engine with just the worker manager
	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Case 1: Allocation is rejected - filter should be cleared
	selfWithRejected := &typesconsensus.ProverInfo{
		Address: []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{
			{
				Status:             typesconsensus.ProverStatusRejected,
				ConfirmationFilter: filter1,
				JoinFrameNumber:    100,
			},
		},
	}

	// Run reconciliation at frame 200 (past the join frame but within grace period)
	engine.reconcileWorkerAllocations(200, selfWithRejected)

	// Verify the worker's filter was cleared because the allocation is rejected
	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Nil(t, workers[0].Filter, "rejected allocation should cause filter to be cleared")
	assert.False(t, workers[0].Allocated, "rejected allocation should not be allocated")
	assert.Equal(t, uint64(0), workers[0].PendingFilterFrame, "pending frame should be cleared")
}

func TestReconcileWorkerAllocations_ActiveAllocationKeepsFilter(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with an assigned filter
	filter1 := []byte("shard-filter-1")
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          true,
		PendingFilterFrame: 0,
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Case 2: Allocation is active - filter should be kept
	selfWithActive := &typesconsensus.ProverInfo{
		Address: []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{
			{
				Status:             typesconsensus.ProverStatusActive,
				ConfirmationFilter: filter1,
				JoinFrameNumber:    100,
			},
		},
	}

	engine.reconcileWorkerAllocations(200, selfWithActive)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, filter1, workers[0].Filter, "active allocation should keep filter")
	assert.True(t, workers[0].Allocated, "active allocation should be allocated")
}

func TestReconcileWorkerAllocations_JoiningAllocationKeepsFilter(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with an assigned filter
	filter1 := []byte("shard-filter-1")
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          false,
		PendingFilterFrame: 100,
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Case 3: Allocation is joining - filter should be kept
	selfWithJoining := &typesconsensus.ProverInfo{
		Address: []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{
			{
				Status:             typesconsensus.ProverStatusJoining,
				ConfirmationFilter: filter1,
				JoinFrameNumber:    100,
			},
		},
	}

	engine.reconcileWorkerAllocations(200, selfWithJoining)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, filter1, workers[0].Filter, "joining allocation should keep filter")
	assert.False(t, workers[0].Allocated, "joining allocation should not be allocated yet")
	assert.Equal(t, uint64(100), workers[0].PendingFilterFrame, "pending frame should be join frame")
}

func TestReconcileWorkerAllocations_MultipleWorkersWithMixedStates(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create workers with different filters
	filter1 := []byte("shard-filter-1")
	filter2 := []byte("shard-filter-2")
	filter3 := []byte("shard-filter-3")

	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          true,
		PendingFilterFrame: 0,
	}
	worker2 := &store.WorkerInfo{
		CoreId:             2,
		Filter:             slices.Clone(filter2),
		Allocated:          false,
		PendingFilterFrame: 100,
	}
	worker3 := &store.WorkerInfo{
		CoreId:             3,
		Filter:             slices.Clone(filter3),
		Allocated:          false,
		PendingFilterFrame: 100,
	}
	require.NoError(t, wm.RegisterWorker(worker1))
	require.NoError(t, wm.RegisterWorker(worker2))
	require.NoError(t, wm.RegisterWorker(worker3))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Mixed states: one active, one joining, one rejected
	self := &typesconsensus.ProverInfo{
		Address: []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{
			{
				Status:             typesconsensus.ProverStatusActive,
				ConfirmationFilter: filter1,
				JoinFrameNumber:    50,
			},
			{
				Status:             typesconsensus.ProverStatusJoining,
				ConfirmationFilter: filter2,
				JoinFrameNumber:    100,
			},
			{
				Status:             typesconsensus.ProverStatusRejected,
				ConfirmationFilter: filter3,
				JoinFrameNumber:    100,
			},
		},
	}

	engine.reconcileWorkerAllocations(200, self)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 3)

	// Find each worker by core ID
	workerMap := make(map[uint]*store.WorkerInfo)
	for _, w := range workers {
		workerMap[w.CoreId] = w
	}

	// Worker 1: active allocation - should keep filter and be allocated
	w1 := workerMap[1]
	assert.Equal(t, filter1, w1.Filter, "active worker should keep filter")
	assert.True(t, w1.Allocated, "active worker should be allocated")

	// Worker 2: joining allocation - should keep filter but not be allocated
	w2 := workerMap[2]
	assert.Equal(t, filter2, w2.Filter, "joining worker should keep filter")
	assert.False(t, w2.Allocated, "joining worker should not be allocated")

	// Worker 3: rejected allocation - should have filter cleared
	w3 := workerMap[3]
	assert.Nil(t, w3.Filter, "rejected worker should have filter cleared")
	assert.False(t, w3.Allocated, "rejected worker should not be allocated")
}

func TestReconcileWorkerAllocations_RejectedWithNoFreeWorker(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with no filter initially
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             nil,
		Allocated:          false,
		PendingFilterFrame: 0,
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// A rejected allocation shouldn't try to assign a worker
	filter1 := []byte("shard-filter-1")
	self := &typesconsensus.ProverInfo{
		Address: []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{
			{
				Status:             typesconsensus.ProverStatusRejected,
				ConfirmationFilter: filter1,
				JoinFrameNumber:    100,
			},
		},
	}

	engine.reconcileWorkerAllocations(200, self)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)

	// The free worker should remain free - rejected allocation should not consume it
	assert.Nil(t, workers[0].Filter, "free worker should remain free when only rejected allocations exist")
	assert.False(t, workers[0].Allocated, "free worker should not be allocated")
}

func TestReconcileWorkerAllocations_UnconfirmedProposalClearsAfterTimeout(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with a filter set from a join proposal that never landed
	filter1 := []byte("shard-filter-1")
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          false,
		PendingFilterFrame: 100, // proposal was made at frame 100
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Prover has no allocations at all - the proposal never landed on-chain
	self := &typesconsensus.ProverInfo{
		Address:     []byte("prover-address"),
		Allocations: []typesconsensus.ProverAllocationInfo{},
	}

	// At frame 105 (5 frames after proposal), filter should NOT be cleared yet
	engine.reconcileWorkerAllocations(105, self)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, filter1, workers[0].Filter, "filter should be kept within timeout window")
	assert.Equal(t, uint64(100), workers[0].PendingFilterFrame, "pending frame should be preserved")

	// At frame 111 (11 frames after proposal, past the 10 frame timeout), filter SHOULD be cleared
	engine.reconcileWorkerAllocations(111, self)

	workers, err = wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Nil(t, workers[0].Filter, "filter should be cleared after proposal timeout")
	assert.False(t, workers[0].Allocated, "worker should not be allocated")
	assert.Equal(t, uint64(0), workers[0].PendingFilterFrame, "pending frame should be cleared")
}

func TestReconcileWorkerAllocations_UnconfirmedProposalWithNilSelf(t *testing.T) {
	logger := zap.NewNop()
	wm := newMockWorkerManager()

	// Create a worker with a filter set from a join proposal
	filter1 := []byte("shard-filter-1")
	worker1 := &store.WorkerInfo{
		CoreId:             1,
		Filter:             slices.Clone(filter1),
		Allocated:          false,
		PendingFilterFrame: 100,
	}
	require.NoError(t, wm.RegisterWorker(worker1))

	engine := &GlobalConsensusEngine{
		logger:        logger,
		workerManager: wm,
	}

	// Even with nil self (no prover info yet), after timeout the filter should be cleared
	// This handles the case where we proposed but haven't synced prover info yet

	// At frame 105, still within timeout - should keep filter
	engine.reconcileWorkerAllocations(105, nil)

	workers, err := wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, filter1, workers[0].Filter, "filter should be kept within timeout window even with nil self")

	// At frame 111, past timeout - should clear filter
	engine.reconcileWorkerAllocations(111, nil)

	workers, err = wm.RangeWorkers()
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Nil(t, workers[0].Filter, "filter should be cleared after timeout even with nil self")
}
