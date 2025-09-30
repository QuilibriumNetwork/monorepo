package worker

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	typesStore "source.quilibrium.com/quilibrium/monorepo/types/store"
)

// mockWorkerStore is a mock implementation of WorkerStore for testing
type mockWorkerStore struct {
	workers         map[uint]*typesStore.WorkerInfo
	workersByFilter map[string]*typesStore.WorkerInfo
	transactions    []mockTransaction
}

type mockTransaction struct {
	operations []operation
	committed  bool
	aborted    bool
}

type operation struct {
	op    string // "set" or "delete"
	key   []byte
	value []byte
}

func newMockWorkerStore() *mockWorkerStore {
	return &mockWorkerStore{
		workers:         make(map[uint]*typesStore.WorkerInfo),
		workersByFilter: make(map[string]*typesStore.WorkerInfo),
	}
}

func (m *mockWorkerStore) NewTransaction(indexed bool) (typesStore.Transaction, error) {
	txn := &mockTransaction{}
	m.transactions = append(m.transactions, *txn)
	return txn, nil
}

func (m *mockWorkerStore) GetWorker(coreId uint) (*typesStore.WorkerInfo, error) {
	worker, exists := m.workers[coreId]
	if !exists {
		return nil, store.ErrNotFound
	}

	workerCopy := *worker
	return &workerCopy, nil
}

func (m *mockWorkerStore) GetWorkerByFilter(filter []byte) (*typesStore.WorkerInfo, error) {
	if len(filter) == 0 {
		return nil, errors.New("filter cannot be empty")
	}
	worker, exists := m.workersByFilter[string(filter)]
	if !exists {
		return nil, store.ErrNotFound
	}
	return worker, nil
}

func (m *mockWorkerStore) PutWorker(txn typesStore.Transaction, worker *typesStore.WorkerInfo) error {
	// Check if worker already exists to clean up old filter index
	if existingWorker, exists := m.workers[worker.CoreId]; exists {
		if len(existingWorker.Filter) > 0 &&
			string(existingWorker.Filter) != string(worker.Filter) {
			delete(m.workersByFilter, string(existingWorker.Filter))
		}
	}

	m.workers[worker.CoreId] = worker
	if len(worker.Filter) > 0 {
		m.workersByFilter[string(worker.Filter)] = worker
	}
	return nil
}

func (m *mockWorkerStore) DeleteWorker(txn typesStore.Transaction, coreId uint) error {
	worker, exists := m.workers[coreId]
	if !exists {
		return store.ErrNotFound
	}
	delete(m.workers, coreId)
	if len(worker.Filter) > 0 {
		delete(m.workersByFilter, string(worker.Filter))
	}
	return nil
}

func (m *mockWorkerStore) RangeWorkers() ([]*typesStore.WorkerInfo, error) {
	var workers []*typesStore.WorkerInfo
	for _, worker := range m.workers {
		workers = append(workers, worker)
	}
	return workers, nil
}

// Mock transaction implementation
func (t *mockTransaction) Set(key, value []byte) error {
	t.operations = append(t.operations, operation{op: "set", key: key, value: value})
	return nil
}

func (t *mockTransaction) Delete(key []byte) error {
	t.operations = append(t.operations, operation{op: "delete", key: key})
	return nil
}

func (t *mockTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return nil, io.NopCloser(nil), nil
}

func (t *mockTransaction) Commit() error {
	t.committed = true
	return nil
}

func (t *mockTransaction) NewIter(lowerBound []byte, upperBound []byte) (typesStore.Iterator, error) {
	return nil, nil
}

func (t *mockTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	return nil
}

func (t *mockTransaction) Abort() error {
	t.aborted = true
	return nil
}

func TestWorkerManager_StartStop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Test starting the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	// Test starting again should fail
	err = manager.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Test stopping the manager
	err = manager.Stop()
	require.NoError(t, err)

	// Test stopping again should fail
	err = manager.Stop()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestWorkerManager_RegisterWorker(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                1,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                []byte("test-filter"),
		TotalStorage:          1000000,
		Automatic:             true,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Verify worker was stored
	storedWorker, err := store.GetWorker(1)
	require.NoError(t, err)
	assert.Equal(t, workerInfo.CoreId, storedWorker.CoreId)
	assert.Equal(t, workerInfo.ListenMultiaddr, storedWorker.ListenMultiaddr)
	assert.Equal(t, workerInfo.Filter, storedWorker.Filter)

	// Test registering the same worker again should fail
	err = manager.RegisterWorker(workerInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestWorkerManager_RegisterWorkerNotStarted(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Try to register without starting
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                1,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                []byte("test-filter"),
		TotalStorage:          1000000,
		Automatic:             true,
	}

	err := manager.RegisterWorker(workerInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestWorkerManager_AllocateDeallocateWorker(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker first
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                1,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                []byte("initial-filter"),
		TotalStorage:          1000000,
		Automatic:             false,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Allocate the worker with a new filter
	newFilter := []byte("new-filter")
	err = manager.AllocateWorker(1, newFilter)
	require.NoError(t, err)

	// Verify filter was updated
	filter, err := manager.GetFilterByWorkerId(1)
	require.NoError(t, err)
	assert.Equal(t, newFilter, filter)

	// Verify we can get worker by new filter
	workerId, err := manager.GetWorkerIdByFilter(newFilter)
	require.NoError(t, err)
	assert.Equal(t, uint(1), workerId)

	// Test allocating again should fail
	err = manager.AllocateWorker(1, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already allocated")

	// Deallocate the worker
	err = manager.DeallocateWorker(1)
	require.NoError(t, err)

	// Test deallocating again should fail
	err = manager.DeallocateWorker(1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allocated")
}

func TestWorkerManager_AllocateNonExistentWorker(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Try to allocate non-existent worker
	err = manager.AllocateWorker(999, []byte("filter"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWorkerManager_GetWorkerIdByFilter(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker
	filter := []byte("unique-filter")
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                42,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                filter,
		TotalStorage:          1000000,
		Automatic:             true,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Get worker ID by filter
	workerId, err := manager.GetWorkerIdByFilter(filter)
	require.NoError(t, err)
	assert.Equal(t, uint(42), workerId)

	// Test non-existent filter
	_, err = manager.GetWorkerIdByFilter([]byte("non-existent"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no worker found")
}

func TestWorkerManager_GetFilterByWorkerId(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker
	filter := []byte("worker-filter")
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                7,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                filter,
		TotalStorage:          1000000,
		Automatic:             false,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Get filter by worker ID
	retrievedFilter, err := manager.GetFilterByWorkerId(7)
	require.NoError(t, err)
	assert.Equal(t, filter, retrievedFilter)

	// Test non-existent worker
	_, err = manager.GetFilterByWorkerId(999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWorkerManager_LoadWorkersOnStart(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()

	// Pre-populate store with workers
	worker1 := &typesStore.WorkerInfo{
		CoreId:                1,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                []byte("filter1"),
		TotalStorage:          1000000,
		Automatic:             true,
	}
	worker2 := &typesStore.WorkerInfo{
		CoreId:                2,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8082",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8083",
		Filter:                []byte("filter2"),
		TotalStorage:          2000000,
		Automatic:             false,
	}

	store.workers[1] = worker1
	store.workersByFilter[string(worker1.Filter)] = worker1
	store.workers[2] = worker2
	store.workersByFilter[string(worker2.Filter)] = worker2

	// Create manager and start it
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Verify workers were loaded into cache
	workerId1, err := manager.GetWorkerIdByFilter([]byte("filter1"))
	require.NoError(t, err)
	assert.Equal(t, uint(1), workerId1)

	workerId2, err := manager.GetWorkerIdByFilter([]byte("filter2"))
	require.NoError(t, err)
	assert.Equal(t, uint(2), workerId2)

	filter1, err := manager.GetFilterByWorkerId(1)
	require.NoError(t, err)
	assert.Equal(t, []byte("filter1"), filter1)

	filter2, err := manager.GetFilterByWorkerId(2)
	require.NoError(t, err)
	assert.Equal(t, []byte("filter2"), filter2)
}

func TestWorkerManager_ConcurrentOperations(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register multiple workers concurrently
	numWorkers := 10
	done := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func(id int) {
			workerInfo := &typesStore.WorkerInfo{
				CoreId:                uint(id),
				ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
				StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
				Filter:                []byte(string(rune('a' + id))),
				TotalStorage:          uint(1000000 * (id + 1)),
				Automatic:             id%2 == 0,
			}
			done <- manager.RegisterWorker(workerInfo)
		}(i)
	}

	// Collect results
	for i := 0; i < numWorkers; i++ {
		err := <-done
		assert.NoError(t, err)
	}

	// Verify all workers were registered
	workers, err := store.RangeWorkers()
	require.NoError(t, err)
	assert.Len(t, workers, numWorkers)
}

func TestWorkerManager_EmptyFilter(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker with empty filter
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                1,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                []byte{}, // Empty filter
		TotalStorage:          1000000,
		Automatic:             true,
		Allocated:             false,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Verify worker was stored
	storedWorker, err := store.GetWorker(1)
	require.NoError(t, err)
	assert.Equal(t, workerInfo.CoreId, storedWorker.CoreId)
	assert.Empty(t, storedWorker.Filter)

	// Try to get worker by empty filter - should fail appropriately
	_, err = manager.GetWorkerIdByFilter([]byte{})
	assert.Error(t, err)

	// Can still get filter (empty) by worker ID
	filter, err := manager.GetFilterByWorkerId(1)
	require.NoError(t, err)
	assert.Empty(t, filter)

	// Allocate with a filter
	newFilter := []byte("new-filter")
	err = manager.AllocateWorker(1, newFilter)
	require.NoError(t, err)

	// Now we should be able to get worker by the new filter
	workerId, err := manager.GetWorkerIdByFilter(newFilter)
	require.NoError(t, err)
	assert.Equal(t, uint(1), workerId)

	// Deallocate the worker
	err = manager.DeallocateWorker(1)
	require.NoError(t, err)

	// Filter should still be set
	filter, err = manager.GetFilterByWorkerId(1)
	require.NoError(t, err)
	assert.Equal(t, newFilter, filter)

	// Can still get by filter after deallocation
	workerId, err = manager.GetWorkerIdByFilter(newFilter)
	require.NoError(t, err)
	assert.Equal(t, uint(1), workerId)
}

func TestWorkerManager_FilterUpdate(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := newMockWorkerStore()
	manager := NewWorkerManager(store, logger, &config.Config{Engine: &config.EngineConfig{}}, func(coreId uint, filter []byte) error { return nil })

	// Start the manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Register a worker with a filter
	oldFilter := []byte("old-filter")
	workerInfo := &typesStore.WorkerInfo{
		CoreId:                2,
		ListenMultiaddr:       "/ip4/127.0.0.1/tcp/8080",
		StreamListenMultiaddr: "/ip4/127.0.0.1/tcp/8081",
		Filter:                oldFilter,
		TotalStorage:          1000000,
		Automatic:             false,
		Allocated:             false,
	}

	err = manager.RegisterWorker(workerInfo)
	require.NoError(t, err)

	// Verify we can get by old filter
	workerId, err := manager.GetWorkerIdByFilter(oldFilter)
	require.NoError(t, err)
	assert.Equal(t, uint(2), workerId)

	// Allocate with a new filter
	newFilter := []byte("new-filter")
	err = manager.AllocateWorker(2, newFilter)
	require.NoError(t, err)

	// Old filter should no longer work
	_, err = manager.GetWorkerIdByFilter(oldFilter)
	assert.Error(t, err, "Looking up old filter should fail after update")

	// New filter should work
	workerId, err = manager.GetWorkerIdByFilter(newFilter)
	require.NoError(t, err)
	assert.Equal(t, uint(2), workerId)

	// Allocate with empty filter (should keep existing filter)
	err = manager.AllocateWorker(2, []byte{})
	assert.Error(t, err) // Should fail because already allocated

	// Deallocate first
	err = manager.DeallocateWorker(2)
	require.NoError(t, err)

	// Now allocate with empty filter - should keep existing filter
	err = manager.AllocateWorker(2, []byte{})
	require.NoError(t, err)

	// Should still have the new filter
	filter, err := manager.GetFilterByWorkerId(2)
	require.NoError(t, err)
	assert.Equal(t, newFilter, filter)
}
