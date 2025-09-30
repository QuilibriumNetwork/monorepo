package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	typesStore "source.quilibrium.com/quilibrium/monorepo/types/store"
	typesWorker "source.quilibrium.com/quilibrium/monorepo/types/worker"
)

type WorkerManager struct {
	store       typesStore.WorkerStore
	logger      *zap.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	started     bool
	config      *config.Config
	proposeFunc func(coreId uint, filter []byte) error

	// When automatic, hold reference to the workers
	dataWorkers []*exec.Cmd

	// In-memory cache for quick lookups
	workersByFilter  map[string]uint // filter hash -> worker id
	filtersByWorker  map[uint][]byte // worker id -> filter
	allocatedWorkers map[uint]bool   // worker id -> allocated status
}

var _ typesWorker.WorkerManager = (*WorkerManager)(nil)

func NewWorkerManager(
	store typesStore.WorkerStore,
	logger *zap.Logger,
	config *config.Config,
	proposeFunc func(coreId uint, filter []byte) error,
) typesWorker.WorkerManager {
	return &WorkerManager{
		store:            store,
		logger:           logger.Named("worker_manager"),
		workersByFilter:  make(map[string]uint),
		filtersByWorker:  make(map[uint][]byte),
		allocatedWorkers: make(map[uint]bool),
		config:           config,
		proposeFunc:      proposeFunc,
	}
}

func (w *WorkerManager) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return errors.New("worker manager already started")
	}

	w.logger.Info("starting worker manager")

	w.ctx, w.cancel = context.WithCancel(ctx)

	// Load existing workers from the store
	if err := w.loadWorkersFromStore(); err != nil {
		w.logger.Error("failed to load workers from store", zap.Error(err))
		return errors.Wrap(err, "start")
	}

	go w.spawnDataWorkers()

	w.started = true
	w.logger.Info("worker manager started successfully")
	return nil
}

func (w *WorkerManager) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		return errors.New("worker manager not started")
	}

	w.logger.Info("stopping worker manager")

	if w.cancel != nil {
		w.cancel()
	}

	w.stopDataWorkers()

	// Clear in-memory caches
	w.workersByFilter = make(map[string]uint)
	w.filtersByWorker = make(map[uint][]byte)
	w.allocatedWorkers = make(map[uint]bool)

	w.started = false

	// Reset metrics
	activeWorkersGauge.Set(0)
	allocatedWorkersGauge.Set(0)
	totalStorageGauge.Set(0)

	w.logger.Info("worker manager stopped")
	return nil
}

func (w *WorkerManager) RegisterWorker(info *typesStore.WorkerInfo) error {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("register"),
	)
	defer timer.ObserveDuration()

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.New("worker manager not started")
	}

	w.logger.Info("registering worker",
		zap.Uint("core_id", info.CoreId),
		zap.String("listen_addr", info.ListenMultiaddr),
		zap.Uint("total_storage", info.TotalStorage),
		zap.Bool("automatic", info.Automatic),
	)

	// Check if worker already exists
	existingWorker, err := w.store.GetWorker(info.CoreId)
	if err == nil && existingWorker != nil {
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.New("worker already registered")
	}

	// Save to store
	txn, err := w.store.NewTransaction(false)
	if err != nil {
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.Wrap(err, "register worker")
	}

	if err := w.store.PutWorker(txn, info); err != nil {
		txn.Abort()
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.Wrap(err, "register worker")
	}

	if err := txn.Commit(); err != nil {
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.Wrap(err, "register worker")
	}

	// Update in-memory cache
	if len(info.Filter) > 0 {
		filterKey := string(info.Filter)
		w.workersByFilter[filterKey] = info.CoreId
	}
	w.filtersByWorker[info.CoreId] = info.Filter

	// Update metrics
	activeWorkersGauge.Inc()
	totalStorageGauge.Add(float64(info.TotalStorage))
	workerOperationsTotal.WithLabelValues("register", "success").Inc()

	w.logger.Info(
		"worker registered successfully",
		zap.Uint("core_id", info.CoreId),
	)
	return nil
}

func (w *WorkerManager) AllocateWorker(coreId uint, filter []byte) error {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("allocate"),
	)
	defer timer.ObserveDuration()

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		return errors.Wrap(
			errors.New("worker manager not started"),
			"allocate worker",
		)
	}

	w.logger.Info("allocating worker",
		zap.Uint("core_id", coreId),
		zap.Binary("filter", filter),
	)

	// Check if worker exists
	worker, err := w.store.GetWorker(coreId)
	if err != nil {
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		if errors.Is(err, store.ErrNotFound) {
			return errors.Wrap(
				errors.New("worker not found"),
				"allocate worker",
			)
		}
		return errors.Wrap(err, "allocate worker")
	}

	// Check if already allocated
	if worker.Allocated {
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		return errors.New("worker already allocated")
	}

	// Update worker filter if provided
	if len(filter) > 0 && string(worker.Filter) != string(filter) {
		// Remove old filter mapping from cache
		if len(worker.Filter) > 0 {
			delete(w.workersByFilter, string(worker.Filter))
		}
		worker.Filter = filter
	}

	// Update allocation status
	worker.Allocated = true

	// Save to store
	txn, err := w.store.NewTransaction(false)
	if err != nil {
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		return errors.Wrap(err, "allocate worker")
	}

	if err := w.store.PutWorker(txn, worker); err != nil {
		txn.Abort()
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		return errors.Wrap(err, "allocate worker")
	}

	if err := txn.Commit(); err != nil {
		workerOperationsTotal.WithLabelValues("allocate", "error").Inc()
		return errors.Wrap(err, "allocate worker")
	}

	// Update cache
	if len(worker.Filter) > 0 {
		filterKey := string(worker.Filter)
		w.workersByFilter[filterKey] = coreId
	}
	w.filtersByWorker[coreId] = worker.Filter
	w.allocatedWorkers[coreId] = true

	// Update metrics
	allocatedWorkersGauge.Inc()
	workerOperationsTotal.WithLabelValues("allocate", "success").Inc()

	w.logger.Info("worker allocated successfully", zap.Uint("core_id", coreId))
	return nil
}

func (w *WorkerManager) DeallocateWorker(coreId uint) error {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("deallocate"),
	)
	defer timer.ObserveDuration()

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		return errors.Wrap(
			errors.New("worker manager not started"),
			"deallocate worker",
		)
	}

	w.logger.Info("deallocating worker", zap.Uint("core_id", coreId))

	// Check if worker exists
	worker, err := w.store.GetWorker(coreId)
	if err != nil {
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		if errors.Is(err, store.ErrNotFound) {
			return errors.New("worker not found")
		}
		return errors.Wrap(err, "deallocate worker")
	}

	// Check if allocated
	if !worker.Allocated {
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		return errors.Wrap(
			errors.New("worker not allocated"),
			"deallocate worker",
		)
	}

	// Update allocation status
	worker.Allocated = false

	// Save to store
	txn, err := w.store.NewTransaction(false)
	if err != nil {
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		return errors.Wrap(err, "deallocate worker")
	}

	if err := w.store.PutWorker(txn, worker); err != nil {
		txn.Abort()
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		return errors.Wrap(err, "deallocate worker")
	}

	if err := txn.Commit(); err != nil {
		workerOperationsTotal.WithLabelValues("deallocate", "error").Inc()
		return errors.Wrap(err, "deallocate worker")
	}

	// Mark as deallocated in cache
	delete(w.allocatedWorkers, coreId)

	// Update metrics
	allocatedWorkersGauge.Dec()
	workerOperationsTotal.WithLabelValues("deallocate", "success").Inc()

	w.logger.Info("worker deallocated successfully", zap.Uint("core_id", coreId))
	return nil
}

func (w *WorkerManager) GetWorkerIdByFilter(filter []byte) (uint, error) {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("lookup"),
	)
	defer timer.ObserveDuration()

	w.mu.RLock()
	defer w.mu.RUnlock()

	if !w.started {
		return 0, errors.Wrap(
			errors.New("worker manager not started"),
			"get worker id by filter",
		)
	}

	if len(filter) == 0 {
		return 0, errors.Wrap(
			errors.New("filter cannot be empty"),
			"get worker id by filter",
		)
	}

	// Check in-memory cache first
	filterKey := string(filter)
	if coreId, exists := w.workersByFilter[filterKey]; exists {
		return coreId, nil
	}

	// Fallback to store
	worker, err := w.store.GetWorkerByFilter(filter)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, errors.Wrap(
				errors.New("no worker found for filter"),
				"get worker id by filter",
			)
		}
		return 0, errors.Wrap(err, "get worker id by filter")
	}

	return worker.CoreId, nil
}

func (w *WorkerManager) GetFilterByWorkerId(coreId uint) ([]byte, error) {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("lookup"),
	)
	defer timer.ObserveDuration()

	w.mu.RLock()
	defer w.mu.RUnlock()

	if !w.started {
		return nil, errors.Wrap(
			errors.New("worker manager not started"),
			"get filter by worker id",
		)
	}

	// Check in-memory cache first
	if filter, exists := w.filtersByWorker[coreId]; exists {
		return filter, nil
	}

	// Fallback to store
	worker, err := w.store.GetWorker(coreId)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.Wrap(
				errors.New("worker not found"),
				"get filter by worker id",
			)
		}
		return nil, errors.Wrap(err, "get filter by worker id")
	}

	return worker.Filter, nil
}

func (w *WorkerManager) RangeWorkers() ([]*typesStore.WorkerInfo, error) {
	return w.store.RangeWorkers()
}

// ProposeAllocation invokes a proposal function set by the parent of the
// manager.
func (w *WorkerManager) ProposeAllocation(coreId uint, filter []byte) error {
	return w.proposeFunc(coreId, filter)
}

// loadWorkersFromStore loads all workers from persistent storage into memory
func (w *WorkerManager) loadWorkersFromStore() error {
	workers, err := w.store.RangeWorkers()
	if err != nil {
		return errors.Wrap(err, "load workers from store")
	}

	var totalStorage uint64
	var allocatedCount int
	for _, worker := range workers {
		// Update cache
		if len(worker.Filter) > 0 {
			filterKey := string(worker.Filter)
			w.workersByFilter[filterKey] = worker.CoreId
		}
		w.filtersByWorker[worker.CoreId] = worker.Filter
		if worker.Allocated {
			w.allocatedWorkers[worker.CoreId] = true
			allocatedCount++
		}
		totalStorage += uint64(worker.TotalStorage)
	}

	// Update metrics
	activeWorkersGauge.Set(float64(len(workers)))
	allocatedWorkersGauge.Set(float64(allocatedCount))
	totalStorageGauge.Set(float64(totalStorage))

	w.logger.Info(fmt.Sprintf("loaded %d workers from store", len(workers)))
	return nil
}

func (w *WorkerManager) spawnDataWorkers() {
	if len(w.config.Engine.DataWorkerStreamMultiaddrs) != 0 {
		w.logger.Warn(
			"data workers configured by multiaddr, be sure these are running...",
		)
		return
	}

	process, err := os.Executable()
	if err != nil {
		w.logger.Panic("failed to get executable path", zap.Error(err))
	}

	w.dataWorkers = make([]*exec.Cmd, w.config.Engine.DataWorkerCount)
	w.logger.Info(
		"spawning data workers",
		zap.Int("count", w.config.Engine.DataWorkerCount),
	)

	for i := 1; i <= w.config.Engine.DataWorkerCount; i++ {
		i := i
		go func() {
			for {
				args := []string{
					fmt.Sprintf("--core=%d", i),
					fmt.Sprintf("--parent-process=%d", os.Getpid()),
				}
				args = append(args, os.Args[1:]...)
				cmd := exec.Command(process, args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stdout
				err := cmd.Start()
				if err != nil {
					w.logger.Panic(
						"failed to start data worker",
						zap.String("cmd", cmd.String()),
						zap.Error(err),
					)
				}

				w.dataWorkers[i-1] = cmd
				cmd.Wait()
				time.Sleep(25 * time.Millisecond)
				w.logger.Info(
					"Data worker stopped, restarting...",
					zap.Int("worker_number", i),
				)
			}
		}()
	}
}

func (w *WorkerManager) stopDataWorkers() {
	for i := 0; i < len(w.dataWorkers); i++ {
		err := w.dataWorkers[i].Process.Signal(os.Kill)
		if err != nil {
			w.logger.Info(
				"unable to kill worker",
				zap.Int("pid", w.dataWorkers[i].Process.Pid),
				zap.Error(err),
			)
		}
	}
}
