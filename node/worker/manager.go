package worker

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
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
	proposeFunc func(
		coreIds []uint,
		filters [][]byte,
		serviceClients map[uint]*grpc.ClientConn,
	) error
	decideFunc func(
		reject [][]byte,
		confirm [][]byte,
	) error

	// When automatic, hold reference to the workers
	dataWorkers []*exec.Cmd

	// IPC service clients
	serviceClients map[uint]*grpc.ClientConn

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
	proposeFunc func(
		coreIds []uint,
		filters [][]byte,
		serviceClients map[uint]*grpc.ClientConn,
	) error,
	decideFunc func(
		reject [][]byte,
		confirm [][]byte,
	) error,
) typesWorker.WorkerManager {
	return &WorkerManager{
		store:            store,
		logger:           logger.Named("worker_manager"),
		workersByFilter:  make(map[string]uint),
		filtersByWorker:  make(map[uint][]byte),
		allocatedWorkers: make(map[uint]bool),
		serviceClients:   make(map[uint]*grpc.ClientConn),
		config:           config,
		proposeFunc:      proposeFunc,
		decideFunc:       decideFunc,
	}
}

func (w *WorkerManager) isStarted() bool {
	w.mu.RLock()
	started := w.started
	w.mu.RUnlock()
	return started
}

func (w *WorkerManager) resetWorkerCaches() {
	w.mu.Lock()
	w.workersByFilter = make(map[string]uint)
	w.filtersByWorker = make(map[uint][]byte)
	w.allocatedWorkers = make(map[uint]bool)
	w.mu.Unlock()
}

func (w *WorkerManager) setWorkerFilterMapping(
	coreID uint,
	filter []byte,
) {
	w.mu.Lock()
	if previous, ok := w.filtersByWorker[coreID]; ok {
		if len(previous) > 0 {
			delete(w.workersByFilter, string(previous))
		}
	}
	if len(filter) > 0 {
		w.workersByFilter[string(filter)] = coreID
	}
	w.filtersByWorker[coreID] = filter // buildutils:allow-slice-alias slice is static
	w.mu.Unlock()
}

func (w *WorkerManager) setWorkerAllocation(coreID uint, allocated bool) {
	w.mu.Lock()
	if allocated {
		w.allocatedWorkers[coreID] = true
	} else {
		delete(w.allocatedWorkers, coreID)
	}
	w.mu.Unlock()
}

func (w *WorkerManager) getServiceClient(coreID uint) (
	*grpc.ClientConn,
	bool,
) {
	w.mu.RLock()
	client, ok := w.serviceClients[coreID]
	w.mu.RUnlock()
	return client, ok
}

func (w *WorkerManager) setServiceClient(
	coreID uint,
	client *grpc.ClientConn,
) {
	w.mu.Lock()
	w.serviceClients[coreID] = client
	w.mu.Unlock()
}

func (w *WorkerManager) deleteServiceClient(coreID uint) {
	w.mu.Lock()
	delete(w.serviceClients, coreID)
	w.mu.Unlock()
}

func (w *WorkerManager) copyServiceClients() map[uint]*grpc.ClientConn {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[uint]*grpc.ClientConn, len(w.serviceClients))
	for id, client := range w.serviceClients {
		out[id] = client
	}
	return out
}

func (w *WorkerManager) currentContext() context.Context {
	w.mu.RLock()
	ctx := w.ctx
	w.mu.RUnlock()
	return ctx
}

func (w *WorkerManager) purgeWorkerFromCache(
	coreID uint,
	filter []byte,
) {
	w.mu.Lock()
	delete(w.filtersByWorker, coreID)
	delete(w.allocatedWorkers, coreID)
	if len(filter) > 0 {
		delete(w.workersByFilter, string(filter))
	}
	w.mu.Unlock()
}

func (w *WorkerManager) closeServiceClient(coreID uint) {
	client, ok := w.getServiceClient(coreID)
	if !ok {
		return
	}
	_ = client.Close()
	w.deleteServiceClient(coreID)
}

func (w *WorkerManager) setDataWorkers(size int) {
	w.mu.Lock()
	w.dataWorkers = make([]*exec.Cmd, size)
	w.mu.Unlock()
}

func (w *WorkerManager) updateDataWorker(
	index int,
	cmd *exec.Cmd,
) {
	w.mu.Lock()
	if index >= 0 && index < len(w.dataWorkers) {
		w.dataWorkers[index] = cmd
	}
	w.mu.Unlock()
}

func (w *WorkerManager) getDataWorker(index int) *exec.Cmd {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if index >= 0 && index < len(w.dataWorkers) {
		return w.dataWorkers[index]
	}
	return nil
}

func (w *WorkerManager) dataWorkerLen() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.dataWorkers)
}

func (w *WorkerManager) hasWorkerFilter(coreID uint) bool {
	w.mu.RLock()
	_, ok := w.filtersByWorker[coreID]
	w.mu.RUnlock()
	return ok
}

func (w *WorkerManager) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return errors.New("worker manager already started")
	}

	w.logger.Info("starting worker manager")

	w.ctx, w.cancel = context.WithCancel(ctx)
	w.started = true
	w.mu.Unlock()

	go w.spawnDataWorkers()

	// Load existing workers from the store
	if err := w.loadWorkersFromStore(); err != nil {
		w.logger.Error("failed to load workers from store", zap.Error(err))
		return errors.Wrap(err, "start")
	}

	w.logger.Info("worker manager started successfully")
	return nil
}

func (w *WorkerManager) Stop() error {
	w.mu.Lock()

	if !w.started {
		w.mu.Unlock()
		return errors.New("worker manager not started")
	}

	w.logger.Info("stopping worker manager")

	cancel := w.cancel
	w.cancel = nil
	w.ctx = nil
	w.started = false
	w.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	w.stopDataWorkers()

	// Clear in-memory caches
	w.resetWorkerCaches()

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

	return w.registerWorker(info)
}

func (w *WorkerManager) registerWorker(info *typesStore.WorkerInfo) error {
	if !w.isStarted() {
		workerOperationsTotal.WithLabelValues("register", "error").Inc()
		return errors.New("worker manager not started")
	}

	existing, err := w.store.GetWorker(info.CoreId)
	creating := false
	if err != nil {
		if errors.Is(err, typesStore.ErrNotFound) {
			creating = true
		} else {
			workerOperationsTotal.WithLabelValues("register", "error").Inc()
			return errors.Wrap(err, "register worker")
		}
	}

	if !creating {
		if info.ListenMultiaddr == "" {
			info.ListenMultiaddr = existing.ListenMultiaddr
		}
		if info.StreamListenMultiaddr == "" {
			info.StreamListenMultiaddr = existing.StreamListenMultiaddr
		}
		if info.TotalStorage == 0 {
			info.TotalStorage = existing.TotalStorage
		}
		info.Automatic = existing.Automatic
	}

	logMsg := "registering worker"
	if !creating {
		logMsg = "updating worker"
	}

	w.logger.Info(logMsg,
		zap.Uint("core_id", info.CoreId),
		zap.String("listen_addr", info.ListenMultiaddr),
		zap.Uint("total_storage", info.TotalStorage),
		zap.Bool("automatic", info.Automatic),
	)

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
	w.setWorkerFilterMapping(info.CoreId, info.Filter)

	// Update metrics
	if creating {
		activeWorkersGauge.Inc()
		totalStorageGauge.Add(float64(info.TotalStorage))
	} else if existing != nil && info.TotalStorage != existing.TotalStorage {
		delta := float64(int64(info.TotalStorage) - int64(existing.TotalStorage))
		totalStorageGauge.Add(delta)
	}
	workerOperationsTotal.WithLabelValues("register", "success").Inc()

	msg := "worker registered successfully"
	if !creating {
		msg = "worker updated successfully"
	}
	w.logger.Info(
		msg,
		zap.Uint("core_id", info.CoreId),
	)

	return nil
}

func (w *WorkerManager) AllocateWorker(coreId uint, filter []byte) error {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("allocate"),
	)
	defer timer.ObserveDuration()

	if !w.isStarted() {
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
		if errors.Is(err, typesStore.ErrNotFound) {
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
		worker.Filter = filter // buildutils:allow-slice-alias slice is static
	}

	// Update allocation status
	worker.Allocated = true
	worker.PendingFilterFrame = 0

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
	w.setWorkerFilterMapping(coreId, worker.Filter)
	w.setWorkerAllocation(coreId, true)

	// Refresh worker
	if err := w.respawnWorker(coreId, worker.Filter); err != nil {
		return errors.Wrap(err, "allocate worker")
	}

	// Update metrics
	allocatedWorkersGauge.Inc()
	workerOperationsTotal.WithLabelValues("allocate", "success").Inc()

	w.logger.Info("worker allocated successfully", zap.Uint("core_id", coreId))
	return nil
}

func (w *WorkerManager) RespawnWorker(coreId uint, filter []byte) error {
	return w.respawnWorker(coreId, filter)
}

func (w *WorkerManager) DeallocateWorker(coreId uint) error {
	timer := prometheus.NewTimer(
		workerOperationDuration.WithLabelValues("deallocate"),
	)
	defer timer.ObserveDuration()

	if !w.isStarted() {
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
		if errors.Is(err, typesStore.ErrNotFound) {
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

	// Update allocation status and clear filter
	worker.Allocated = false
	worker.Filter = nil
	worker.PendingFilterFrame = 0

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

	// Update cache
	w.setWorkerFilterMapping(coreId, nil)
	w.setWorkerAllocation(coreId, false)

	// Refresh worker
	if err := w.respawnWorker(coreId, []byte{}); err != nil {
		return errors.Wrap(err, "allocate worker")
	}

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

	if !w.isStarted() {
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
	w.mu.RLock()
	coreId, exists := w.workersByFilter[filterKey]
	w.mu.RUnlock()
	if exists {
		return coreId, nil
	}

	// Fallback to store
	worker, err := w.store.GetWorkerByFilter(filter)
	if err != nil {
		if errors.Is(err, typesStore.ErrNotFound) {
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

	if !w.isStarted() {
		return nil, errors.Wrap(
			errors.New("worker manager not started"),
			"get filter by worker id",
		)
	}

	// Check in-memory cache first
	w.mu.RLock()
	filter, exists := w.filtersByWorker[coreId]
	w.mu.RUnlock()
	if exists {
		return filter, nil
	}

	// Fallback to store
	worker, err := w.store.GetWorker(coreId)
	if err != nil {
		if errors.Is(err, typesStore.ErrNotFound) {
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
	workers, err := w.store.RangeWorkers()
	if err != nil {
		return nil, err
	}

	if len(workers) != int(w.config.Engine.DataWorkerCount) {
		for i := uint(1); i <= uint(w.config.Engine.DataWorkerCount); i++ {
			if _, ok := w.getServiceClient(i); ok {
				continue
			}
			if _, err := w.getIPCOfWorker(i); err != nil {
				w.logger.Error(
					"could not initialize worker for range",
					zap.Uint("core_id", i),
					zap.Error(err),
				)
			}
		}
		workers, err = w.store.RangeWorkers()
		if err != nil {
			return nil, err
		}
	}

	return workers, nil
}

const workerConnectivityTimeout = 5 * time.Second

func (w *WorkerManager) CheckWorkersConnected() ([]uint, error) {
	workers, err := w.store.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "check worker connectivity")
	}

	unreachable := make([]uint, 0)
	for _, worker := range workers {
		_, err := w.getIPCOfWorkerWithTimeout(
			worker.CoreId,
			workerConnectivityTimeout,
		)
		if err != nil {
			w.logger.Debug(
				"worker unreachable during connectivity check",
				zap.Uint("core_id", worker.CoreId),
				zap.Error(err),
			)
			w.closeServiceClient(worker.CoreId)
			unreachable = append(unreachable, worker.CoreId)
		}
	}

	return unreachable, nil
}

// ProposeAllocations invokes a proposal function set by the parent of the
// manager.
func (w *WorkerManager) ProposeAllocations(
	coreIds []uint,
	filters [][]byte,
) error {
	for _, coreId := range coreIds {
		_, err := w.getIPCOfWorker(coreId)
		if err != nil {
			w.logger.Error("could not get ipc of worker", zap.Error(err))
			return errors.Wrap(err, "allocate worker")
		}
	}
	return w.proposeFunc(coreIds, filters, w.copyServiceClients())
}

// DecideAllocations invokes a deciding function set by the parent of the
// manager.
func (w *WorkerManager) DecideAllocations(
	reject [][]byte,
	confirm [][]byte,
) error {
	return w.decideFunc(reject, confirm)
}

// loadWorkersFromStore loads all workers from persistent storage into memory
func (w *WorkerManager) loadWorkersFromStore() error {
	workers, err := w.store.RangeWorkers()
	if err != nil {
		return errors.Wrap(err, "load workers from store")
	}

	if len(workers) != int(w.config.Engine.DataWorkerCount) {
		existingWorkers := make(map[uint]*typesStore.WorkerInfo, len(workers))
		for _, worker := range workers {
			existingWorkers[worker.CoreId] = worker
		}

		// Ensure all configured workers exist
		for i := uint(1); i <= uint(w.config.Engine.DataWorkerCount); i++ {
			if _, ok := existingWorkers[i]; ok {
				continue
			}
			if _, err := w.getIPCOfWorker(i); err != nil {
				w.logger.Error(
					"could not obtain IPC for worker",
					zap.Uint("core_id", i),
					zap.Error(err),
				)
			}
		}

		// Remove workers beyond configured count
		for _, worker := range workers {
			if worker.CoreId <= uint(w.config.Engine.DataWorkerCount) {
				continue
			}

			txn, err := w.store.NewTransaction(false)
			if err != nil {
				w.logger.Error(
					"could not create txn to delete worker",
					zap.Uint("core_id", worker.CoreId),
					zap.Error(err),
				)
				continue
			}

			if err := w.store.DeleteWorker(txn, worker.CoreId); err != nil {
				_ = txn.Abort()
				w.logger.Error(
					"could not delete worker",
					zap.Uint("core_id", worker.CoreId),
					zap.Error(err),
				)
			}
			if err := txn.Commit(); err != nil {
				_ = txn.Abort()
				w.logger.Error(
					"could not commit worker delete",
					zap.Uint("core_id", worker.CoreId),
					zap.Error(err),
				)
			}

			w.closeServiceClient(worker.CoreId)
			w.purgeWorkerFromCache(worker.CoreId, worker.Filter)
		}

		workers, err = w.store.RangeWorkers()
		if err != nil {
			return errors.Wrap(err, "load workers from store")
		}
	}

	var totalStorage uint64
	var allocatedCount int
	for _, worker := range workers {
		// Update cache
		w.setWorkerFilterMapping(worker.CoreId, worker.Filter)
		if worker.Allocated {
			w.setWorkerAllocation(worker.CoreId, true)
			allocatedCount++
		} else {
			w.setWorkerAllocation(worker.CoreId, false)
		}
		totalStorage += uint64(worker.TotalStorage)
		if err := w.respawnWorker(worker.CoreId, worker.Filter); err != nil {
			w.logger.Error(
				"could not respawn worker",
				zap.Uint("core_id", worker.CoreId),
				zap.Error(err),
			)
			continue
		}
	}

	// Update metrics
	activeWorkersGauge.Set(float64(len(workers)))
	allocatedWorkersGauge.Set(float64(allocatedCount))
	totalStorageGauge.Set(float64(totalStorage))

	w.logger.Info(fmt.Sprintf("loaded %d workers from store", len(workers)))
	return nil
}

func (w *WorkerManager) getMultiaddrOfWorker(coreId uint) (
	multiaddr.Multiaddr,
	error,
) {
	rpcMultiaddr := fmt.Sprintf(
		w.config.Engine.DataWorkerBaseListenMultiaddr,
		int(w.config.Engine.DataWorkerBaseStreamPort)+int(coreId-1),
	)

	if len(w.config.Engine.DataWorkerStreamMultiaddrs) != 0 {
		rpcMultiaddr = w.config.Engine.DataWorkerStreamMultiaddrs[coreId-1]
	}

	rpcMultiaddr = strings.Replace(rpcMultiaddr, "/0.0.0.0/", "/127.0.0.1/", 1)
	rpcMultiaddr = strings.Replace(rpcMultiaddr, "/0:0:0:0:0:0:0:0/", "/::1/", 1)
	rpcMultiaddr = strings.Replace(rpcMultiaddr, "/::/", "/::1/", 1)

	ma, err := multiaddr.StringCast(rpcMultiaddr)
	return ma, errors.Wrap(err, "get multiaddr of worker")
}

func (w *WorkerManager) getP2PMultiaddrOfWorker(coreId uint) (
	multiaddr.Multiaddr,
	error,
) {
	p2pMultiaddr := fmt.Sprintf(
		w.config.Engine.DataWorkerBaseListenMultiaddr,
		int(w.config.Engine.DataWorkerBaseP2PPort)+int(coreId-1),
	)

	if len(w.config.Engine.DataWorkerP2PMultiaddrs) != 0 {
		p2pMultiaddr = w.config.Engine.DataWorkerP2PMultiaddrs[coreId-1]
	}

	ma, err := multiaddr.StringCast(p2pMultiaddr)
	return ma, errors.Wrap(err, "get p2p multiaddr of worker")
}

func (w *WorkerManager) ensureWorkerRegistered(
	coreId uint,
	p2pAddr multiaddr.Multiaddr,
	streamAddr multiaddr.Multiaddr,
) error {
	_, err := w.store.GetWorker(coreId)
	if err == nil {
		return nil
	}
	if !errors.Is(err, typesStore.ErrNotFound) {
		return err
	}

	return w.registerWorker(&typesStore.WorkerInfo{
		CoreId:                coreId,
		ListenMultiaddr:       p2pAddr.String(),
		StreamListenMultiaddr: streamAddr.String(),
		Filter:                nil,
		TotalStorage:          0,
		Automatic:             len(w.config.Engine.DataWorkerP2PMultiaddrs) == 0,
		Allocated:             false,
	})
}

func (w *WorkerManager) getIPCOfWorker(coreId uint) (
	protobufs.DataIPCServiceClient,
	error,
) {
	ctx := w.currentContext()
	if ctx == nil {
		ctx = context.Background()
	}
	return w.getIPCOfWorkerWithContext(ctx, coreId)
}

func (w *WorkerManager) getIPCOfWorkerWithTimeout(
	coreId uint,
	timeout time.Duration,
) (protobufs.DataIPCServiceClient, error) {
	ctx := w.currentContext()
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return w.getIPCOfWorkerWithContext(ctx, coreId)
}

func (w *WorkerManager) getIPCOfWorkerWithContext(
	ctx context.Context,
	coreId uint,
) (
	protobufs.DataIPCServiceClient,
	error,
) {
	if client, ok := w.getServiceClient(coreId); ok {
		return protobufs.NewDataIPCServiceClient(client), nil
	}

	w.logger.Info("reconnecting to worker", zap.Uint("core_id", coreId))
	streamAddr, err := w.getMultiaddrOfWorker(coreId)
	if err != nil {
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	p2pAddr, err := w.getP2PMultiaddrOfWorker(coreId)
	if err != nil {
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	if err := w.ensureWorkerRegistered(coreId, p2pAddr, streamAddr); err != nil {
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	mga, err := mn.ToNetAddr(streamAddr)
	if err != nil {
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	peerPrivKey, err := hex.DecodeString(w.config.P2P.PeerPrivKey)
	if err != nil {
		w.logger.Error("error unmarshaling peerkey", zap.Error(err))
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		w.logger.Error("error unmarshaling peerkey", zap.Error(err))
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		w.logger.Error("error unmarshaling peerkey", zap.Error(err))
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	creds, err := p2p.NewPeerAuthenticator(
		w.logger,
		w.config.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(id)},
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.node.pb.DataIPCService": channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(id))
	if err != nil {
		return nil, errors.Wrap(err, "get ipc of worker")
	}

	return w.dialWorkerWithRetry(
		ctx,
		coreId,
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
}

func (w *WorkerManager) dialWorkerWithRetry(
	ctx context.Context,
	coreId uint,
	target string,
	opts ...grpc.DialOption,
) (protobufs.DataIPCServiceClient, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	const (
		initialBackoff = 50 * time.Millisecond
		maxBackoff     = 5 * time.Second
	)

	backoff := initialBackoff
	for {
		client, err := grpc.NewClient(target, opts...)
		if err == nil {
			w.setServiceClient(coreId, client)
			return protobufs.NewDataIPCServiceClient(client), nil
		}

		w.logger.Info(
			"worker dial failed, retrying",
			zap.Uint("core_id", coreId),
			zap.String("target", target),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "get ipc of worker")
		}

		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (w *WorkerManager) respawnWorker(
	coreId uint,
	filter []byte,
) error {
	const (
		respawnTimeout    = 5 * time.Second
		initialBackoff    = 50 * time.Millisecond
		maxRespawnBackoff = 2 * time.Second
	)

	managerCtx := w.currentContext()
	if managerCtx == nil {
		managerCtx = context.Background()
	}

	backoff := initialBackoff
	for {
		svc, err := w.getIPCOfWorker(coreId)
		if err != nil {
			w.logger.Error(
				"could not get ipc of worker",
				zap.Uint("core_id", coreId),
				zap.Error(err),
			)
			select {
			case <-time.After(backoff):
			case <-managerCtx.Done():
				return errors.Wrap(managerCtx.Err(), "respawn worker")
			}
			continue
		}

		ctx, cancel := context.WithTimeout(managerCtx, respawnTimeout)
		_, err = svc.Respawn(ctx, &protobufs.RespawnRequest{Filter: filter}) // buildutils:allow-slice-alias slice is static
		cancel()
		if err == nil {
			return nil
		}

		w.logger.Warn(
			"worker respawn failed, retrying",
			zap.Uint("core_id", coreId),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)
		w.closeServiceClient(coreId)

		select {
		case <-time.After(backoff):
		case <-managerCtx.Done():
			return errors.Wrap(managerCtx.Err(), "respawn worker")
		}

		if backoff < maxRespawnBackoff {
			backoff *= 2
			if backoff > maxRespawnBackoff {
				backoff = maxRespawnBackoff
			}
		}
	}
}

func (w *WorkerManager) spawnDataWorkers() {
	if len(w.config.Engine.DataWorkerP2PMultiaddrs) != 0 {
		w.logger.Warn(
			"data workers configured by multiaddr, be sure these are running...",
		)
		return
	}

	process, err := os.Executable()
	if err != nil {
		w.logger.Panic("failed to get executable path", zap.Error(err))
	}

	w.setDataWorkers(w.config.Engine.DataWorkerCount)
	w.logger.Info(
		"spawning data workers",
		zap.Int("count", w.config.Engine.DataWorkerCount),
	)

	for i := 1; i <= w.config.Engine.DataWorkerCount; i++ {
		i := i
		go func() {
			for w.isStarted() {
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

				w.updateDataWorker(i-1, cmd)
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
	for i := 0; i < w.dataWorkerLen(); i++ {
		cmd := w.getDataWorker(i)
		if cmd == nil || cmd.Process == nil {
			continue
		}
		err := cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			w.logger.Info(
				"unable to stop worker",
				zap.Int("pid", cmd.Process.Pid),
				zap.Error(err),
			)
		}
	}
}
