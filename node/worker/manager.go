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
	"source.quilibrium.com/quilibrium/monorepo/node/store"
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

func (w *WorkerManager) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return errors.New("worker manager already started")
	}

	w.logger.Info("starting worker manager")

	w.ctx, w.cancel = context.WithCancel(ctx)

	w.started = true

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

	return w.registerWorker(info)
}

func (w *WorkerManager) registerWorker(info *typesStore.WorkerInfo) error {
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

	// Refresh worker
	svc, err := w.getIPCOfWorker(coreId)
	if err != nil {
		w.logger.Error("could not get ipc of worker", zap.Error(err))
		return errors.Wrap(err, "allocate worker")
	}

	_, err = svc.Respawn(w.ctx, &protobufs.RespawnRequest{
		Filter: worker.Filter,
	})
	if err != nil {
		w.logger.Error("could not respawn worker", zap.Error(err))
		return errors.Wrap(err, "allocate worker")
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

	// Refresh worker
	svc, err := w.getIPCOfWorker(coreId)
	if err != nil {
		w.logger.Error("could not get ipc of worker", zap.Error(err))
		return errors.Wrap(err, "allocate worker")
	}

	_, err = svc.Respawn(w.ctx, &protobufs.RespawnRequest{
		Filter: []byte{},
	})
	if err != nil {
		w.logger.Error("could not respawn worker", zap.Error(err))
		return errors.Wrap(err, "allocate worker")
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
	return w.proposeFunc(coreIds, filters, w.serviceClients)
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

	if len(workers) != w.config.Engine.DataWorkerCount {
		for i := range w.config.Engine.DataWorkerCount {
			_, err := w.getIPCOfWorker(uint(i + 1))
			if err != nil {
				w.logger.Error("could not obtain IPC for worker", zap.Error(err))
				continue
			}
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
		svc, err := w.getIPCOfWorker(worker.CoreId)
		if err != nil {
			w.logger.Error("could not obtain IPC for worker", zap.Error(err))
			continue
		}

		_, err = svc.Respawn(w.ctx, &protobufs.RespawnRequest{
			Filter: worker.Filter,
		})
		if err != nil {
			w.logger.Error("could not respawn worker", zap.Error(err))
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

func (w *WorkerManager) getIPCOfWorker(coreId uint) (
	protobufs.DataIPCServiceClient,
	error,
) {
	client, ok := w.serviceClients[coreId]
	if !ok {
		w.logger.Info("reconnecting to worker", zap.Uint("core_id", coreId))
		addr, err := w.getMultiaddrOfWorker(coreId)
		if err != nil {
			return nil, errors.Wrap(err, "get ipc of worker")
		}

		mga, err := mn.ToNetAddr(addr)
		if err != nil {
			return nil, errors.Wrap(err, "get ipc of worker")
		}

		peerPrivKey, err := hex.DecodeString(w.config.P2P.PeerPrivKey)
		if err != nil {
			w.logger.Error("error unmarshaling peerkey", zap.Error(err))
			return nil, errors.Wrap(err, "get ipc of worker")
		}

		if _, ok := w.filtersByWorker[coreId]; !ok {
			p2pAddr, err := w.getP2PMultiaddrOfWorker(coreId)
			if err != nil {
				return nil, errors.Wrap(err, "get ipc of worker")
			}
			err = w.registerWorker(&typesStore.WorkerInfo{
				CoreId:                coreId,
				ListenMultiaddr:       p2pAddr.String(),
				StreamListenMultiaddr: addr.String(),
				Filter:                nil,
				TotalStorage:          0,
				Automatic:             len(w.config.Engine.DataWorkerP2PMultiaddrs) == 0,
				Allocated:             false,
			})
			if err != nil {
				return nil, errors.Wrap(err, "get ipc of worker")
			}
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

		client, err = grpc.NewClient(
			mga.String(),
			grpc.WithTransportCredentials(creds),
		)
		if err != nil {

			return nil, errors.Wrap(err, "get ipc of worker")
		}

		w.serviceClients[coreId] = client
	}

	return protobufs.NewDataIPCServiceClient(client), nil
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

	w.dataWorkers = make([]*exec.Cmd, w.config.Engine.DataWorkerCount)
	w.logger.Info(
		"spawning data workers",
		zap.Int("count", w.config.Engine.DataWorkerCount),
	)

	for i := 1; i <= w.config.Engine.DataWorkerCount; i++ {
		i := i
		go func() {
			for w.started {
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
		err := w.dataWorkers[i].Process.Signal(syscall.SIGTERM)
		if err != nil {
			w.logger.Info(
				"unable to stop worker",
				zap.Int("pid", w.dataWorkers[i].Process.Pid),
				zap.Error(err),
			)
		}
	}
}
