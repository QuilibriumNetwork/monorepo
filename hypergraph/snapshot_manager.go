package hypergraph

import (
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type snapshotHandle struct {
	store   tries.TreeBackingStore
	release func()
	refs    atomic.Int32
	root    []byte
	key     string

	branchCacheMu sync.RWMutex
	branchCache   map[string]*protobufs.HypergraphComparisonResponse

	leafCacheMu   sync.RWMutex
	leafDataCache map[string][]byte
	leafCacheMiss map[string]struct{}
}

func newSnapshotHandle(
	key string,
	store tries.TreeBackingStore,
	release func(),
	root []byte,
) *snapshotHandle {
	h := &snapshotHandle{
		store:         store,
		release:       release,
		branchCache:   make(map[string]*protobufs.HypergraphComparisonResponse),
		leafDataCache: make(map[string][]byte),
		leafCacheMiss: make(map[string]struct{}),
		key:           key,
	}
	if len(root) != 0 {
		h.root = append([]byte{}, root...)
	}
	h.refs.Store(1)
	return h
}

func (h *snapshotHandle) acquire() tries.TreeBackingStore {
	h.refs.Add(1)
	return h.store
}

func (h *snapshotHandle) releaseRef(logger *zap.Logger) bool {
	if h == nil {
		return false
	}

	if h.refs.Add(-1) == 0 {
		if h.release != nil {
			if err := safeRelease(h.release); err != nil {
				logger.Warn("failed to release hypergraph snapshot", zap.Error(err))
			}
		}
		return true
	}
	return false
}

func (h *snapshotHandle) Store() tries.TreeBackingStore {
	if h == nil {
		return nil
	}
	return h.store
}

func (h *snapshotHandle) Root() []byte {
	if h == nil || len(h.root) == 0 {
		return nil
	}
	return append([]byte{}, h.root...)
}

func (h *snapshotHandle) getBranchInfo(
	path []int32,
) (*protobufs.HypergraphComparisonResponse, bool) {
	if h == nil {
		return nil, false
	}
	key := string(packPath(path))
	h.branchCacheMu.RLock()
	resp, ok := h.branchCache[key]
	h.branchCacheMu.RUnlock()
	return resp, ok
}

func (h *snapshotHandle) storeBranchInfo(
	path []int32,
	resp *protobufs.HypergraphComparisonResponse,
) {
	if h == nil || resp == nil {
		return
	}
	key := string(packPath(path))
	h.branchCacheMu.Lock()
	h.branchCache[key] = resp
	h.branchCacheMu.Unlock()
}

func (h *snapshotHandle) getLeafData(key []byte) ([]byte, bool) {
	if h == nil {
		return nil, false
	}
	cacheKey := string(key)
	h.leafCacheMu.RLock()
	data, ok := h.leafDataCache[cacheKey]
	h.leafCacheMu.RUnlock()
	return data, ok
}

// buildutils:allow-slice-alias data is already cloned for this
func (h *snapshotHandle) storeLeafData(key []byte, data []byte) {
	if h == nil || len(data) == 0 {
		return
	}
	cacheKey := string(key)
	h.leafCacheMu.Lock()
	h.leafDataCache[cacheKey] = data
	delete(h.leafCacheMiss, cacheKey)
	h.leafCacheMu.Unlock()
}

func (h *snapshotHandle) markLeafMiss(key []byte) {
	if h == nil {
		return
	}
	cacheKey := string(key)
	h.leafCacheMu.Lock()
	h.leafCacheMiss[cacheKey] = struct{}{}
	h.leafCacheMu.Unlock()
}

func (h *snapshotHandle) isLeafMiss(key []byte) bool {
	if h == nil {
		return false
	}
	cacheKey := string(key)
	h.leafCacheMu.RLock()
	_, miss := h.leafCacheMiss[cacheKey]
	h.leafCacheMu.RUnlock()
	return miss
}

type snapshotManager struct {
	logger  *zap.Logger
	store   tries.TreeBackingStore
	mu      sync.Mutex
	root    []byte
	handles map[string]*snapshotHandle
}

func newSnapshotManager(
	logger *zap.Logger,
	store tries.TreeBackingStore,
) *snapshotManager {
	return &snapshotManager{
		logger:  logger,
		store:   store,
		handles: make(map[string]*snapshotHandle),
	}
}

func (m *snapshotManager) publish(root []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, handle := range m.handles {
		if handle != nil {
			handle.releaseRef(m.logger)
		}
		delete(m.handles, key)
	}

	m.root = nil
	if len(root) != 0 {
		m.root = append([]byte{}, root...)
	}

	rootHex := ""
	if len(root) != 0 {
		rootHex = hex.EncodeToString(root)
	}
	m.logger.Debug("reset snapshot state", zap.String("root", rootHex))
}

func (m *snapshotManager) acquire(
	shardKey tries.ShardKey,
) *snapshotHandle {
	key := shardKeyString(shardKey)
	m.mu.Lock()
	defer m.mu.Unlock()

	if handle, ok := m.handles[key]; ok {
		handle.acquire()
		return handle
	}

	if m.store == nil {
		return nil
	}

	storeSnapshot, release, err := m.store.NewShardSnapshot(shardKey)
	if err != nil {
		m.logger.Warn(
			"failed to build shard snapshot",
			zap.Error(err),
			zap.String("shard_key", key),
		)
		return nil
	}

	handle := newSnapshotHandle(key, storeSnapshot, release, m.root)
	m.handles[key] = handle
	return handle
}

func (m *snapshotManager) release(handle *snapshotHandle) {
	if handle == nil {
		return
	}
	if !handle.releaseRef(m.logger) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.handles[handle.key]; ok && current == handle {
		delete(m.handles, handle.key)
	}
}

func shardKeyString(sk tries.ShardKey) string {
	buf := make([]byte, 0, len(sk.L1)+len(sk.L2))
	buf = append(buf, sk.L1[:]...)
	buf = append(buf, sk.L2[:]...)
	return hex.EncodeToString(buf)
}

func safeRelease(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic releasing snapshot: %v", r)
		}
	}()
	fn()
	return nil
}
