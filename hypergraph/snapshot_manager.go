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

	branchCacheMu sync.RWMutex
	branchCache   map[string]*protobufs.HypergraphComparisonResponse

	leafCacheMu   sync.RWMutex
	leafDataCache map[string][]byte
	leafCacheMiss map[string]struct{}
}

func newSnapshotHandle(
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

func (h *snapshotHandle) releaseRef(logger *zap.Logger) {
	if h == nil {
		return
	}

	if h.refs.Add(-1) == 0 && h.release != nil {
		if err := safeRelease(h.release); err != nil {
			logger.Warn("failed to release hypergraph snapshot", zap.Error(err))
		}
	}
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
	mu      sync.Mutex
	current *snapshotHandle
}

func newSnapshotManager(logger *zap.Logger) *snapshotManager {
	return &snapshotManager{logger: logger}
}

func (m *snapshotManager) publish(
	store tries.TreeBackingStore,
	release func(),
	root []byte,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	handle := newSnapshotHandle(store, release, root)
	prev := m.current
	m.current = handle

	if prev != nil {
		prev.releaseRef(m.logger)
	}

	rootHex := ""
	if len(root) != 0 {
		rootHex = hex.EncodeToString(root)
	}
	m.logger.Debug("swapped snapshot", zap.String("root", rootHex))
}

func (m *snapshotManager) acquire() *snapshotHandle {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.current == nil {
		return nil
	}
	m.current.acquire()
	return m.current
}

func (m *snapshotManager) release(handle *snapshotHandle) {
	if handle == nil {
		return
	}
	handle.releaseRef(m.logger)
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
