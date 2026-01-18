package hypergraph

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// maxSnapshotGenerations is the maximum number of historical snapshot
// generations to retain. When a new root is published, older generations
// beyond this limit are released.
const maxSnapshotGenerations = 10

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

// snapshotGeneration represents a set of shard snapshots for a specific
// commit root.
type snapshotGeneration struct {
	root    []byte
	handles map[string]*snapshotHandle // keyed by shard key
}

type snapshotManager struct {
	logger *zap.Logger
	store  tries.TreeBackingStore
	mu     sync.Mutex
	// generations holds snapshot generations ordered from newest to oldest.
	// generations[0] is the current/latest generation.
	generations []*snapshotGeneration
}

func newSnapshotManager(
	logger *zap.Logger,
	store tries.TreeBackingStore,
) *snapshotManager {
	return &snapshotManager{
		logger:      logger,
		store:       store,
		generations: make([]*snapshotGeneration, 0, maxSnapshotGenerations),
	}
}

func (m *snapshotManager) publish(root []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rootHex := ""
	if len(root) != 0 {
		rootHex = hex.EncodeToString(root)
	}

	// Check if this root already matches the current generation
	if len(m.generations) > 0 && bytes.Equal(m.generations[0].root, root) {
		m.logger.Debug(
			"publish called with current root, no change",
			zap.String("root", rootHex),
		)
		return
	}

	// Create a new generation for this root
	newGen := &snapshotGeneration{
		handles: make(map[string]*snapshotHandle),
	}
	if len(root) != 0 {
		newGen.root = append([]byte{}, root...)
	}

	// Prepend the new generation (newest first)
	m.generations = append([]*snapshotGeneration{newGen}, m.generations...)

	// Release generations beyond the limit
	for len(m.generations) > maxSnapshotGenerations {
		oldGen := m.generations[len(m.generations)-1]
		m.generations = m.generations[:len(m.generations)-1]

		// Release all handles in the old generation
		for key, handle := range oldGen.handles {
			delete(oldGen.handles, key)
			if handle != nil {
				handle.releaseRef(m.logger)
			}
		}

		oldRootHex := ""
		if len(oldGen.root) != 0 {
			oldRootHex = hex.EncodeToString(oldGen.root)
		}
		m.logger.Debug(
			"released old snapshot generation",
			zap.String("root", oldRootHex),
		)
	}

	m.logger.Debug(
		"published new snapshot generation",
		zap.String("root", rootHex),
		zap.Int("total_generations", len(m.generations)),
	)
}

// acquire returns a snapshot handle for the given shard key. If expectedRoot
// is provided and a matching generation has an existing snapshot for this shard,
// that snapshot is returned. Otherwise, a new snapshot is created from the
// current DB state and associated with the latest generation.
//
// Note: Historical snapshots are only available if they were created while that
// generation was current. We cannot create a snapshot of past state retroactively.
func (m *snapshotManager) acquire(
	shardKey tries.ShardKey,
	expectedRoot []byte,
) *snapshotHandle {
	key := shardKeyString(shardKey)
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.generations) == 0 {
		m.logger.Warn("no snapshot generations available")
		return nil
	}

	// If expectedRoot is provided, look for an existing snapshot in that generation
	if len(expectedRoot) > 0 {
		for _, gen := range m.generations {
			if bytes.Equal(gen.root, expectedRoot) {
				// Found matching generation, check if it has a snapshot for this shard
				if handle, ok := gen.handles[key]; ok {
					m.logger.Debug(
						"found existing snapshot for expected root",
						zap.String("expected_root", hex.EncodeToString(expectedRoot)),
					)
					handle.acquire()
					return handle
				}
				// Generation exists but no snapshot for this shard yet.
				// Only create if this is the latest generation (current DB state matches).
				if gen != m.generations[0] {
					m.logger.Warn(
						"generation matches expected root but is not latest, cannot create snapshot",
						zap.String("expected_root", hex.EncodeToString(expectedRoot)),
					)
					return nil
				}
				// Fall through to create snapshot for latest generation
				m.logger.Debug(
					"creating snapshot for expected root (latest generation)",
					zap.String("expected_root", hex.EncodeToString(expectedRoot)),
				)
				break
			}
		}
		// If we didn't find a matching generation at all, reject
		if len(m.generations) == 0 || !bytes.Equal(m.generations[0].root, expectedRoot) {
			if m.logger != nil {
				latestRoot := ""
				if len(m.generations) > 0 {
					latestRoot = hex.EncodeToString(m.generations[0].root)
				}
				m.logger.Warn(
					"no snapshot generation matches expected root, rejecting sync request",
					zap.String("expected_root", hex.EncodeToString(expectedRoot)),
					zap.String("latest_root", latestRoot),
				)
			}
			return nil
		}
	}

	// Use the latest generation for new snapshots
	latestGen := m.generations[0]

	// Check if we already have a handle for this shard in the latest generation
	if handle, ok := latestGen.handles[key]; ok {
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

	handle := newSnapshotHandle(key, storeSnapshot, release, latestGen.root)
	// Acquire a ref for the caller. The handle is created with refs=1 (the owner ref
	// held by the snapshot manager), and this adds another ref for the sync session.
	// This ensures publish() can release the owner ref without closing the DB while
	// a sync is still using it.
	handle.acquire()
	latestGen.handles[key] = handle
	return handle
}

// currentRoot returns the commit root of the latest snapshot generation.
func (m *snapshotManager) currentRoot() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.generations) == 0 {
		return nil
	}
	return append([]byte{}, m.generations[0].root...)
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

	// Search all generations for this handle and remove it
	for _, gen := range m.generations {
		if current, ok := gen.handles[handle.key]; ok && current == handle {
			delete(gen.handles, handle.key)
			return
		}
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
