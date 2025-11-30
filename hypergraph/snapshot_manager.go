package hypergraph

import (
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type snapshotHandle struct {
	store   tries.TreeBackingStore
	release func()
	refs    atomic.Int32
	root    []byte
}

func newSnapshotHandle(
	store tries.TreeBackingStore,
	release func(),
	root []byte,
) *snapshotHandle {
	h := &snapshotHandle{
		store:   store,
		release: release,
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

type snapshotManager struct {
	logger  *zap.Logger
	current atomic.Pointer[snapshotHandle]
}

func newSnapshotManager(logger *zap.Logger) *snapshotManager {
	return &snapshotManager{logger: logger}
}

func (m *snapshotManager) publish(
	store tries.TreeBackingStore,
	release func(),
	root []byte,
) {
	handle := newSnapshotHandle(store, release, root)
	prev := m.current.Swap(handle)
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
	handle := m.current.Load()
	if handle == nil {
		return nil
	}
	handle.acquire()
	return handle
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
