package hypergraph

import (
	"sync"
	"sync/atomic"
	"time"
)

type SyncController struct {
	globalSync atomic.Bool
	statusMu   sync.RWMutex
	syncStatus map[string]*SyncInfo
	maxActiveSessions int32
	activeSessions    atomic.Int32
}

func (s *SyncController) TryEstablishSyncSession(peerID string) bool {
	if peerID == "" {
		return !s.globalSync.Swap(true)
	}

	info := s.getOrCreate(peerID)
	if info.inProgress.Swap(true) {
		return false
	}

	if !s.incrementActiveSessions() {
		info.inProgress.Store(false)
		return false
	}

	return true
}

func (s *SyncController) EndSyncSession(peerID string) {
	if peerID == "" {
		s.globalSync.Store(false)
		return
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()
	if info != nil {
		if info.inProgress.Swap(false) {
			s.decrementActiveSessions()
		}
	}
}

func (s *SyncController) GetStatus(peerID string) (*SyncInfo, bool) {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	info, ok := s.syncStatus[peerID]
	return info, ok
}

func (s *SyncController) SetStatus(peerID string, info *SyncInfo) {
	s.statusMu.Lock()
	existing := s.syncStatus[peerID]
	if existing == nil {
		s.syncStatus[peerID] = info
	} else {
		existing.Unreachable = info.Unreachable
		existing.LastSynced = info.LastSynced
	}
	s.statusMu.Unlock()
}

func (s *SyncController) getOrCreate(peerID string) *SyncInfo {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	info, ok := s.syncStatus[peerID]
	if !ok {
		info = &SyncInfo{}
		s.syncStatus[peerID] = info
	}
	return info
}

type SyncInfo struct {
	Unreachable bool
	LastSynced  time.Time
	inProgress  atomic.Bool
}

func NewSyncController(maxActiveSessions int) *SyncController {
	var max int32
	if maxActiveSessions > 0 {
		max = int32(maxActiveSessions)
	}
	return &SyncController{
		syncStatus:        map[string]*SyncInfo{},
		maxActiveSessions: max,
	}
}

func (s *SyncController) incrementActiveSessions() bool {
	if s.maxActiveSessions <= 0 {
		return true
	}

	for {
		current := s.activeSessions.Load()
		if current >= s.maxActiveSessions {
			return false
		}
		if s.activeSessions.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (s *SyncController) decrementActiveSessions() {
	if s.maxActiveSessions <= 0 {
		return
	}

	for {
		current := s.activeSessions.Load()
		if current == 0 {
			return
		}
		if s.activeSessions.CompareAndSwap(current, current-1) {
			return
		}
	}
}
