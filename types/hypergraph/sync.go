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
}

func (s *SyncController) TryEstablishSyncSession(peerID string) bool {
	if peerID == "" {
		return !s.globalSync.Swap(true)
	}

	info := s.getOrCreate(peerID)
	return !info.inProgress.Swap(true)
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
		info.inProgress.Store(false)
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

func NewSyncController() *SyncController {
	return &SyncController{
		syncStatus: map[string]*SyncInfo{},
	}
}
