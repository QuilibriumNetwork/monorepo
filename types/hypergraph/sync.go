package hypergraph

import (
	"sync/atomic"
	"time"
)

type SyncController struct {
	isSyncing  atomic.Bool
	SyncStatus map[string]*SyncInfo
}

func (s *SyncController) TryEstablishSyncSession() bool {
	return !s.isSyncing.Swap(true)
}

func (s *SyncController) EndSyncSession() {
	s.isSyncing.Store(false)
}

type SyncInfo struct {
	Unreachable bool
	LastSynced  time.Time
}

func NewSyncController() *SyncController {
	return &SyncController{
		isSyncing:  atomic.Bool{},
		SyncStatus: map[string]*SyncInfo{},
	}
}
