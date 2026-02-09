package hypergraph

import (
	"sync"
	"sync/atomic"
	"time"
)

// maxSessionsPerPeer is the maximum number of concurrent sync sessions
// allowed from a single peer.
const maxSessionsPerPeer = 10

type SyncController struct {
	globalSync        atomic.Bool
	statusMu          sync.RWMutex
	syncStatus        map[string]*SyncInfo
	maxActiveSessions int32
	activeSessions    atomic.Int32
	selfPeerID        string
}

func (s *SyncController) TryEstablishSyncSession(peerID string) bool {
	if peerID == "" {
		return !s.globalSync.Swap(true)
	}

	info := s.getOrCreate(peerID)

	// Allow unlimited sessions from self (our own workers syncing to master)
	isSelf := s.selfPeerID != "" && peerID == s.selfPeerID

	// Try to increment peer's session count (up to maxSessionsPerPeer, unless self)
	for {
		current := info.activeSessions.Load()
		if !isSelf && current >= maxSessionsPerPeer {
			return false
		}
		if info.activeSessions.CompareAndSwap(current, current+1) {
			break
		}
	}

	// Skip global session limit for self-sync
	if !isSelf && !s.incrementActiveSessions() {
		info.activeSessions.Add(-1)
		return false
	}

	// Record session start time for staleness detection
	now := time.Now().UnixNano()
	info.lastStartedAt.Store(now)
	info.lastActivity.Store(now)

	return true
}

func (s *SyncController) EndSyncSession(peerID string) {
	if peerID == "" {
		s.globalSync.Store(false)
		return
	}

	isSelf := s.selfPeerID != "" && peerID == s.selfPeerID

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()
	if info != nil {
		// Decrement peer's session count
		for {
			current := info.activeSessions.Load()
			if current <= 0 {
				return
			}
			if info.activeSessions.CompareAndSwap(current, current-1) {
				// Only decrement global counter for non-self sessions
				if !isSelf {
					s.decrementActiveSessions()
				}
				return
			}
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
	Unreachable    bool
	LastSynced     time.Time
	activeSessions atomic.Int32  // Number of active sessions for this peer
	lastStartedAt  atomic.Int64  // Unix nano timestamp when most recent session started
	lastActivity   atomic.Int64  // Unix nano timestamp of last activity
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

// SetSelfPeerID sets the self peer ID for the controller. Sessions from this
// peer ID are allowed unlimited concurrency (for workers syncing to master).
func (s *SyncController) SetSelfPeerID(peerID string) {
	s.selfPeerID = peerID
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

// UpdateActivity updates the last activity timestamp for a peer's sync session.
// This should be called periodically during sync to prevent idle timeout.
func (s *SyncController) UpdateActivity(peerID string) {
	if peerID == "" {
		return
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()

	if info != nil && info.activeSessions.Load() > 0 {
		info.lastActivity.Store(time.Now().UnixNano())
	}
}

// IsSessionStale checks if a peer's sessions have exceeded the maximum duration or idle timeout.
// maxDuration is the maximum total duration for a sync session.
// idleTimeout is the maximum time without activity before sessions are considered stale.
func (s *SyncController) IsSessionStale(peerID string, maxDuration, idleTimeout time.Duration) bool {
	if peerID == "" {
		return false
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()

	if info == nil || info.activeSessions.Load() <= 0 {
		return false
	}

	now := time.Now().UnixNano()
	startedAt := info.lastStartedAt.Load()
	lastActivity := info.lastActivity.Load()

	// Check if session has exceeded maximum duration
	if startedAt > 0 && time.Duration(now-startedAt) > maxDuration {
		return true
	}

	// Check if session has been idle too long
	if lastActivity > 0 && time.Duration(now-lastActivity) > idleTimeout {
		return true
	}

	return false
}

// ForceEndSession forcibly ends all sync sessions for a peer, used for cleaning up stale sessions.
// Returns true if any sessions were ended.
func (s *SyncController) ForceEndSession(peerID string) bool {
	if peerID == "" {
		return false
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()

	if info == nil {
		return false
	}

	// End all sessions for this peer
	for {
		current := info.activeSessions.Load()
		if current <= 0 {
			return false
		}
		if info.activeSessions.CompareAndSwap(current, 0) {
			// Decrement global counter by the number of sessions we ended
			for i := int32(0); i < current; i++ {
				s.decrementActiveSessions()
			}
			return true
		}
	}
}

// CleanupStaleSessions finds and forcibly ends all stale sync sessions.
// Returns the list of peer IDs that were cleaned up.
func (s *SyncController) CleanupStaleSessions(maxDuration, idleTimeout time.Duration) []string {
	var stale []string

	s.statusMu.RLock()
	for peerID, info := range s.syncStatus {
		if info == nil || info.activeSessions.Load() <= 0 {
			continue
		}

		now := time.Now().UnixNano()
		startedAt := info.lastStartedAt.Load()
		lastActivity := info.lastActivity.Load()

		if startedAt > 0 && time.Duration(now-startedAt) > maxDuration {
			stale = append(stale, peerID)
			continue
		}

		if lastActivity > 0 && time.Duration(now-lastActivity) > idleTimeout {
			stale = append(stale, peerID)
		}
	}
	s.statusMu.RUnlock()

	for _, peerID := range stale {
		s.ForceEndSession(peerID)
	}

	return stale
}

// SessionDuration returns how long since the most recent session started.
// Returns 0 if there are no active sessions.
func (s *SyncController) SessionDuration(peerID string) time.Duration {
	if peerID == "" {
		return 0
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()

	if info == nil || info.activeSessions.Load() <= 0 {
		return 0
	}

	startedAt := info.lastStartedAt.Load()
	if startedAt == 0 {
		return 0
	}

	return time.Duration(time.Now().UnixNano() - startedAt)
}

// ActiveSessionCount returns the number of active sync sessions for a peer.
func (s *SyncController) ActiveSessionCount(peerID string) int32 {
	if peerID == "" {
		return 0
	}

	s.statusMu.RLock()
	info := s.syncStatus[peerID]
	s.statusMu.RUnlock()

	if info == nil {
		return 0
	}

	return info.activeSessions.Load()
}
