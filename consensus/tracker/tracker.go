package tracker

import (
	"unsafe"

	"go.uber.org/atomic"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// NewestQCTracker is a helper structure which keeps track of the newest QC
// (by rank) in concurrency safe way.
type NewestQCTracker struct {
	newestQC *atomic.UnsafePointer
}

func NewNewestQCTracker() *NewestQCTracker {
	tracker := &NewestQCTracker{
		newestQC: atomic.NewUnsafePointer(unsafe.Pointer(nil)),
	}
	return tracker
}

// Track updates local state of NewestQC if the provided instance is newer
// (by rank). Concurrency safe
func (t *NewestQCTracker) Track(qc *models.QuorumCertificate) bool {
	// to record the newest value that we have ever seen we need to use loop
	// with CAS atomic operation to make sure that we always write the latest
	// value in case of shared access to updated value.
	for {
		// take a snapshot
		newestQC := t.NewestQC()
		// verify that our update makes sense
		if newestQC != nil && (*newestQC).GetRank() >= (*qc).GetRank() {
			return false
		}
		// attempt to install new value, repeat in case of shared update.
		if t.newestQC.CompareAndSwap(unsafe.Pointer(newestQC), unsafe.Pointer(qc)) {
			return true
		}
	}
}

// NewestQC returns the newest QC(by rank) tracked.
// Concurrency safe.
func (t *NewestQCTracker) NewestQC() *models.QuorumCertificate {
	return (*models.QuorumCertificate)(t.newestQC.Load())
}

// NewestTCTracker is a helper structure which keeps track of the newest TC (by
// rank) in concurrency safe way.
type NewestTCTracker struct {
	newestTC *atomic.UnsafePointer
}

func NewNewestTCTracker() *NewestTCTracker {
	tracker := &NewestTCTracker{
		newestTC: atomic.NewUnsafePointer(unsafe.Pointer(nil)),
	}
	return tracker
}

// Track updates local state of NewestTC if the provided instance is newer (by
// rank). Concurrency safe.
func (t *NewestTCTracker) Track(tc *models.TimeoutCertificate) bool {
	// to record the newest value that we have ever seen we need to use loop
	// with CAS atomic operation to make sure that we always write the latest
	// value in case of shared access to updated value.
	for {
		// take a snapshot
		newestTC := t.NewestTC()
		// verify that our update makes sense
		if newestTC != nil && (*newestTC).GetRank() >= (*tc).GetRank() {
			return false
		}
		// attempt to install new value, repeat in case of shared update.
		if t.newestTC.CompareAndSwap(unsafe.Pointer(newestTC), unsafe.Pointer(tc)) {
			return true
		}
	}
}

// NewestTC returns the newest TC(by rank) tracked.
// Concurrency safe.
func (t *NewestTCTracker) NewestTC() *models.TimeoutCertificate {
	return (*models.TimeoutCertificate)(t.newestTC.Load())
}

// NewestStateTracker is a helper structure which keeps track of the newest
// state (by rank) in concurrency safe way.
type NewestStateTracker[StateT models.Unique] struct {
	newestState *atomic.UnsafePointer
}

func NewNewestStateTracker[StateT models.Unique]() *NewestStateTracker[StateT] {
	tracker := &NewestStateTracker[StateT]{
		newestState: atomic.NewUnsafePointer(unsafe.Pointer(nil)),
	}
	return tracker
}

// Track updates local state of newestState if the provided instance is newer
// (by rank). Concurrency safe.
func (t *NewestStateTracker[StateT]) Track(state *models.State[StateT]) bool {
	// to record the newest value that we have ever seen we need to use loop
	// with CAS atomic operation to make sure that we always write the latest
	// value in case of shared access to updated value.
	for {
		// take a snapshot
		newestState := t.NewestState()
		// verify that our update makes sense
		if newestState != nil && newestState.Rank >= state.Rank {
			return false
		}
		// attempt to install new value, repeat in case of shared update.
		if t.newestState.CompareAndSwap(
			unsafe.Pointer(newestState),
			unsafe.Pointer(state),
		) {
			return true
		}
	}
}

// NewestState returns the newest state (by rank) tracked.
// Concurrency safe.
func (t *NewestStateTracker[StateT]) NewestState() *models.State[StateT] {
	return (*models.State[StateT])(t.newestState.Load())
}

// NewestPartialTimeoutCertificateTracker tracks the newest partial TC (by rank) in a
// concurrency safe way.
type NewestPartialTimeoutCertificateTracker struct {
	newestPartialTimeoutCertificate *atomic.UnsafePointer
}

func NewNewestPartialTimeoutCertificateTracker() *NewestPartialTimeoutCertificateTracker {
	tracker := &NewestPartialTimeoutCertificateTracker{
		newestPartialTimeoutCertificate: atomic.NewUnsafePointer(unsafe.Pointer(nil)),
	}
	return tracker
}

// Track updates local state of newestPartialTimeoutCertificate if the provided instance is
// newer (by rank). Concurrency safe.
func (t *NewestPartialTimeoutCertificateTracker) Track(
	partialTimeoutCertificate *consensus.PartialTimeoutCertificateCreated,
) bool {
	// To record the newest value that we have ever seen, we need to use loop
	// with CAS atomic operation to make sure that we always write the latest
	// value in case of shared access to updated value.
	for {
		// take a snapshot
		newestPartialTimeoutCertificate := t.NewestPartialTimeoutCertificate()
		// verify that our partial TC is from a newer rank
		if newestPartialTimeoutCertificate != nil && newestPartialTimeoutCertificate.Rank >= partialTimeoutCertificate.Rank {
			return false
		}
		// attempt to install new value, repeat in case of shared update.
		if t.newestPartialTimeoutCertificate.CompareAndSwap(
			unsafe.Pointer(newestPartialTimeoutCertificate),
			unsafe.Pointer(partialTimeoutCertificate),
		) {
			return true
		}
	}
}

// NewestPartialTimeoutCertificate returns the newest partial TC (by rank) tracked.
// Concurrency safe.
func (
	t *NewestPartialTimeoutCertificateTracker,
) NewestPartialTimeoutCertificate() *consensus.PartialTimeoutCertificateCreated {
	return (*consensus.PartialTimeoutCertificateCreated)(t.newestPartialTimeoutCertificate.Load())
}
