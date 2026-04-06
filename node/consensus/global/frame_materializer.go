package global

// Frame materialization: applying a committed global frame's transactions to
// the hypergraph, syncing prover state, running eviction, and publishing
// snapshots. The FrameMaterializer owns all materialization-related state and
// holds a back-reference to the engine for shared dependencies.

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	execstate "source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// FrameMaterializer encapsulates the state and logic for materializing global
// frames — applying transactions, syncing prover roots, running eviction, and
// publishing snapshots.
type FrameMaterializer struct {
	engine *GlobalConsensusEngine // back-reference to shared engine state

	// commitBarrier serializes tree commits across materialize and
	// rebuildShardCommitments. Ordering: commitBarrier > materializeMu.
	commitBarrier sync.Mutex

	// materializeMu + lastMaterializedFrame provide idempotency: each frame
	// is materialized at most once.
	materializeMu         sync.Mutex
	lastMaterializedFrame atomic.Uint64

	// Prover root sync tracking.
	proverRootSynced        atomic.Bool
	proverRootVerifiedFrame atomic.Uint64
	proverSyncInProgress    atomic.Bool
}

// NewFrameMaterializer creates a FrameMaterializer bound to the given engine.
func NewFrameMaterializer(engine *GlobalConsensusEngine) *FrameMaterializer {
	return &FrameMaterializer{engine: engine}
}

func (m *FrameMaterializer) materialize(
	txn store.Transaction,
	frame *protobufs.GlobalFrame,
) error {
	e := m.engine
	frameNumber := frame.Header.FrameNumber

	// Idempotency guard: each frame is materialized at most once.
	// ProveNextState calls materialize(nil, prior) to ensure frame N's
	// mutations are applied before computing N+1's prover root.
	// addCertifiedState also calls materialize for the same frame;
	// the second call returns immediately.
	m.materializeMu.Lock()
	if frameNumber <= m.lastMaterializedFrame.Load() {
		m.materializeMu.Unlock()
		return nil
	}
	defer m.materializeMu.Unlock()

	requests := frame.Requests
	expectedProverRoot := frame.Header.ProverTreeCommitment
	proposer := frame.Header.Prover
	start := time.Now()
	var appliedCount atomic.Int64
	var skippedCount atomic.Int64

	m.commitBarrier.Lock()
	_, err := e.hypergraph.Commit(frameNumber)
	m.commitBarrier.Unlock()
	if err != nil {
		e.logger.Error("error committing hypergraph", zap.Error(err))
		return errors.Wrap(err, "materialize")
	}

	var expectedRootHex string
	localRootHex := ""

	// Check prover root BEFORE processing transactions. If there's a mismatch,
	// we need to sync first, otherwise we'll apply transactions on top of
	// divergent state and then sync will delete the newly added records.
	if len(expectedProverRoot) > 0 {
		localProverRoot, localRootErr := m.computeLocalProverRoot(frameNumber)
		if localRootErr != nil {
			e.logger.Warn(
				"failed to compute local prover root",
				zap.Uint64("frame_number", frameNumber),
				zap.Error(localRootErr),
			)
		}

		updatedProverRoot := localProverRoot
		if localRootErr == nil && len(localProverRoot) > 0 {
			if !bytes.Equal(localProverRoot, expectedProverRoot) {
				e.logger.Info(
					"prover root mismatch detected before processing frame, syncing first",
					zap.Uint64("frame_number", frameNumber),
					zap.String("expected_root", hex.EncodeToString(expectedProverRoot)),
					zap.String("local_root", hex.EncodeToString(localProverRoot)),
				)
				// Perform blocking hypersync before continuing
				_ = m.performBlockingProverHypersync(
					proposer,
					expectedProverRoot,
				)

				// After sync, use expectedProverRoot for the snapshot so
				// workers can sync against the root they expect. The next
				// frame's Commit(N+1) will verify actual convergence.
				updatedProverRoot = expectedProverRoot
			}
		}

		// Publish the snapshot generation with the new root so clients can sync
		// against this specific state.
		if len(updatedProverRoot) > 0 {
			if hgCRDT, ok := e.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
				hgCRDT.PublishSnapshot(updatedProverRoot)
			}
		}

		if len(expectedProverRoot) > 0 {
			expectedRootHex = hex.EncodeToString(expectedProverRoot)
		}
		if len(localProverRoot) > 0 {
			localRootHex = hex.EncodeToString(localProverRoot)
		}

		if bytes.Equal(updatedProverRoot, expectedProverRoot) {
			m.proverRootSynced.Store(true)
			m.proverRootVerifiedFrame.Store(frameNumber)
		}
	}

	var st execstate.State
	st = hgstate.NewHypergraphState(e.hypergraph)

	e.logger.Debug(
		"materializing messages",
		zap.Int("message_count", len(requests)),
	)
	worldSize := e.hypergraph.GetSize(nil, nil).Uint64()
	e.currentDifficultyMu.RLock()
	difficulty := uint64(e.currentDifficulty)
	e.currentDifficultyMu.RUnlock()

	eg := errgroup.Group{}
	eg.SetLimit(len(requests))

	for i, request := range requests {
		idx := i
		req := request
		eg.Go(func() error {
			requestBytes, err := req.ToCanonicalBytes()

			if err != nil {
				e.logger.Error(
					"error serializing request",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				return errors.Wrap(err, "materialize")
			}

			if len(requestBytes) == 0 {
				e.logger.Error(
					"empty request bytes",
					zap.Int("message_index", idx),
				)
				return errors.Wrap(errors.New("empty request"), "materialize")
			}

			costBasis, err := e.executionManager.GetCost(requestBytes)
			if err != nil {
				e.logger.Error(
					"invalid message",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				skippedCount.Add(1)
				return nil
			}

			var baseline *big.Int
			if costBasis.Cmp(big.NewInt(0)) == 0 {
				baseline = big.NewInt(0)
			} else {
				baseline = reward.GetBaselineFee(
					difficulty,
					worldSize,
					costBasis.Uint64(),
					8000000000,
				)
				baseline.Quo(baseline, costBasis)
			}

			_, err = e.executionManager.ProcessMessage(
				frameNumber,
				baseline,
				bytes.Repeat([]byte{0xff}, 32),
				requestBytes,
				st,
			)
			if err != nil {
				e.logger.Error(
					"error processing message",
					zap.Int("message_index", idx),
					zap.Error(err),
				)
				skippedCount.Add(1)
				return nil
			}
			appliedCount.Add(1)

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	m.commitBarrier.Lock()
	stateCommitErr := st.Commit()
	m.commitBarrier.Unlock()
	if stateCommitErr != nil {
		return errors.Wrap(stateCommitErr, "materialize")
	}

	// Persist any alt shard updates from this frame
	if err := m.persistAltShardUpdates(frameNumber, requests); err != nil {
		e.logger.Error(
			"failed to persist alt shard updates",
			zap.Uint64("frame_number", frameNumber),
			zap.Error(err),
		)
	}

	err = e.proverRegistry.ProcessStateTransition(st, frameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	err = e.proverRegistry.PruneOrphanJoins(frameNumber)
	if err != nil {
		return errors.Wrap(err, "materialize")
	}

	// Evict provers inactive for >360 frames, subtracting any halt duration.
	// Only archive nodes perform eviction — non-archive nodes receive the
	// eviction results through sync.
	// computeShardHaltDurations initializes the streak map on first call
	// (reconstructing halt data from LastActiveFrameNumber). Skip eviction
	// until it has run at least once so we never evict before accounting
	// for halt periods. During an active coverage halt (any shard at
	// math.MaxUint64), skip eviction entirely — nobody should be evicted.
	shardHaltDurations := e.coverageMonitor.computeShardHaltDurations(frameNumber)
	anyHalted := false
	for _, d := range shardHaltDurations {
		if d == math.MaxUint64 {
			anyHalted = true
			break
		}
	}
	if e.config.Engine.ArchiveMode && shardHaltDurations != nil && !anyHalted {
		evictionState := hgstate.NewHypergraphState(e.hypergraph)
		evicted, evictErr := e.proverRegistry.EvictInactiveProvers(
			frameNumber, 360, shardHaltDurations, evictionState,
		)
		if evictErr != nil {
			e.logger.Error("error evicting inactive provers", zap.Error(evictErr))
		} else if len(evicted) > 0 {
			m.commitBarrier.Lock()
			commitErr := evictionState.Commit()
			m.commitBarrier.Unlock()
			if commitErr != nil {
				e.logger.Error(
					"error committing eviction state",
					zap.Error(commitErr),
				)
			} else {
				e.logger.Info("evicted inactive provers",
					zap.Int("count", len(evicted)),
					zap.Uint64("frame_number", frameNumber),
				)
			}
		}
	}

	if len(localRootHex) > 0 {
		m.reconcileLocalWorkerAllocations()
	}

	// After all tree modifications (ProcessMessages, state transitions,
	// evictions), publish a snapshot with the post-materialize vertex adds
	// root. This is the root that frame N+1's ProverTreeCommitment will
	// contain. Workers detecting a mismatch at frame N+1 will sync against
	// this root, so the master must have a matching snapshot available.
	m.commitBarrier.Lock()
	postRoot, postRootErr := m.computeLocalProverRoot(frameNumber + 1)
	if postRootErr == nil && len(postRoot) > 0 {
		if hgCRDT, ok := e.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
			hgCRDT.PublishSnapshot(postRoot)
		}
	}
	m.commitBarrier.Unlock()

	postRootHex := ""
	if len(postRoot) > 0 {
		postRootHex = hex.EncodeToString(postRoot)
	}

	e.logger.Info(
		"materialized global frame",
		zap.Uint64("frame_number", frameNumber),
		zap.Int("request_count", len(requests)),
		zap.Int("applied_requests", int(appliedCount.Load())),
		zap.Int("skipped_requests", int(skippedCount.Load())),
		zap.String("expected_root", expectedRootHex),
		zap.String("local_root", localRootHex),
		zap.String("post_materialize_root", postRootHex),
		zap.String("proposer", hex.EncodeToString(proposer)),
		zap.Duration("duration", time.Since(start)),
	)

	m.lastMaterializedFrame.Store(frameNumber)
	return nil
}

// persistAltShardUpdates iterates through frame requests to find and persist
// any AltShardUpdate messages to the hypergraph store.
func (m *FrameMaterializer) persistAltShardUpdates(
	frameNumber uint64,
	requests []*protobufs.MessageBundle,
) error {
	e := m.engine
	var altUpdates []*protobufs.AltShardUpdate

	// Collect all alt shard updates from the frame's requests
	for _, bundle := range requests {
		if bundle == nil {
			continue
		}
		for _, req := range bundle.Requests {
			if req == nil {
				continue
			}
			if altUpdate := req.GetAltShardUpdate(); altUpdate != nil {
				altUpdates = append(altUpdates, altUpdate)
			}
		}
	}

	if len(altUpdates) == 0 {
		return nil
	}

	// Create a transaction for the hypergraph store
	txn, err := e.hypergraphStore.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "persist alt shard updates")
	}

	for _, update := range altUpdates {
		// Derive shard address from public key
		if len(update.PublicKey) == 0 {
			e.logger.Warn("alt shard update with empty public key, skipping")
			continue
		}

		addrBI, err := poseidon.HashBytes(update.PublicKey)
		if err != nil {
			e.logger.Warn(
				"failed to hash alt shard public key",
				zap.Error(err),
			)
			continue
		}
		shardAddress := addrBI.FillBytes(make([]byte, 32))

		// Persist the alt shard commit
		err = e.hypergraphStore.SetAltShardCommit(
			txn,
			frameNumber,
			shardAddress,
			update.VertexAddsRoot,
			update.VertexRemovesRoot,
			update.HyperedgeAddsRoot,
			update.HyperedgeRemovesRoot,
		)
		if err != nil {
			txn.Abort()
			return errors.Wrap(err, "persist alt shard updates")
		}

		e.logger.Debug(
			"persisted alt shard update",
			zap.Uint64("frame_number", frameNumber),
			zap.String("shard_address", hex.EncodeToString(shardAddress)),
		)
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "persist alt shard updates")
	}

	e.logger.Info(
		"persisted alt shard updates",
		zap.Uint64("frame_number", frameNumber),
		zap.Int("count", len(altUpdates)),
	)

	return nil
}

func (m *FrameMaterializer) computeLocalProverRoot(
	frameNumber uint64,
) ([]byte, error) {
	e := m.engine
	if e.hypergraph == nil {
		return nil, errors.New("hypergraph unavailable")
	}

	commitSet, err := e.hypergraph.Commit(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "compute local prover root")
	}

	var zeroShardKey tries.ShardKey
	for shardKey, phaseCommits := range commitSet {
		if shardKey.L1 == zeroShardKey.L1 {
			if len(phaseCommits) == 0 || len(phaseCommits[0]) == 0 {
				return nil, errors.New("empty prover root commitment")
			}
			return slices.Clone(phaseCommits[0]), nil
		}
	}

	return nil, errors.New("prover root shard missing")
}

func (m *FrameMaterializer) verifyProverRoot(
	frameNumber uint64,
	expected []byte,
	localRoot []byte,
	proposer []byte,
) bool {
	e := m.engine
	if len(expected) == 0 || len(localRoot) == 0 {
		return true
	}

	if !bytes.Equal(localRoot, expected) {
		e.logger.Warn(
			"prover root mismatch",
			zap.Uint64("frame_number", frameNumber),
			zap.String("expected_root", hex.EncodeToString(expected)),
			zap.String("local_root", hex.EncodeToString(localRoot)),
			zap.String("proposer", hex.EncodeToString(proposer)),
		)
		m.proverRootSynced.Store(false)
		m.proverRootVerifiedFrame.Store(0)
		m.triggerProverHypersync(proposer, expected)
		return false
	}

	e.logger.Debug(
		"prover root verified",
		zap.Uint64("frame_number", frameNumber),
		zap.String("root", hex.EncodeToString(localRoot)),
		zap.String("proposer", hex.EncodeToString(proposer)),
	)

	m.proverRootSynced.Store(true)
	m.proverRootVerifiedFrame.Store(frameNumber)
	return true
}

func (m *FrameMaterializer) triggerProverHypersync(proposer []byte, expectedRoot []byte) {
	e := m.engine
	if e.consensusProtocol.syncProvider == nil || len(proposer) == 0 {
		e.logger.Debug("no sync provider or proposer")
		return
	}
	if bytes.Equal(proposer, e.getProverAddress()) {
		e.logger.Debug("we are the proposer")
		return
	}
	if !m.proverSyncInProgress.CompareAndSwap(false, true) {
		e.logger.Debug("already syncing")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer m.proverSyncInProgress.Store(false)

		shardKey := tries.ShardKey{
			L1: [3]byte{0x00, 0x00, 0x00},
			L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		}
		e.consensusProtocol.syncProvider.HyperSync(ctx, proposer, shardKey, nil, expectedRoot)
		if err := e.proverRegistry.Refresh(); err != nil {
			e.logger.Warn(
				"failed to refresh prover registry after hypersync",
				zap.Error(err),
			)
		}
		cancel()
	}()

	go func() {
		select {
		case <-e.ShutdownSignal():
			cancel()
		case <-ctx.Done():
		}
	}()
}

// performBlockingProverHypersync performs a synchronous hypersync that blocks
// until completion. This is used at the start of materialize to ensure we sync
// before applying any transactions when there's a prover root mismatch.
func (m *FrameMaterializer) performBlockingProverHypersync(
	proposer []byte,
	expectedRoot []byte,
) []byte {
	e := m.engine
	if e.consensusProtocol.syncProvider == nil || len(proposer) == 0 {
		e.logger.Debug("blocking hypersync: no sync provider or proposer")
		return nil
	}
	if bytes.Equal(proposer, e.getProverAddress()) {
		e.logger.Debug("blocking hypersync: we are the proposer")
		return nil
	}

	// Wait for any existing sync to complete first
	for m.proverSyncInProgress.Load() {
		e.logger.Debug("blocking hypersync: waiting for existing sync to complete")
		time.Sleep(100 * time.Millisecond)
	}

	// Mark sync as in progress
	if !m.proverSyncInProgress.CompareAndSwap(false, true) {
		// Another sync started, wait for it
		for m.proverSyncInProgress.Load() {
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	}
	defer m.proverSyncInProgress.Store(false)

	e.logger.Info(
		"performing blocking hypersync before processing frame",
		zap.String("proposer", hex.EncodeToString(proposer)),
		zap.String("expected_root", hex.EncodeToString(expectedRoot)),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up shutdown handler
	done := make(chan struct{})
	go func() {
		select {
		case <-e.ShutdownSignal():
			cancel()
		case <-done:
		}
	}()

	shardKey := tries.ShardKey{
		L1: [3]byte{0x00, 0x00, 0x00},
		L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
	}

	// Perform sync synchronously (blocking)
	newRoots := e.consensusProtocol.syncProvider.HyperSync(ctx, proposer, shardKey, nil, expectedRoot)
	close(done)

	// Check if HyperSync actually converged: the vertex adds root (first
	// valid entry) must match expectedRoot. HyperSync appends nil roots for
	// failed phase syncs, so len(newRoots) > 0 does not imply success.
	hyperSyncConverged := false
	for _, root := range newRoots {
		if len(root) > 0 && bytes.Equal(root, expectedRoot) {
			hyperSyncConverged = true
			break
		}
	}

	if !hyperSyncConverged {
		if len(newRoots) > 0 {
			e.logger.Warn(
				"HyperSync returned roots but did not converge to expected root",
				zap.Int("root_count", len(newRoots)),
				zap.String("expected_root", hex.EncodeToString(expectedRoot)),
			)
		}

		// Fall back to the archive client's existing gRPC connection. The
		// archive server registers HypergraphComparisonService on the same
		// streaming server, so we can sync directly without key registry or
		// peer info.
		if e.archiveClient != nil {
			e.logger.Info("falling back to archive client for sync")
			newRoots = nil
			if hg, ok := e.hypergraph.(*hgcrdt.HypergraphCRDT); ok {
				conn := e.archiveClient.Conn()
				phases := []protobufs.HypergraphPhaseSet{
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
				}
				for _, phase := range phases {
					client := protobufs.NewHypergraphComparisonServiceClient(conn)
					str, err := client.PerformSync(ctx)
					if err != nil {
						e.logger.Error(
							"archive sync: PerformSync error",
							zap.String("phase", phase.String()),
							zap.Error(err),
						)
						break
					}
					root, syncErr := hg.SyncFrom(str, shardKey, phase, expectedRoot)
					str.CloseSend()
					if syncErr != nil {
						e.logger.Error(
							"archive sync: SyncFrom error",
							zap.String("phase", phase.String()),
							zap.Error(syncErr),
						)
					}
					newRoots = append(newRoots, root)
				}
			}
		}
	}

	e.logger.Info("blocking hypersync completed",
		zap.Int("root_count", len(newRoots)),
		zap.Bool("converged", hyperSyncConverged),
	)

	if !e.config.Engine.ArchiveMode {
		if err := e.proverRegistry.Refresh(); err != nil {
			e.logger.Warn(
				"failed to refresh prover registry after blocking hypersync",
				zap.Error(err),
			)
		}
	}

	if len(newRoots) == 0 {
		return nil
	}

	return newRoots[0]
}

func (m *FrameMaterializer) reconcileLocalWorkerAllocations() {
	e := m.engine
	if e.config.Engine.ArchiveMode {
		return
	}
	if e.workerManager == nil || e.proverRegistry == nil {
		return
	}
	workers, err := e.workerManager.RangeWorkers()
	if err != nil || len(workers) == 0 {
		if err != nil {
			e.logger.Warn(
				"failed to range workers for reconciliation",
				zap.Error(err),
			)
		}
		return
	}

	info, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	if err != nil || info == nil {
		if err != nil {
			e.logger.Warn(
				"failed to load prover info for reconciliation",
				zap.Error(err),
			)
		}
		return
	}

	statusByFilter := make(
		map[string]typesconsensus.ProverStatus,
		len(info.Allocations),
	)
	for _, alloc := range info.Allocations {
		if len(alloc.ConfirmationFilter) == 0 {
			continue
		}
		statusByFilter[hex.EncodeToString(alloc.ConfirmationFilter)] = alloc.Status
	}

	for _, worker := range workers {
		if len(worker.Filter) == 0 {
			continue
		}
		key := hex.EncodeToString(worker.Filter)
		status, ok := statusByFilter[key]
		if !ok {
			if worker.Allocated {
				if err := e.workerManager.DeallocateWorker(worker.CoreId); err != nil {
					e.logger.Warn(
						"failed to deallocate worker for missing allocation",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
			continue
		}

		switch status {
		case typesconsensus.ProverStatusActive:
			if !worker.Allocated {
				if err := e.workerManager.AllocateWorker(
					worker.CoreId,
					worker.Filter,
				); err != nil {
					e.logger.Warn(
						"failed to allocate worker after confirmation",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
		case typesconsensus.ProverStatusLeaving,
			typesconsensus.ProverStatusRejected,
			typesconsensus.ProverStatusKicked:
			if worker.Allocated {
				if err := e.workerManager.DeallocateWorker(worker.CoreId); err != nil {
					e.logger.Warn(
						"failed to deallocate worker after status change",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
		}
	}
}
