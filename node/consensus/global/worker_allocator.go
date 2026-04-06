package global

// worker_allocator.go contains the WorkerAllocator sub-component of
// GlobalConsensusEngine.  It owns worker allocation, join/leave proposal,
// and seniority merge logic.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// WorkerAllocator encapsulates worker allocation, join/leave proposal,
// and seniority merge logic.  It holds a back-reference to the engine
// for shared state access, plus the fields it exclusively owns.
type WorkerAllocator struct {
	engine *GlobalConsensusEngine

	// Owned state
	proposer                *provers.Manager
	lastJoinAttemptFrame    atomic.Uint64
	lastSeniorityMergeFrame atomic.Uint64
}

// NewWorkerAllocator creates a WorkerAllocator bound to the given engine.
// proposer may be nil for archive nodes.
func NewWorkerAllocator(
	engine *GlobalConsensusEngine,
	proposer *provers.Manager,
) *WorkerAllocator {
	return &WorkerAllocator{
		engine:   engine,
		proposer: proposer,
	}
}

const pendingFilterGraceFrames = 720

// proposalTimeoutFrames is the number of frames to wait for a join proposal
// to appear in the registry before clearing the worker's filter. If a proposal is
// submitted but never lands (e.g., network issues, not included in frame),
// we should reset the filter so the worker can try again.
const proposalTimeoutFrames = 10

type allocationSnapshot struct {
	shardsPending       int
	awaitingFrames      []string
	shardsLeaving       int
	shardsActive        int
	shardsPaused        int
	shardDivisions      int
	logicalShards       int
	pendingFilters      [][]byte
	proposalDescriptors []provers.ShardDescriptor
	decideDescriptors   []provers.ShardDescriptor
	worldBytes          *big.Int

	// Leave rebalancing fields
	leaveProposalCandidates []provers.ShardDescriptor // Active allocations eligible for leave
	pendingLeaveFilters     [][]byte                  // Leaving allocations in 360-720 window
}

func (s *allocationSnapshot) statusFields() []zap.Field {
	if s == nil {
		return nil
	}

	return []zap.Field{
		zap.Int("pending_joins", s.shardsPending),
		zap.String("pending_join_frames", strings.Join(s.awaitingFrames, ", ")),
		zap.Int("pending_leaves", s.shardsLeaving),
		zap.Int("active", s.shardsActive),
		zap.Int("paused", s.shardsPaused),
		zap.Int("network_shards", s.shardDivisions),
		zap.Int("network_logical_shards", s.logicalShards),
	}
}

func (s *allocationSnapshot) proposalSnapshotFields() []zap.Field {
	if s == nil {
		return nil
	}

	return []zap.Field{
		zap.Int("proposal_candidates", len(s.proposalDescriptors)),
		zap.Int("pending_confirmations", len(s.pendingFilters)),
		zap.Int("decide_descriptors", len(s.decideDescriptors)),
	}
}

func (w *WorkerAllocator) estimateSeniorityFromConfig() uint64 {
	peerIds := []string{}
	peerIds = append(peerIds, peer.ID(w.engine.pubsub.GetPeerID()).String())
	if len(w.engine.config.Engine.MultisigProverEnrollmentPaths) != 0 {
		for _, conf := range w.engine.config.Engine.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				w.engine.logger.Error("could not load config", zap.Error(err))
				continue
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				w.engine.logger.Error("could not decode peer key", zap.Error(err))
				continue
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				w.engine.logger.Error("could not unmarshal peer key", zap.Error(err))
				continue
			}

			pub := privKey.GetPublic()
			id, err := peer.IDFromPublicKey(pub)
			if err != nil {
				w.engine.logger.Error("could not unmarshal peerid", zap.Error(err))
				continue
			}

			peerIds = append(peerIds, id.String())
		}
	}
	seniorityBI := compat.GetAggregatedSeniority(peerIds)
	return seniorityBI.Uint64()
}

func (w *WorkerAllocator) evaluateForProposals(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	allowProposals bool,
) {
	self, effectiveSeniority := w.allocationContext()
	w.reconcileWorkerAllocations(data.Frame.Header.FrameNumber, self)

	// Re-check after reconciliation — stale filters may have been cleared,
	// making workers available for new proposals.
	if !allowProposals {
		workers, err := w.engine.workerManager.RangeWorkers()
		if err == nil {
			for _, wk := range workers {
				if wk != nil && len(wk.Filter) == 0 && !wk.ManuallyManaged {
					allowProposals = true
					break
				}
			}
		}
	}

	w.checkExcessPendingJoins(self, data.Frame.Header.FrameNumber)
	canPropose, skipReason := w.joinProposalReady(data.Frame.Header.FrameNumber)

	snapshot, ok := w.collectAllocationSnapshot(
		ctx,
		data,
		self,
		effectiveSeniority,
	)
	if !ok {
		return
	}

	w.logAllocationStatus(snapshot)
	pendingFilters := snapshot.pendingFilters
	proposalDescriptors := snapshot.proposalDescriptors
	decideDescriptors := snapshot.decideDescriptors
	worldBytes := snapshot.worldBytes

	// Filter out manually-managed workers from auto-management decisions.
	if mmFilters := w.engine.workerManager.ManuallyManagedFilters(); len(mmFilters) > 0 {
		pendingFilters = filterByteSlices(pendingFilters, mmFilters)
		snapshot.leaveProposalCandidates = filterDescriptors(snapshot.leaveProposalCandidates, mmFilters)
		snapshot.pendingLeaveFilters = filterByteSlices(snapshot.pendingLeaveFilters, mmFilters)
	}

	joinProposedThisCycle := false
	if len(proposalDescriptors) != 0 && allowProposals {
		if canPropose {
			proposals, err := w.proposer.PlanAndAllocate(
				uint64(data.Frame.Header.Difficulty),
				proposalDescriptors,
				100,
				worldBytes,
				data.Frame.Header.FrameNumber,
			)
			if err != nil {
				w.engine.logger.Error("could not plan shard allocations", zap.Error(err))
			} else {
				if len(proposals) > 0 {
					joinProposedThisCycle = true
					w.lastJoinAttemptFrame.Store(data.Frame.Header.FrameNumber)
				}
				expectedRewardSum := big.NewInt(0)
				for _, p := range proposals {
					expectedRewardSum.Add(expectedRewardSum, p.ExpectedReward)
				}
				raw := decimal.NewFromBigInt(expectedRewardSum, 0)
				rewardInQuilPerInterval := raw.Div(decimal.NewFromInt(8000000000))
				rewardInQuilPerDay := rewardInQuilPerInterval.Mul(
					decimal.NewFromInt(24 * 60 * 6),
				)
				w.engine.logger.Info(
					"proposed joins",
					zap.Int("shard_proposals", len(proposals)),
					zap.String(
						"estimated_reward_per_interval",
						rewardInQuilPerInterval.String(),
					),
					zap.String(
						"estimated_reward_per_day",
						rewardInQuilPerDay.String(),
					),
				)
			}
		} else {
			w.engine.logger.Info(
				"skipping join proposals",
				zap.String("reason", skipReason),
				zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
			)
		}
	} else if len(proposalDescriptors) != 0 && !allowProposals {
		w.engine.logger.Info(
			"skipping join proposals",
			zap.String("reason", "all workers have local filters but some may not be allocated in registry"),
			zap.Int("unallocated_shards", len(proposalDescriptors)),
			zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
		)
	}

	if !joinProposedThisCycle {
		w.checkAndSubmitSeniorityMerge(self, data.Frame.Header.FrameNumber)
	}

	if len(pendingFilters) != 0 {
		// Build a descriptor list that excludes self's active allocations.
		// DecideJoins computes bestScore from this list — if we include
		// active allocations, their high scores cause perpetual rejection
		// of pending joins (the proposer compares against shards it can't
		// actually switch to, creating an infinite propose-reject loop).
		pendingSet := make(map[string]struct{}, len(pendingFilters))
		for _, pf := range pendingFilters {
			pendingSet[string(pf)] = struct{}{}
		}
		decideCandidates := slices.Clone(proposalDescriptors)
		for _, d := range decideDescriptors {
			if _, isPending := pendingSet[string(d.Filter)]; isPending {
				decideCandidates = append(decideCandidates, d)
			}
		}
		if err := w.proposer.DecideJoins(
			uint64(data.Frame.Header.Difficulty),
			decideCandidates,
			pendingFilters,
			worldBytes,
		); err != nil {
			w.engine.logger.Error("could not decide shard allocations", zap.Error(err))
		} else {
			w.engine.logger.Info(
				"decided on joins",
				zap.Int("joins", len(pendingFilters)),
			)
		}
	}

	// Leave rebalancing: propose leaves for overcrowded shards
	if len(snapshot.leaveProposalCandidates) > 0 && canPropose && !joinProposedThisCycle {
		leaveFilters, err := w.proposer.PlanLeaves(
			uint64(data.Frame.Header.Difficulty),
			snapshot.leaveProposalCandidates,
			proposalDescriptors,
			worldBytes,
		)
		if err != nil {
			w.engine.logger.Error("could not plan leaves", zap.Error(err))
		} else if len(leaveFilters) > 0 {
			w.lastJoinAttemptFrame.Store(data.Frame.Header.FrameNumber)
			w.engine.logger.Info(
				"proposed leaves",
				zap.Int("leave_proposals", len(leaveFilters)),
			)
		}
	}

	// Decide pending leaves in the 360-720 frame window
	if len(snapshot.pendingLeaveFilters) > 0 {
		// Build decideCandidates for leaves: unallocated shards + leaving shard descriptors
		pendingLeaveSet := make(map[string]struct{}, len(snapshot.pendingLeaveFilters))
		for _, pf := range snapshot.pendingLeaveFilters {
			pendingLeaveSet[string(pf)] = struct{}{}
		}
		leaveDecideCandidates := slices.Clone(proposalDescriptors)
		for _, d := range decideDescriptors {
			if _, isLeaving := pendingLeaveSet[string(d.Filter)]; isLeaving {
				leaveDecideCandidates = append(leaveDecideCandidates, d)
			}
		}
		if err := w.proposer.DecideLeaves(
			uint64(data.Frame.Header.Difficulty),
			leaveDecideCandidates,
			snapshot.pendingLeaveFilters,
			worldBytes,
		); err != nil {
			w.engine.logger.Error("could not decide leaves", zap.Error(err))
		} else {
			w.engine.logger.Info(
				"decided on leaves",
				zap.Int("leaves", len(snapshot.pendingLeaveFilters)),
			)
		}
	}
}

func (w *WorkerAllocator) reconcileWorkerAllocations(
	frameNumber uint64,
	self *typesconsensus.ProverInfo,
) {
	if w.engine.workerManager == nil {
		return
	}

	workers, err := w.engine.workerManager.RangeWorkers()
	if err != nil {
		w.engine.logger.Warn("could not load workers for reconciliation", zap.Error(err))
		return
	}

	filtersToWorkers := make(map[string]*store.WorkerInfo, len(workers))
	freeWorkers := make([]*store.WorkerInfo, 0, len(workers))
	for _, worker := range workers {
		if worker == nil {
			continue
		}
		if len(worker.Filter) == 0 {
			freeWorkers = append(freeWorkers, worker)
			continue
		}
		filtersToWorkers[string(worker.Filter)] = worker
	}

	seenFilters := make(map[string]struct{})
	rejectedFilters := make(map[string]struct{})
	if self != nil {
		for _, alloc := range self.Allocations {
			if len(alloc.ConfirmationFilter) == 0 {
				continue
			}

			// Track rejected allocations separately - we need to clear their
			// workers immediately without waiting for the grace period
			if alloc.Status == typesconsensus.ProverStatusRejected {
				rejectedFilters[string(alloc.ConfirmationFilter)] = struct{}{}
				continue
			}

			// Expired joins (implicitly rejected) and expired leaves
			// (implicitly confirmed) should also be cleared immediately —
			// the allocation will never be confirmed/completed and the
			// worker is stuck waiting for a state change that cannot come.
			if alloc.Status == typesconsensus.ProverStatusJoining &&
				frameNumber > alloc.JoinFrameNumber+pendingFilterGraceFrames {
				rejectedFilters[string(alloc.ConfirmationFilter)] = struct{}{}
				continue
			}
			if alloc.Status == typesconsensus.ProverStatusLeaving &&
				frameNumber > alloc.LeaveFrameNumber+pendingFilterGraceFrames {
				rejectedFilters[string(alloc.ConfirmationFilter)] = struct{}{}
				continue
			}

			key := string(alloc.ConfirmationFilter)
			worker, ok := filtersToWorkers[key]
			if !ok {
				if len(freeWorkers) == 0 {
					w.engine.logger.Warn(
						"no free worker available for registry allocation",
						zap.String("filter", hex.EncodeToString(alloc.ConfirmationFilter)),
					)
					continue
				}
				worker = freeWorkers[0]
				freeWorkers = freeWorkers[1:]
				worker.Filter = slices.Clone(alloc.ConfirmationFilter)
			}

			seenFilters[key] = struct{}{}

			desiredAllocated := alloc.Status == typesconsensus.ProverStatusActive ||
				alloc.Status == typesconsensus.ProverStatusPaused

			pendingFrame := alloc.JoinFrameNumber
			if desiredAllocated {
				pendingFrame = 0
			}

			if worker.Allocated != desiredAllocated ||
				worker.PendingFilterFrame != pendingFrame {
				worker.Allocated = desiredAllocated
				worker.PendingFilterFrame = pendingFrame
				if err := w.engine.workerManager.RegisterWorker(worker); err != nil {
					w.engine.logger.Warn(
						"failed to update worker allocation state",
						zap.Uint("core_id", worker.CoreId),
						zap.Error(err),
					)
				}
			}
		}
	}

	for _, worker := range workers {
		if worker == nil || len(worker.Filter) == 0 {
			continue
		}
		if _, ok := seenFilters[string(worker.Filter)]; ok {
			continue
		}

		// Immediately clear workers whose allocations were rejected
		// (no grace period needed - the rejection is definitive)
		if _, rejected := rejectedFilters[string(worker.Filter)]; rejected {
			w.engine.logger.Info(
				"clearing rejected worker filter",
				zap.Uint("core_id", worker.CoreId),
				zap.String("filter", hex.EncodeToString(worker.Filter)),
			)
			worker.Filter = nil
			worker.Allocated = false
			worker.PendingFilterFrame = 0
			if err := w.engine.workerManager.RegisterWorker(worker); err != nil {
				w.engine.logger.Warn(
					"failed to clear rejected worker filter",
					zap.Uint("core_id", worker.CoreId),
					zap.Error(err),
				)
			}
			continue
		}

		if worker.PendingFilterFrame != 0 {
			if frameNumber <= worker.PendingFilterFrame {
				continue
			}
			// Worker has a filter set from a proposal, but no registry allocation
			// exists for this filter. Use shorter timeout since the proposal
			// likely didn't land at all.
			if frameNumber-worker.PendingFilterFrame < proposalTimeoutFrames {
				continue
			}
		}

		// If we can't get prover info (self == nil) and the worker has a filter
		// with PendingFilterFrame == 0 (not from a recent proposal), log a warning
		// but still clear it after a grace period to avoid stuck state
		if worker.PendingFilterFrame == 0 && self == nil {
			w.engine.logger.Warn(
				"worker has orphaned filter with no prover info available",
				zap.Uint("core_id", worker.CoreId),
				zap.String("filter", hex.EncodeToString(worker.Filter)),
				zap.Bool("allocated", worker.Allocated),
			)
			// Still clear it - if we can't verify the allocation, assume it's stale
		}

		w.engine.logger.Info(
			"clearing stale worker filter",
			zap.Uint("core_id", worker.CoreId),
			zap.String("filter", hex.EncodeToString(worker.Filter)),
			zap.Bool("was_allocated", worker.Allocated),
			zap.Uint64("pending_frame", worker.PendingFilterFrame),
			zap.Bool("self_nil", self == nil),
		)
		worker.Filter = nil
		worker.Allocated = false
		worker.PendingFilterFrame = 0
		if err := w.engine.workerManager.RegisterWorker(worker); err != nil {
			w.engine.logger.Warn(
				"failed to clear stale worker filter",
				zap.Uint("core_id", worker.CoreId),
				zap.Error(err),
			)
		}
	}
}

// shardRingInfo holds the ring assignment values derived from the total
// number of active+joining provers on a shard. Ring = floor(rank / 8)
// where rank is a 0-indexed position in the sorted candidate list.
type shardRingInfo struct {
	// currentRing: ring of the last existing prover (position count-1).
	currentRing uint8
	// joinerRing: ring a new joiner would land on (position count).
	joinerRing uint8
	// activeOnCurrentRing: provers sharing the last existing prover's ring.
	activeOnCurrentRing uint64
	// activeOnJoinerRing: provers that would share the joiner's ring
	// (existing on that ring + the joiner itself).
	activeOnJoinerRing uint64
}

// computeShardRingInfo calculates ring assignments from the count of
// active+joining provers on a shard.
func computeShardRingInfo(totalActiveJoining int) shardRingInfo {
	ri := shardRingInfo{}

	if totalActiveJoining > 0 {
		ri.currentRing = uint8((totalActiveJoining - 1) / 8)
	}
	ri.joinerRing = uint8(totalActiveJoining / 8)

	ri.activeOnCurrentRing = uint64(totalActiveJoining % 8)
	if ri.activeOnCurrentRing == 0 && totalActiveJoining > 0 {
		ri.activeOnCurrentRing = 8
	}

	ri.activeOnJoinerRing = uint64(totalActiveJoining%8) + 1

	return ri
}

// resolveProverRing determines the ring and on-ring count for a shard entry.
//
//   - totalCandidates: number of active+joining provers on the shard.
//   - isAllocated: whether the local prover is allocated to this shard.
//   - selfAddress: the local prover's address (may be nil).
//   - candidateAddrs: lazy accessor returning the sorted candidate addresses
//     (only called when isAllocated && selfAddress is set).
//
// Returns (ring, onRing).
func resolveProverRing(
	totalCandidates int,
	isAllocated bool,
	selfAddress []byte,
	candidateAddrs func() [][]byte,
) (uint8, int) {
	ri := computeShardRingInfo(totalCandidates)

	if !isAllocated || len(selfAddress) == 0 {
		return ri.joinerRing, int(ri.activeOnJoinerRing)
	}

	// Find this prover's actual rank in the sorted candidate list.
	for rank, addr := range candidateAddrs() {
		if bytes.Equal(addr, selfAddress) {
			ring := uint8(rank / 8)
			ringStart := rank - (rank % 8)
			onRing := totalCandidates - ringStart
			if onRing > 8 {
				onRing = 8
			}
			return ring, onRing
		}
	}

	// Prover is allocated but not in the active/joining candidate list
	// (e.g. leaving or paused). Fall back to the last existing prover's ring.
	return ri.currentRing, int(ri.activeOnCurrentRing)
}

func (w *WorkerAllocator) collectAllocationSnapshot(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	self *typesconsensus.ProverInfo,
	_ uint64, // effectiveSeniority – no longer used for ring prediction
) (*allocationSnapshot, bool) {
	appShards, err := w.engine.shardsStore.RangeAppShards()
	if err != nil {
		w.engine.logger.Error("could not obtain app shard info", zap.Error(err))
		return nil, false
	}

	// consolidate into high level L2 shards:
	shardMap := map[string]store.ShardInfo{}
	for _, s := range appShards {
		shardMap[string(s.L2)] = s
	}

	shards := []store.ShardInfo{}
	for _, s := range shardMap {
		shards = append(shards, store.ShardInfo{
			L1: s.L1,
			L2: s.L2,
		})
	}

	registry, err := w.engine.keyStore.GetKeyRegistryByProver(data.Frame.Header.Prover)
	if err != nil {
		w.engine.logger.Info(
			"awaiting key registry info for prover",
			zap.String(
				"prover_address",
				hex.EncodeToString(data.Frame.Header.Prover),
			),
		)
		return nil, false
	}

	if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
		w.engine.logger.Info("key registry info missing identity of prover")
		return nil, false
	}

	pub, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		w.engine.logger.Warn("error unmarshaling identity key", zap.Error(err))
		return nil, false
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		w.engine.logger.Warn("error deriving peer id", zap.Error(err))
		return nil, false
	}

	info := w.engine.peerInfoManager.GetPeerInfo([]byte(peerId))
	if info == nil {
		w.engine.logger.Info(
			"no peer info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil, false
	}

	if len(info.Reachability) == 0 {
		w.engine.logger.Info(
			"no reachability info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil, false
	}

	var client protobufs.GlobalServiceClient = nil
	if len(info.Reachability[0].StreamMultiaddrs) > 0 {
		s := info.Reachability[0].StreamMultiaddrs[0]
		creds, err := p2p.NewPeerAuthenticator(
			w.engine.logger,
			w.engine.config.P2P,
			nil,
			nil,
			nil,
			nil,
			[][]byte{[]byte(peerId)},
			map[string]channel.AllowedPeerPolicyType{},
			map[string]channel.AllowedPeerPolicyType{},
		).CreateClientTLSCredentials([]byte(peerId))
		if err != nil {
			return nil, false
		}

		ma, err := multiaddr.StringCast(s)
		if err != nil {
			return nil, false
		}

		mga, err := mn.ToNetAddr(ma)
		if err != nil {
			return nil, false
		}

		cc, err := grpc.NewClient(
			mga.String(),
			grpc.WithTransportCredentials(creds),
		)
		if err != nil {
			w.engine.logger.Debug(
				"could not establish direct channel, trying next multiaddr",
				zap.String("peer", peer.ID(peerId).String()),
				zap.String("multiaddr", ma.String()),
				zap.Error(err),
			)
			return nil, false
		}
		defer func() {
			if err := cc.Close(); err != nil {
				w.engine.logger.Error("error while closing connection", zap.Error(err))
			}
		}()

		client = protobufs.NewGlobalServiceClient(cc)
	}

	if client == nil {
		w.engine.logger.Debug("could not get app shards from prover")
		return nil, false
	}

	worldBytes := big.NewInt(0)
	shardsPending := 0
	shardsActive := 0
	shardsLeaving := 0
	shardsPaused := 0
	logicalShards := 0
	shardDivisions := 0
	awaitingFrame := map[uint64]struct{}{}
	pendingFilters := [][]byte{}
	proposalDescriptors := []provers.ShardDescriptor{}
	decideDescriptors := []provers.ShardDescriptor{}
	leaveProposalCandidates := []provers.ShardDescriptor{}
	pendingLeaveFilters := [][]byte{}

	for _, shardInfo := range shards {
		shardKey := slices.Concat(shardInfo.L1, shardInfo.L2)
		var resp *protobufs.GetAppShardsResponse
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			resp, err = w.getAppShardsFromProver(client, shardKey)
			if err == nil {
				break
			}
			w.engine.logger.Debug(
				"retrying app shard retrieval",
				zap.Int("attempt", attempt+1),
				zap.Error(err),
			)
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
		if err != nil {
			w.engine.logger.Debug("could not get app shards from prover after retries", zap.Error(err))
			return nil, false
		}

		for _, shard := range resp.Info {
			shardDivisions++
			worldBytes = worldBytes.Add(worldBytes, new(big.Int).SetBytes(shard.Size))
			bp := slices.Clone(shardInfo.L2)
			for _, p := range shard.Prefix {
				bp = append(bp, byte(p))
			}

			prs, err := w.engine.proverRegistry.GetProvers(bp)
			if err != nil {
				w.engine.logger.Error("failed to get provers", zap.Error(err))
				continue
			}

			allocated := false
			pending := false
			isActiveAllocation := false
			isPendingLeave := false
			if self != nil {
				for _, allocation := range self.Allocations {
					if bytes.Equal(allocation.ConfirmationFilter, bp) {
						allocated = allocation.Status != typesconsensus.ProverStatusLeaving

						// Treat expired joins and leaves as unallocated so the
						// proposer will submit a fresh join instead of sitting
						// in limbo.
						if allocation.Status == typesconsensus.ProverStatusJoining &&
							data.Frame.Header.FrameNumber > allocation.JoinFrameNumber+pendingFilterGraceFrames {
							allocated = false
						}
						if allocation.Status == typesconsensus.ProverStatusLeaving &&
							data.Frame.Header.FrameNumber > allocation.LeaveFrameNumber+pendingFilterGraceFrames {
							allocated = false
						}

						if allocation.Status == typesconsensus.ProverStatusJoining &&
							data.Frame.Header.FrameNumber <= allocation.JoinFrameNumber+pendingFilterGraceFrames {
							shardsPending++
							awaitingFrame[allocation.JoinFrameNumber+360] = struct{}{}
						}
						if allocation.Status == typesconsensus.ProverStatusActive {
							shardsActive++
							isActiveAllocation = true
						}
						if allocation.Status == typesconsensus.ProverStatusLeaving &&
							data.Frame.Header.FrameNumber <= allocation.LeaveFrameNumber+pendingFilterGraceFrames {
							shardsLeaving++
							// Check if in the 360-720 decision window
							if allocation.LeaveFrameNumber+360 <= data.Frame.Header.FrameNumber {
								isPendingLeave = true
							}
						}
						if allocation.Status == typesconsensus.ProverStatusPaused {
							shardsPaused++
						}
						if w.engine.config.P2P.Network != 0 ||
							data.Frame.Header.FrameNumber > token.FRAME_2_1_EXTENDED_ENROLL_END {
							pending = allocation.Status ==
								typesconsensus.ProverStatusJoining &&
								allocation.JoinFrameNumber+360 <= data.Frame.Header.FrameNumber &&
								data.Frame.Header.FrameNumber <= allocation.JoinFrameNumber+pendingFilterGraceFrames
						}
					}
				}
			}

			size := new(big.Int).SetBytes(shard.Size)
			if size.Cmp(big.NewInt(0)) == 0 {
				continue
			}

			logicalShards += int(shard.DataShards)

			// Count all active/joining provers on this shard. The actual ring
			// assignment (global_prover_shard_update.go:computeRingAssignments)
			// uses floor(rank / 8) where rank is position in the full sorted
			// candidate list. A new joiner lands at the end (0-indexed
			// position = totalActiveJoining), so predicted ring =
			// floor(totalActiveJoining / 8).
			totalActiveJoining := 0
			for _, i := range prs {
				for _, a := range i.Allocations {
					if !bytes.Equal(a.ConfirmationFilter, bp) {
						continue
					}
					if a.Status == typesconsensus.ProverStatusActive ||
						a.Status == typesconsensus.ProverStatusJoining {
						totalActiveJoining++
					}
					break
				}
			}

			ri := computeShardRingInfo(totalActiveJoining)
			currentRing := ri.currentRing
			joinerRing := ri.joinerRing
			activeOnJoinerRing := ri.activeOnJoinerRing
			activeOnCurrentRing := ri.activeOnCurrentRing

			if allocated && pending {
				pendingFilters = append(pendingFilters, bp)
			}
			if !allocated {
				proposalDescriptors = append(
					proposalDescriptors,
					provers.ShardDescriptor{
						Filter:       bp,
						Size:         size.Uint64(),
						Ring:         joinerRing,
						Shards:       shard.DataShards,
						ActiveOnRing: activeOnJoinerRing,
					},
				)
			}
			if isActiveAllocation {
				leaveProposalCandidates = append(
					leaveProposalCandidates,
					provers.ShardDescriptor{
						Filter:       bp,
						Size:         size.Uint64(),
						Ring:         currentRing,
						Shards:       shard.DataShards,
						ActiveOnRing: activeOnCurrentRing,
					},
				)
			}
			if isPendingLeave {
				pendingLeaveFilters = append(pendingLeaveFilters, bp)
			}
			decideDescriptors = append(
				decideDescriptors,
				provers.ShardDescriptor{
					Filter:       bp,
					Size:         size.Uint64(),
					Ring:         currentRing,
					Shards:       shard.DataShards,
					ActiveOnRing: activeOnCurrentRing,
				},
			)
		}
	}

	awaitingFrames := []string{}
	for frame := range awaitingFrame {
		awaitingFrames = append(awaitingFrames, fmt.Sprintf("%d", frame))
	}

	return &allocationSnapshot{
		shardsPending:           shardsPending,
		awaitingFrames:          awaitingFrames,
		shardsLeaving:           shardsLeaving,
		shardsActive:            shardsActive,
		shardsPaused:            shardsPaused,
		shardDivisions:          shardDivisions,
		logicalShards:           logicalShards,
		pendingFilters:          pendingFilters,
		proposalDescriptors:     proposalDescriptors,
		decideDescriptors:       decideDescriptors,
		worldBytes:              worldBytes,
		leaveProposalCandidates: leaveProposalCandidates,
		pendingLeaveFilters:     pendingLeaveFilters,
	}, true
}

func (w *WorkerAllocator) logAllocationStatus(
	snapshot *allocationSnapshot,
) {
	if snapshot == nil {
		return
	}

	w.engine.logger.Info(
		"status for allocations",
		snapshot.statusFields()...,
	)

	w.engine.logger.Debug(
		"proposal evaluation snapshot",
		snapshot.proposalSnapshotFields()...,
	)
}

func (w *WorkerAllocator) logAllocationStatusOnly(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	self *typesconsensus.ProverInfo,
	effectiveSeniority uint64,
) {
	snapshot, ok := w.collectAllocationSnapshot(
		ctx,
		data,
		self,
		effectiveSeniority,
	)
	if !ok || snapshot == nil {
		w.engine.logger.Info(
			"all workers already allocated or pending; skipping proposal cycle",
		)
		return
	}

	w.engine.logger.Info(
		"all workers already allocated or pending; skipping proposal cycle",
		snapshot.statusFields()...,
	)
	w.logAllocationStatus(snapshot)
}

// checkAndSubmitSeniorityMerge submits a seniority merge if the prover exists
// with incorrect seniority and cooldowns have elapsed. This is called both from
// evaluateForProposals (when no join was proposed) and from the "all workers
// allocated" path, ensuring seniority is corrected regardless of allocation state.
func (w *WorkerAllocator) checkAndSubmitSeniorityMerge(
	self *typesconsensus.ProverInfo,
	frameNumber uint64,
) {
	if self == nil {
		return
	}

	mergeSeniority := w.estimateSeniorityFromConfig()
	if mergeSeniority <= self.Seniority {
		return
	}

	lastJoin := w.lastJoinAttemptFrame.Load()
	lastMerge := w.lastSeniorityMergeFrame.Load()
	joinCooldownOk := lastJoin == 0 || frameNumber-lastJoin >= 10
	mergeCooldownOk := lastMerge == 0 || frameNumber-lastMerge >= 10

	if joinCooldownOk && mergeCooldownOk {
		frame := w.engine.GetFrame()
		if frame != nil {
			helpers, peerIds := w.buildMergeHelpers()
			err := w.submitSeniorityMerge(
				frame, helpers, mergeSeniority, peerIds,
			)
			if err != nil {
				w.engine.logger.Error(
					"could not submit seniority merge",
					zap.Error(err),
				)
			} else {
				w.lastSeniorityMergeFrame.Store(frameNumber)
			}
		}
	} else {
		w.engine.logger.Debug(
			"seniority merge deferred due to cooldown",
			zap.Uint64("merge_seniority", mergeSeniority),
			zap.Uint64("existing_seniority", self.Seniority),
			zap.Uint64("last_join_frame", lastJoin),
			zap.Uint64("last_merge_frame", lastMerge),
			zap.Uint64("current_frame", frameNumber),
		)
	}
}

func (w *WorkerAllocator) allocationContext() (
	*typesconsensus.ProverInfo,
	uint64,
) {
	self, err := w.engine.proverRegistry.GetProverInfo(w.engine.getProverAddress())
	if err != nil || self == nil {
		return nil, w.estimateSeniorityFromConfig()
	}
	return self, self.Seniority
}

func (w *WorkerAllocator) checkExcessPendingJoins(
	self *typesconsensus.ProverInfo,
	frameNumber uint64,
) {
	excessFilters := w.selectExcessPendingFilters(self, frameNumber)
	if len(excessFilters) != 0 {
		w.engine.logger.Debug(
			"identified excess pending joins",
			zap.Int("excess_count", len(excessFilters)),
			zap.Uint64("frame_number", frameNumber),
		)
		w.rejectExcessPending(excessFilters, frameNumber)
		return
	}

	w.engine.logger.Debug(
		"no excess pending joins detected",
		zap.Uint64("frame_number", frameNumber),
	)
}

func (w *WorkerAllocator) publishKeyRegistry() {
	vk, err := w.engine.keyManager.GetAgreementKey("q-view-key")
	if err != nil {
		vk, err = w.engine.keyManager.CreateAgreementKey(
			"q-view-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			w.engine.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	sk, err := w.engine.keyManager.GetAgreementKey("q-spend-key")
	if err != nil {
		sk, err = w.engine.keyManager.CreateAgreementKey(
			"q-spend-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			w.engine.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	pk, err := w.engine.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		pk, _, err = w.engine.keyManager.CreateSigningKey(
			"q-prover-key",
			crypto.KeyTypeBLS48581G1,
		)
		if err != nil {
			w.engine.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	onion, err := w.engine.keyManager.GetAgreementKey("q-onion-key")
	if err != nil {
		onion, err = w.engine.keyManager.CreateAgreementKey(
			"q-onion-key",
			crypto.KeyTypeX448,
		)
		if err != nil {
			w.engine.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	sig, err := w.engine.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			pk.Public().([]byte),
		),
	)
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigp, err := pk.SignWithDomain(
		w.engine.pubsub.GetPublicKey(),
		[]byte("KEY_REGISTRY"),
	)
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigvk, err := w.engine.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			vk.Public(),
		),
	)
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigsk, err := w.engine.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			sk.Public(),
		),
	)
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigonion, err := w.engine.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			onion.Public(),
		),
	)
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	registry := &protobufs.KeyRegistry{
		LastUpdated: uint64(time.Now().UnixMilli()),
		IdentityKey: &protobufs.Ed448PublicKey{
			KeyValue: w.engine.pubsub.GetPublicKey(),
		},
		ProverKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: pk.Public().([]byte),
		},
		IdentityToProver: &protobufs.Ed448Signature{
			Signature: sig,
		},
		ProverToIdentity: &protobufs.BLS48581Signature{
			Signature: sigp,
		},
		KeysByPurpose: map[string]*protobufs.KeyCollection{
			"ONION_ROUTING": &protobufs.KeyCollection{
				KeyPurpose: "ONION_ROUTING",
				X448Keys: []*protobufs.SignedX448Key{{
					Key: &protobufs.X448PublicKey{
						KeyValue: onion.Public(),
					},
					ParentKeyAddress: w.engine.pubsub.GetPeerID(),
					Signature: &protobufs.SignedX448Key_Ed448Signature{
						Ed448Signature: &protobufs.Ed448Signature{
							Signature: sigonion,
						},
					},
				}},
			},
			"view": &protobufs.KeyCollection{
				KeyPurpose: "view",
				Decaf448Keys: []*protobufs.SignedDecaf448Key{{
					Key: &protobufs.Decaf448PublicKey{
						KeyValue: vk.Public(),
					},
					ParentKeyAddress: w.engine.pubsub.GetPeerID(),
					Signature: &protobufs.SignedDecaf448Key_Ed448Signature{
						Ed448Signature: &protobufs.Ed448Signature{
							Signature: sigvk,
						},
					},
				}},
			},
			"spend": &protobufs.KeyCollection{
				KeyPurpose: "spend",
				Decaf448Keys: []*protobufs.SignedDecaf448Key{{
					Key: &protobufs.Decaf448PublicKey{
						KeyValue: sk.Public(),
					},
					ParentKeyAddress: w.engine.pubsub.GetPeerID(),
					Signature: &protobufs.SignedDecaf448Key_Ed448Signature{
						Ed448Signature: &protobufs.Ed448Signature{
							Signature: sigsk,
						},
					},
				}},
			},
		},
	}
	kr, err := registry.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	w.engine.pubsub.PublishToBitmask(
		GLOBAL_PEER_INFO_BITMASK,
		kr,
	)
}

func (w *WorkerAllocator) getAppShardsFromProver(
	client protobufs.GlobalServiceClient,
	shardKey []byte,
) (
	*protobufs.GetAppShardsResponse,
	error,
) {
	getCtx, cancelGet := context.WithTimeout(
		context.Background(),
		w.engine.config.Engine.SyncTimeout,
	)
	response, err := client.GetAppShards(
		getCtx,
		&protobufs.GetAppShardsRequest{
			ShardKey: shardKey, // buildutils:allow-slice-alias slice is static
		},
		// The message size limits are swapped because the server is the one
		// sending the data.
		grpc.MaxCallRecvMsgSize(
			w.engine.config.Engine.SyncMessageLimits.MaxSendMsgSize,
		),
		grpc.MaxCallSendMsgSize(
			w.engine.config.Engine.SyncMessageLimits.MaxRecvMsgSize,
		),
	)
	cancelGet()
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, err
	}

	return response, nil
}

// filterByteSlices removes entries whose hex encoding appears in the exclude set.
func filterByteSlices(items [][]byte, exclude map[string]struct{}) [][]byte {
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		if _, skip := exclude[hex.EncodeToString(item)]; !skip {
			out = append(out, item)
		}
	}
	return out
}

// filterDescriptors removes ShardDescriptors whose filter hex appears in the exclude set.
func filterDescriptors(descs []provers.ShardDescriptor, exclude map[string]struct{}) []provers.ShardDescriptor {
	out := make([]provers.ShardDescriptor, 0, len(descs))
	for _, d := range descs {
		if _, skip := exclude[hex.EncodeToString(d.Filter)]; !skip {
			out = append(out, d)
		}
	}
	return out
}

// --- Methods moved from global_consensus_engine.go ---

func (w *WorkerAllocator) joinProposalReady(
	frameNumber uint64,
) (bool, string) {
	if w.engine.lastObservedFrame.Load() == 0 {
		w.engine.logger.Debug("join proposal blocked: no observed frame")
		return false, "awaiting initial frame"
	}

	if !w.engine.materializer.proverRootSynced.Load() {
		w.engine.logger.Debug("join proposal blocked: prover root not synced")
		return false, "awaiting prover root sync"
	}

	verified := w.engine.materializer.proverRootVerifiedFrame.Load()
	if verified == 0 || verified < frameNumber {
		w.engine.logger.Debug(
			"join proposal blocked: frame not verified",
			zap.Uint64("verified_frame", verified),
			zap.Uint64("current_frame", frameNumber),
		)
		return false, "latest frame not yet verified"
	}

	lastAttempt := w.lastJoinAttemptFrame.Load()
	if lastAttempt != 0 {
		if frameNumber <= lastAttempt {
			w.engine.logger.Debug(
				"join proposal blocked: waiting for newer frame",
				zap.Uint64("last_attempt", lastAttempt),
				zap.Uint64("current_frame", frameNumber),
			)
			return false, "waiting for newer frame"
		}
		if frameNumber-lastAttempt < 4 {
			w.engine.logger.Debug(
				"join proposal blocked: cooling down between attempts",
				zap.Uint64("last_attempt", lastAttempt),
				zap.Uint64("current_frame", frameNumber),
			)
			return false, "cooldown between join attempts"
		}
	}

	return true, ""
}

func (w *WorkerAllocator) selectExcessPendingFilters(
	self *typesconsensus.ProverInfo,
	frameNumber uint64,
) [][]byte {
	if self == nil || w.engine.config == nil || w.engine.config.Engine == nil {
		w.engine.logger.Debug("excess pending evaluation skipped: missing config or prover info")
		return nil
	}

	capacity := w.engine.config.Engine.DataWorkerCount
	if capacity <= 0 {
		return nil
	}

	active := 0
	pending := make([][]byte, 0, len(self.Allocations))

	for _, allocation := range self.Allocations {
		if len(allocation.ConfirmationFilter) == 0 {
			continue
		}

		switch allocation.Status {
		case typesconsensus.ProverStatusActive:
			active++
		case typesconsensus.ProverStatusJoining:
			// Skip expired joins — they are implicitly rejected and should
			// not count toward the pending limit or be candidates for
			// explicit rejection.
			if frameNumber > allocation.JoinFrameNumber+pendingFilterGraceFrames {
				continue
			}
			filterCopy := make([]byte, len(allocation.ConfirmationFilter))
			copy(filterCopy, allocation.ConfirmationFilter)
			pending = append(pending, filterCopy)
		}
	}

	allowedPending := capacity - active
	if allowedPending < 0 {
		allowedPending = 0
	}

	if len(pending) <= allowedPending {
		w.engine.logger.Debug(
			"pending joins within limit",
			zap.Int("active_allocations", active),
			zap.Int("pending_allocations", len(pending)),
			zap.Int("capacity", capacity),
		)
		return nil
	}

	excess := len(pending) - allowedPending
	w.engine.logger.Debug(
		"pending joins exceed limit",
		zap.Int("active_allocations", active),
		zap.Int("pending_allocations", len(pending)),
		zap.Int("capacity", capacity),
		zap.Int("excess", excess),
	)
	rand.Shuffle(len(pending), func(i, j int) {
		pending[i], pending[j] = pending[j], pending[i]
	})

	return pending[:excess]
}

func (w *WorkerAllocator) rejectExcessPending(
	filters [][]byte,
	frameNumber uint64,
) {
	if w.engine.workerManager == nil || len(filters) == 0 {
		return
	}

	last := w.engine.lastRejectFrame.Load()
	if last != 0 {
		if frameNumber <= last {
			w.engine.logger.Debug(
				"forced rejection skipped: awaiting newer frame",
				zap.Uint64("last_reject_frame", last),
				zap.Uint64("current_frame", frameNumber),
			)
			return
		}
		if frameNumber-last < 4 {
			w.engine.logger.Debug(
				"deferring forced join rejections",
				zap.Uint64("frame_number", frameNumber),
				zap.Uint64("last_reject_frame", last),
			)
			return
		}
	}

	limit := len(filters)
	if limit > 100 {
		limit = 100
	}

	rejects := make([][]byte, limit)
	for i := 0; i < limit; i++ {
		rejects[i] = filters[i]
	}

	if err := w.engine.workerManager.DecideAllocations(rejects, nil); err != nil {
		w.engine.logger.Warn("failed to reject excess joins", zap.Error(err))
		return
	}

	w.engine.lastRejectFrame.Store(frameNumber)
	w.engine.logger.Info(
		"submitted forced join rejections",
		zap.Int("rejections", len(rejects)),
		zap.Uint64("frame_number", frameNumber),
	)
}

func (w *WorkerAllocator) ProposeWorkerJoin(
	coreIds []uint,
	filters [][]byte,
	serviceClients map[uint]*grpc.ClientConn,
) error {
	frame := w.engine.GetFrame()
	if frame == nil {
		w.engine.logger.Debug("cannot propose, no frame")
		return errors.New("not ready")
	}

	_, err := w.engine.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		w.engine.logger.Debug("cannot propose, no signer key")
		return errors.Wrap(err, "propose worker join")
	}

	info, err := w.engine.proverRegistry.GetProverInfo(w.engine.getProverAddress())
	proverExists := err == nil && info != nil

	// Build merge helpers and calculate potential merge seniority
	helpers, peerIds := w.buildMergeHelpers()
	mergeSeniorityBI := compat.GetAggregatedSeniority(peerIds)
	var mergeSeniority uint64 = 0
	if mergeSeniorityBI.IsUint64() {
		mergeSeniority = mergeSeniorityBI.Uint64()
	}

	// Always include merge targets in the join — Materialize handles
	// seniority for both new and existing provers. A separate seniority
	// merge is not submitted because it would double-count with the join.
	if proverExists {
		w.engine.logger.Debug(
			"prover already exists, merge targets will be included in join",
			zap.Uint64("existing_seniority", info.Seniority),
			zap.Uint64("merge_seniority", mergeSeniority),
		)
	}

	w.engine.logger.Info(
		"proposing worker join with seniority",
		zap.Uint64("seniority", mergeSeniority),
		zap.Strings("peer_ids", peerIds),
	)

	var delegate []byte
	if w.engine.config.Engine.DelegateAddress != "" {
		delegate, err = hex.DecodeString(w.engine.config.Engine.DelegateAddress)
		if err != nil {
			w.engine.logger.Error("could not construct join", zap.Error(err))
			return errors.Wrap(err, "propose worker join")
		}
	}

	challenge := sha3.Sum256(frame.Header.Output)

	joins := min(len(serviceClients), len(filters))
	results := make([][516]byte, joins)
	idx := uint32(0)
	ids := [][]byte{}
	w.engine.logger.Debug("preparing join commitment")
	for range joins {
		ids = append(
			ids,
			slices.Concat(
				w.engine.getProverAddress(),
				filters[idx],
				binary.BigEndian.AppendUint32(nil, idx),
			),
		)
		idx++
	}

	idx = 0

	wg := errgroup.Group{}
	wg.SetLimit(joins)

	w.engine.logger.Debug(
		"attempting join proof",
		zap.String("challenge", hex.EncodeToString(challenge[:])),
		zap.Uint64("difficulty", uint64(frame.Header.Difficulty)),
		zap.Int("ids_count", len(ids)),
	)

	for _, core := range coreIds {
		svc := serviceClients[core]
		i := idx

		// limit to available joins
		if i == uint32(joins) {
			break
		}
		wg.Go(func() error {
			client := protobufs.NewDataIPCServiceClient(svc)
			resp, err := client.CreateJoinProof(
				context.TODO(),
				&protobufs.CreateJoinProofRequest{
					Challenge:   challenge[:],
					Difficulty:  frame.Header.Difficulty,
					Ids:         ids,
					ProverIndex: i,
				},
			)
			if err != nil {
				return err
			}

			results[i] = [516]byte(resp.Response)
			return nil
		})
		idx++
	}
	w.engine.logger.Debug("waiting for join proof to complete")

	err = wg.Wait()
	if err != nil {
		w.engine.logger.Debug("failed join proof", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	join, err := global.NewProverJoin(
		filters,
		frame.Header.FrameNumber,
		helpers,
		delegate,
		w.engine.keyManager,
		w.engine.hypergraph,
		schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		w.engine.frameProver,
		w.engine.clockStore,
	)
	if err != nil {
		w.engine.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	for _, res := range results {
		join.Proof = append(join.Proof, res[:]...)
	}

	err = join.Prove(frame.Header.FrameNumber)
	if err != nil {
		w.engine.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			{
				Request: &protobufs.MessageRequest_Join{
					Join: join.ToProtobuf(),
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	}

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	err = w.engine.publishProverMessage(msg)
	if err != nil {
		w.engine.logger.Error("could not construct join", zap.Error(err))
		return errors.Wrap(err, "propose worker join")
	}

	w.engine.logger.Info(
		"submitted join request",
		zap.Uint64("seniority", mergeSeniority),
		zap.Strings("peer_ids", peerIds),
	)

	return nil
}

// buildMergeHelpers constructs the seniority merge helpers from the current
// peer key and any configured multisig prover enrollment paths.
func (w *WorkerAllocator) buildMergeHelpers() ([]*global.SeniorityMerge, []string) {
	helpers := []*global.SeniorityMerge{}
	peerIds := []string{}

	peerPrivKeyBytes, err := hex.DecodeString(w.engine.config.P2P.PeerPrivKey)
	if err != nil {
		w.engine.logger.Debug("cannot decode peer key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	peerPrivKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKeyBytes)
	if err != nil {
		w.engine.logger.Debug("cannot unmarshal peer key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	peerPub := peerPrivKey.GetPublic()
	peerPubBytes, err := peerPub.Raw()
	if err != nil {
		w.engine.logger.Debug("cannot get peer public key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	peerPrivRaw, err := peerPrivKey.Raw()
	if err != nil {
		w.engine.logger.Debug("cannot get peer private key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	oldProver, err := keys.Ed448KeyFromBytes(peerPrivRaw, peerPubBytes)
	if err != nil {
		w.engine.logger.Debug("cannot get peer key for merge helpers", zap.Error(err))
		return helpers, peerIds
	}

	helpers = append(helpers, global.NewSeniorityMerge(
		crypto.KeyTypeEd448,
		oldProver,
	))

	peerId, err := peer.IDFromPublicKey(peerPub)
	if err != nil {
		w.engine.logger.Debug("cannot get peer ID for merge helpers", zap.Error(err))
		return helpers, peerIds
	}
	peerIds = append(peerIds, peerId.String())

	if len(w.engine.config.Engine.MultisigProverEnrollmentPaths) != 0 {
		w.engine.logger.Debug("loading old configs for merge helpers")
		for _, conf := range w.engine.config.Engine.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				w.engine.logger.Error("could not load config for merge helpers", zap.Error(err))
				continue
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				w.engine.logger.Error("could not decode peer key for merge helpers", zap.Error(err))
				continue
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				w.engine.logger.Error("could not unmarshal peer key for merge helpers", zap.Error(err))
				continue
			}

			pub := privKey.GetPublic()
			pubBytes, err := pub.Raw()
			if err != nil {
				w.engine.logger.Error("could not get public key for merge helpers", zap.Error(err))
				continue
			}

			id, err := peer.IDFromPublicKey(pub)
			if err != nil {
				w.engine.logger.Error("could not get peer ID for merge helpers", zap.Error(err))
				continue
			}

			priv, err := privKey.Raw()
			if err != nil {
				w.engine.logger.Error("could not get private key for merge helpers", zap.Error(err))
				continue
			}

			signer, err := keys.Ed448KeyFromBytes(priv, pubBytes)
			if err != nil {
				w.engine.logger.Error("could not create signer for merge helpers", zap.Error(err))
				continue
			}

			peerIds = append(peerIds, id.String())
			helpers = append(helpers, global.NewSeniorityMerge(
				crypto.KeyTypeEd448,
				signer,
			))
		}
	}

	return helpers, peerIds
}

// submitSeniorityMerge submits a seniority merge request to claim additional
// seniority from old peer keys for an existing prover.
func (w *WorkerAllocator) submitSeniorityMerge(
	frame *protobufs.GlobalFrame,
	helpers []*global.SeniorityMerge,
	seniority uint64,
	peerIds []string,
) error {
	if len(helpers) == 0 {
		return errors.New("no merge helpers available")
	}

	seniorityMerge, err := global.NewProverSeniorityMerge(
		frame.Header.FrameNumber,
		helpers,
		w.engine.hypergraph,
		schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		w.engine.keyManager,
	)
	if err != nil {
		w.engine.logger.Error("could not construct seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	err = seniorityMerge.Prove(frame.Header.FrameNumber)
	if err != nil {
		w.engine.logger.Error("could not prove seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			{
				Request: &protobufs.MessageRequest_SeniorityMerge{
					SeniorityMerge: seniorityMerge.ToProtobuf(),
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	}

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not encode seniority merge bundle", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	err = w.engine.publishProverMessage(msg)
	if err != nil {
		w.engine.logger.Error("could not publish seniority merge", zap.Error(err))
		return errors.Wrap(err, "submit seniority merge")
	}

	w.engine.logger.Info(
		"submitted seniority merge request",
		zap.Uint64("seniority", seniority),
		zap.Strings("peer_ids", peerIds),
	)

	return nil
}

func (w *WorkerAllocator) DecideWorkerJoins(
	reject [][]byte,
	confirm [][]byte,
) error {
	frame := w.engine.GetFrame()
	if frame == nil {
		w.engine.logger.Debug("cannot decide, no frame")
		return errors.New("not ready")
	}

	_, err := w.engine.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		w.engine.logger.Debug("cannot decide, no signer key")
		return errors.Wrap(err, "decide worker joins")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{},
	}

	if len(reject) != 0 {
		rejectMessage, err := global.NewProverReject(
			reject,
			frame.Header.FrameNumber,
			w.engine.keyManager,
			w.engine.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		)
		if err != nil {
			w.engine.logger.Error("could not construct reject", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		err = rejectMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			w.engine.logger.Error("could not construct reject", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Reject{
				Reject: rejectMessage.ToProtobuf(),
			},
		})
	} else if len(confirm) != 0 {
		confirmMessage, err := global.NewProverConfirm(
			confirm,
			frame.Header.FrameNumber,
			w.engine.keyManager,
			w.engine.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		)
		if err != nil {
			w.engine.logger.Error("could not construct confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		err = confirmMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			w.engine.logger.Error("could not construct confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker joins")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Confirm{
				Confirm: confirmMessage.ToProtobuf(),
			},
		})
	}

	bundle.Timestamp = time.Now().UnixMilli()

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not construct decision", zap.Error(err))
		return errors.Wrap(err, "decide worker joins")
	}

	err = w.engine.publishProverMessage(msg)
	if err != nil {
		w.engine.logger.Error("could not construct join decisions", zap.Error(err))
		return errors.Wrap(err, "decide worker joins")
	}

	w.engine.logger.Debug("submitted join decisions")

	return nil
}

func (w *WorkerAllocator) ProposeWorkerLeave(
	filters [][]byte,
) error {
	frame := w.engine.GetFrame()
	if frame == nil {
		w.engine.logger.Debug("cannot propose leave, no frame")
		return errors.New("not ready")
	}

	_, err := w.engine.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		w.engine.logger.Debug("cannot propose leave, no signer key")
		return errors.Wrap(err, "propose worker leave")
	}

	leave, err := global.NewProverLeave(
		filters,
		frame.Header.FrameNumber,
		w.engine.keyManager,
		w.engine.hypergraph,
		schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
	)
	if err != nil {
		w.engine.logger.Error("could not construct leave", zap.Error(err))
		return errors.Wrap(err, "propose worker leave")
	}

	err = leave.Prove(frame.Header.FrameNumber)
	if err != nil {
		w.engine.logger.Error("could not prove leave", zap.Error(err))
		return errors.Wrap(err, "propose worker leave")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			{
				Request: &protobufs.MessageRequest_Leave{
					Leave: leave.ToProtobuf(),
				},
			},
		},
		Timestamp: time.Now().UnixMilli(),
	}

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not serialize leave", zap.Error(err))
		return errors.Wrap(err, "propose worker leave")
	}

	err = w.engine.publishProverMessage(msg)
	if err != nil {
		w.engine.logger.Error("could not publish leave", zap.Error(err))
		return errors.Wrap(err, "propose worker leave")
	}

	w.engine.logger.Info(
		"submitted leave request",
		zap.Int("filters", len(filters)),
	)

	return nil
}

func (w *WorkerAllocator) DecideWorkerLeaves(
	reject [][]byte,
	confirm [][]byte,
) error {
	frame := w.engine.GetFrame()
	if frame == nil {
		w.engine.logger.Debug("cannot decide leaves, no frame")
		return errors.New("not ready")
	}

	_, err := w.engine.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		w.engine.logger.Debug("cannot decide leaves, no signer key")
		return errors.Wrap(err, "decide worker leaves")
	}

	bundle := &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{},
	}

	if len(reject) != 0 {
		rejectMessage, err := global.NewProverReject(
			reject,
			frame.Header.FrameNumber,
			w.engine.keyManager,
			w.engine.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		)
		if err != nil {
			w.engine.logger.Error("could not construct leave reject", zap.Error(err))
			return errors.Wrap(err, "decide worker leaves")
		}

		err = rejectMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			w.engine.logger.Error("could not prove leave reject", zap.Error(err))
			return errors.Wrap(err, "decide worker leaves")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Reject{
				Reject: rejectMessage.ToProtobuf(),
			},
		})
	}

	if len(confirm) != 0 {
		confirmMessage, err := global.NewProverConfirm(
			confirm,
			frame.Header.FrameNumber,
			w.engine.keyManager,
			w.engine.hypergraph,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, w.engine.inclusionProver),
		)
		if err != nil {
			w.engine.logger.Error("could not construct leave confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker leaves")
		}

		err = confirmMessage.Prove(frame.Header.FrameNumber)
		if err != nil {
			w.engine.logger.Error("could not prove leave confirm", zap.Error(err))
			return errors.Wrap(err, "decide worker leaves")
		}

		bundle.Requests = append(bundle.Requests, &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_Confirm{
				Confirm: confirmMessage.ToProtobuf(),
			},
		})
	}

	bundle.Timestamp = time.Now().UnixMilli()

	msg, err := bundle.ToCanonicalBytes()
	if err != nil {
		w.engine.logger.Error("could not serialize leave decisions", zap.Error(err))
		return errors.Wrap(err, "decide worker leaves")
	}

	err = w.engine.publishProverMessage(msg)
	if err != nil {
		w.engine.logger.Error("could not publish leave decisions", zap.Error(err))
		return errors.Wrap(err, "decide worker leaves")
	}

	w.engine.logger.Debug("submitted leave decisions")

	return nil
}
