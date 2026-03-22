package global

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

func (e *GlobalConsensusEngine) eventDistributorLoop(
	ctx lifecycle.SignalerContext,
) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			ctx.Throw(errors.Errorf("fatal unhandled error encountered: %v", r))
		}
	}()

	e.logger.Debug("starting event distributor")

	// Subscribe to events from the event distributor
	eventCh := e.eventDistributor.Subscribe("global")
	defer e.eventDistributor.Unsubscribe("global")

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.quit:
			return
		case event, ok := <-eventCh:
			if !ok {
				e.logger.Error("event channel closed unexpectedly")
				return
			}

			e.logger.Debug("received event", zap.Int("event_type", int(event.Type)))

			// Handle the event based on its type
			switch event.Type {
			case typesconsensus.ControlEventGlobalNewHead:
				timer := prometheus.NewTimer(globalCoordinationDuration)

				// New global frame has been selected as the head by the time reel
				if data, ok := event.Data.(*consensustime.GlobalEvent); ok &&
					data.Frame != nil {
					e.lastObservedFrame.Store(data.Frame.Header.FrameNumber)
					e.logger.Info(
						"received new global head event",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					e.flushDeferredGlobalMessages(data.Frame.GetRank() + 1)

					// Check shard coverage asynchronously to avoid blocking event processing
					e.triggerCoverageCheckAsync(
						data.Frame.Header.FrameNumber,
						data.Frame.Header.Prover,
					)

					// Update global coordination metrics
					globalCoordinationTotal.Inc()
					timer.ObserveDuration()

					_, err := e.signerRegistry.GetIdentityKey(e.GetPeerInfo().PeerId)
					if err != nil && !e.hasSentKeyBundle {
						e.hasSentKeyBundle = true
						e.publishKeyRegistry()
					}

					if e.proposer != nil && !e.config.Engine.ArchiveMode {
						workers, err := e.workerManager.RangeWorkers()
						if err != nil {
							e.logger.Error("could not retrieve workers", zap.Error(err))
						} else {
							if len(workers) == 0 {
								e.logger.Error("no workers detected for allocation")
							}
							allAllocated := true
							needsProposals := false
							for _, w := range workers {
								if w.ManuallyManaged {
									continue
								}
								allAllocated = allAllocated && w.Allocated
								if len(w.Filter) == 0 {
									needsProposals = true
								}
							}
							if needsProposals || !allAllocated {
								e.evaluateForProposals(ctx, data, needsProposals)
							} else {
								self, effectiveSeniority := e.allocationContext()
								// Still reconcile allocations even when all workers appear
								// allocated - this clears stale filters that no longer match
								// prover allocations in the registry.
								e.reconcileWorkerAllocations(data.Frame.Header.FrameNumber, self)
								e.checkExcessPendingJoins(self, data.Frame.Header.FrameNumber)
								e.checkAndSubmitSeniorityMerge(self, data.Frame.Header.FrameNumber)
								e.logAllocationStatusOnly(ctx, data, self, effectiveSeniority)
							}
						}
					}
				}

			case typesconsensus.ControlEventGlobalEquivocation:
				// Handle equivocation by constructing and publishing a ProverKick
				// message
				if data, ok := event.Data.(*consensustime.GlobalEvent); ok &&
					data.Frame != nil && data.OldHead != nil {
					e.logger.Warn(
						"received equivocating frame",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					// The equivocating prover is the one who signed the new frame
					if data.Frame.Header != nil &&
						data.Frame.Header.PublicKeySignatureBls48581 != nil &&
						data.Frame.Header.PublicKeySignatureBls48581.PublicKey != nil {

						kickedProverPublicKey :=
							data.Frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue

						// Serialize both conflicting frame headers
						conflictingFrame1, err := data.OldHead.Header.ToCanonicalBytes()
						if err != nil {
							e.logger.Error(
								"failed to marshal old frame header",
								zap.Error(err),
							)
							continue
						}

						conflictingFrame2, err := data.Frame.Header.ToCanonicalBytes()
						if err != nil {
							e.logger.Error(
								"failed to marshal new frame header",
								zap.Error(err),
							)
							continue
						}

						// Create the ProverKick message using the intrinsic struct
						proverKick, err := globalintrinsics.NewProverKick(
							data.Frame.Header.FrameNumber,
							kickedProverPublicKey,
							conflictingFrame1,
							conflictingFrame2,
							e.blsConstructor,
							e.frameProver,
							e.hypergraph,
							schema.NewRDFMultiprover(
								&schema.TurtleRDFParser{},
								e.inclusionProver,
							),
							e.proverRegistry,
							e.clockStore,
						)
						if err != nil {
							e.logger.Error(
								"failed to construct prover kick",
								zap.Error(err),
							)
							continue
						}

						err = proverKick.Prove(data.Frame.Header.FrameNumber)
						if err != nil {
							e.logger.Error(
								"failed to prove prover kick",
								zap.Error(err),
							)
							continue
						}

						// Serialize the ProverKick to the request form
						kickBytes, err := proverKick.ToRequestBytes()
						if err != nil {
							e.logger.Error(
								"failed to serialize prover kick",
								zap.Error(err),
							)
							continue
						}

						// Publish the kick message
						if err := e.publishProverMessage(kickBytes); err != nil {
							e.logger.Error("failed to publish prover kick", zap.Error(err))
						} else {
							e.logger.Info(
								"published prover kick for equivocation",
								zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
								zap.String(
									"kicked_prover",
									hex.EncodeToString(kickedProverPublicKey),
								),
							)
						}
					}
				}

			case typesconsensus.ControlEventCoverageHalt:
				data, ok := event.Data.(*typesconsensus.CoverageEventData)
				if ok && data.Message != "" {
					e.logger.Error(data.Message)
					e.halt()
					go func() {
						for {
							select {
							case <-ctx.Done():
								return
							case <-time.After(10 * time.Second):
								e.logger.Error(
									"full halt detected, leaving system in halted state until recovery",
								)
							}
						}
					}()
				}

			case typesconsensus.ControlEventHalt:
				data, ok := event.Data.(*typesconsensus.ErrorEventData)
				if ok && data.Error != nil {
					e.logger.Error(
						"full halt detected, leaving system in halted state",
						zap.Error(data.Error),
					)
					e.halt()
					go func() {
						for {
							select {
							case <-ctx.Done():
								return
							case <-time.After(10 * time.Second):
								e.logger.Error(
									"full halt detected, leaving system in halted state",
									zap.Error(data.Error),
								)
							}
						}
					}()
				}

			case typesconsensus.ControlEventShardSplitEligible:
				if data, ok := event.Data.(*typesconsensus.ShardSplitEventData); ok {
					e.handleShardSplitEvent(data)
				}

			case typesconsensus.ControlEventShardMergeEligible:
				if data, ok := event.Data.(*typesconsensus.BulkShardMergeEventData); ok {
					e.handleShardMergeEvent(data)
				}

			default:
				e.logger.Debug(
					"received unhandled event type",
					zap.Int("event_type", int(event.Type)),
				)
			}
		}
	}
}

const pendingFilterGraceFrames = 720

// proposalTimeoutFrames is the number of frames to wait for a join proposal
// to appear in the registry before clearing the worker's filter. If a proposal is
// submitted but never lands (e.g., network issues, not included in frame),
// we should reset the filter so the worker can try again.
const proposalTimeoutFrames = 10

func (e *GlobalConsensusEngine) emitCoverageEvent(
	eventType typesconsensus.ControlEventType,
	data *typesconsensus.CoverageEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: eventType,
		Data: data,
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info(
		"emitted coverage event",
		zap.String("type", fmt.Sprintf("%d", eventType)),
		zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
		zap.Int("prover_count", data.ProverCount),
		zap.String("message", data.Message),
	)
}

func (e *GlobalConsensusEngine) emitBulkMergeEvent(
	mergeGroups []typesconsensus.ShardMergeEventData,
	frameProver []byte,
) {
	if len(mergeGroups) == 0 {
		return
	}

	// Combine all merge groups into a single bulk event
	data := &typesconsensus.BulkShardMergeEventData{
		MergeGroups: mergeGroups,
		FrameProver: frameProver,
	}

	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventShardMergeEligible,
		Data: data,
	}

	go e.eventDistributor.Publish(event)

	totalShards := 0
	totalProvers := 0
	for _, group := range mergeGroups {
		totalShards += len(group.ShardAddresses)
		totalProvers += group.TotalProvers
	}

	e.logger.Info(
		"emitted bulk merge eligible event",
		zap.Int("merge_groups", len(mergeGroups)),
		zap.Int("total_shards", totalShards),
		zap.Int("total_provers", totalProvers),
	)
}

func (e *GlobalConsensusEngine) emitSplitEvent(
	data *typesconsensus.ShardSplitEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventShardSplitEligible,
		Data: data,
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info(
		"emitted split eligible event",
		zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
		zap.Int("proposed_shard_count", len(data.ProposedShards)),
		zap.Int("prover_count", data.ProverCount),
		zap.Uint64("attested_storage", data.AttestedStorage),
	)
}

func (e *GlobalConsensusEngine) emitAlertEvent(alertMessage string) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventHalt,
		Data: &typesconsensus.ErrorEventData{
			Error: errors.New(alertMessage),
		},
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info("emitted alert message")
}

const shardActionCooldownFrames = 360

func (e *GlobalConsensusEngine) handleShardSplitEvent(
	data *typesconsensus.ShardSplitEventData,
) {
	// Only the prover who produced the triggering frame should emit
	if !bytes.Equal(data.FrameProver, e.getProverAddress()) {
		return
	}

	frameNumber := e.lastObservedFrame.Load()
	if frameNumber == 0 {
		return
	}

	addrKey := string(data.ShardAddress)
	e.lastShardActionFrameMu.Lock()
	if last, ok := e.lastShardActionFrame[addrKey]; ok &&
		frameNumber-last < shardActionCooldownFrames {
		e.lastShardActionFrameMu.Unlock()
		e.logger.Debug(
			"skipping shard split, cooldown active",
			zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
			zap.Uint64("last_action_frame", last),
			zap.Uint64("current_frame", frameNumber),
		)
		return
	}
	e.lastShardActionFrame[addrKey] = frameNumber
	e.lastShardActionFrameMu.Unlock()

	op := globalintrinsics.NewShardSplitOp(
		data.ShardAddress,
		data.ProposedShards,
		e.keyManager,
		e.shardsStore,
		e.proverRegistry,
	)

	if err := op.Prove(frameNumber); err != nil {
		e.logger.Error(
			"failed to prove shard split",
			zap.Error(err),
		)
		return
	}

	splitBytes, err := op.ToRequestBytes()
	if err != nil {
		e.logger.Error(
			"failed to serialize shard split",
			zap.Error(err),
		)
		return
	}

	if err := e.publishProverMessage(splitBytes); err != nil {
		e.logger.Error("failed to publish shard split", zap.Error(err))
	} else {
		e.logger.Info(
			"published shard split",
			zap.String("shard_address", hex.EncodeToString(data.ShardAddress)),
			zap.Int("proposed_shards", len(data.ProposedShards)),
			zap.Uint64("frame_number", frameNumber),
		)
	}
}

func (e *GlobalConsensusEngine) handleShardMergeEvent(
	data *typesconsensus.BulkShardMergeEventData,
) {
	// Only the prover who produced the triggering frame should emit
	if !bytes.Equal(data.FrameProver, e.getProverAddress()) {
		return
	}

	frameNumber := e.lastObservedFrame.Load()
	if frameNumber == 0 {
		return
	}

	for _, group := range data.MergeGroups {
		if len(group.ShardAddresses) < 2 {
			continue
		}

		// Use first shard's first 32 bytes as parent address
		parentAddress := group.ShardAddresses[0][:32]

		// Check cooldown for the parent address
		parentKey := string(parentAddress)
		e.lastShardActionFrameMu.Lock()
		if last, ok := e.lastShardActionFrame[parentKey]; ok &&
			frameNumber-last < shardActionCooldownFrames {
			e.lastShardActionFrameMu.Unlock()
			e.logger.Debug(
				"skipping shard merge, cooldown active",
				zap.String("parent_address", hex.EncodeToString(parentAddress)),
				zap.Uint64("last_action_frame", last),
				zap.Uint64("current_frame", frameNumber),
			)
			continue
		}
		e.lastShardActionFrame[parentKey] = frameNumber
		e.lastShardActionFrameMu.Unlock()

		op := globalintrinsics.NewShardMergeOp(
			group.ShardAddresses,
			parentAddress,
			e.keyManager,
			e.shardsStore,
			e.proverRegistry,
		)

		if err := op.Prove(frameNumber); err != nil {
			e.logger.Error(
				"failed to prove shard merge",
				zap.Error(err),
			)
			continue
		}

		mergeBytes, err := op.ToRequestBytes()
		if err != nil {
			e.logger.Error(
				"failed to serialize shard merge",
				zap.Error(err),
			)
			continue
		}

		if err := e.publishProverMessage(mergeBytes); err != nil {
			e.logger.Error("failed to publish shard merge", zap.Error(err))
		} else {
			e.logger.Info(
				"published shard merge",
				zap.String("parent_address", hex.EncodeToString(parentAddress)),
				zap.Int("shard_count", len(group.ShardAddresses)),
				zap.Uint64("frame_number", frameNumber),
			)
		}
	}
}

func (e *GlobalConsensusEngine) estimateSeniorityFromConfig() uint64 {
	peerIds := []string{}
	peerIds = append(peerIds, peer.ID(e.pubsub.GetPeerID()).String())
	if len(e.config.Engine.MultisigProverEnrollmentPaths) != 0 {
		for _, conf := range e.config.Engine.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				e.logger.Error("could not load config", zap.Error(err))
				continue
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				e.logger.Error("could not decode peer key", zap.Error(err))
				continue
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				e.logger.Error("could not unmarshal peer key", zap.Error(err))
				continue
			}

			pub := privKey.GetPublic()
			id, err := peer.IDFromPublicKey(pub)
			if err != nil {
				e.logger.Error("could not unmarshal peerid", zap.Error(err))
				continue
			}

			peerIds = append(peerIds, id.String())
		}
	}
	seniorityBI := compat.GetAggregatedSeniority(peerIds)
	return seniorityBI.Uint64()
}

func (e *GlobalConsensusEngine) evaluateForProposals(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	allowProposals bool,
) {
	self, effectiveSeniority := e.allocationContext()
	e.reconcileWorkerAllocations(data.Frame.Header.FrameNumber, self)

	// Re-check after reconciliation — stale filters may have been cleared,
	// making workers available for new proposals.
	if !allowProposals {
		workers, err := e.workerManager.RangeWorkers()
		if err == nil {
			for _, w := range workers {
				if w != nil && len(w.Filter) == 0 && !w.ManuallyManaged {
					allowProposals = true
					break
				}
			}
		}
	}

	e.checkExcessPendingJoins(self, data.Frame.Header.FrameNumber)
	canPropose, skipReason := e.joinProposalReady(data.Frame.Header.FrameNumber)

	snapshot, ok := e.collectAllocationSnapshot(
		ctx,
		data,
		self,
		effectiveSeniority,
	)
	if !ok {
		return
	}

	e.logAllocationStatus(snapshot)
	pendingFilters := snapshot.pendingFilters
	proposalDescriptors := snapshot.proposalDescriptors
	decideDescriptors := snapshot.decideDescriptors
	worldBytes := snapshot.worldBytes

	// Filter out manually-managed workers from auto-management decisions.
	if mmFilters := e.workerManager.ManuallyManagedFilters(); len(mmFilters) > 0 {
		pendingFilters = filterByteSlices(pendingFilters, mmFilters)
		snapshot.leaveProposalCandidates = filterDescriptors(snapshot.leaveProposalCandidates, mmFilters)
		snapshot.pendingLeaveFilters = filterByteSlices(snapshot.pendingLeaveFilters, mmFilters)
	}

	joinProposedThisCycle := false
	if len(proposalDescriptors) != 0 && allowProposals {
		if canPropose {
			proposals, err := e.proposer.PlanAndAllocate(
				uint64(data.Frame.Header.Difficulty),
				proposalDescriptors,
				100,
				worldBytes,
				data.Frame.Header.FrameNumber,
			)
			if err != nil {
				e.logger.Error("could not plan shard allocations", zap.Error(err))
			} else {
				if len(proposals) > 0 {
					joinProposedThisCycle = true
					e.lastJoinAttemptFrame.Store(data.Frame.Header.FrameNumber)
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
				e.logger.Info(
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
			e.logger.Info(
				"skipping join proposals",
				zap.String("reason", skipReason),
				zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
			)
		}
	} else if len(proposalDescriptors) != 0 && !allowProposals {
		e.logger.Info(
			"skipping join proposals",
			zap.String("reason", "all workers have local filters but some may not be allocated in registry"),
			zap.Int("unallocated_shards", len(proposalDescriptors)),
			zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
		)
	}

	if !joinProposedThisCycle {
		e.checkAndSubmitSeniorityMerge(self, data.Frame.Header.FrameNumber)
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
		if err := e.proposer.DecideJoins(
			uint64(data.Frame.Header.Difficulty),
			decideCandidates,
			pendingFilters,
			worldBytes,
		); err != nil {
			e.logger.Error("could not decide shard allocations", zap.Error(err))
		} else {
			e.logger.Info(
				"decided on joins",
				zap.Int("joins", len(pendingFilters)),
			)
		}
	}

	// Leave rebalancing: propose leaves for overcrowded shards
	if len(snapshot.leaveProposalCandidates) > 0 && canPropose && !joinProposedThisCycle {
		leaveFilters, err := e.proposer.PlanLeaves(
			uint64(data.Frame.Header.Difficulty),
			snapshot.leaveProposalCandidates,
			proposalDescriptors,
			worldBytes,
		)
		if err != nil {
			e.logger.Error("could not plan leaves", zap.Error(err))
		} else if len(leaveFilters) > 0 {
			e.lastJoinAttemptFrame.Store(data.Frame.Header.FrameNumber)
			e.logger.Info(
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
		if err := e.proposer.DecideLeaves(
			uint64(data.Frame.Header.Difficulty),
			leaveDecideCandidates,
			snapshot.pendingLeaveFilters,
			worldBytes,
		); err != nil {
			e.logger.Error("could not decide leaves", zap.Error(err))
		} else {
			e.logger.Info(
				"decided on leaves",
				zap.Int("leaves", len(snapshot.pendingLeaveFilters)),
			)
		}
	}
}

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

func (e *GlobalConsensusEngine) reconcileWorkerAllocations(
	frameNumber uint64,
	self *typesconsensus.ProverInfo,
) {
	if e.workerManager == nil {
		return
	}

	workers, err := e.workerManager.RangeWorkers()
	if err != nil {
		e.logger.Warn("could not load workers for reconciliation", zap.Error(err))
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
					e.logger.Warn(
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
				if err := e.workerManager.RegisterWorker(worker); err != nil {
					e.logger.Warn(
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
			e.logger.Info(
				"clearing rejected worker filter",
				zap.Uint("core_id", worker.CoreId),
				zap.String("filter", hex.EncodeToString(worker.Filter)),
			)
			worker.Filter = nil
			worker.Allocated = false
			worker.PendingFilterFrame = 0
			if err := e.workerManager.RegisterWorker(worker); err != nil {
				e.logger.Warn(
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
			e.logger.Warn(
				"worker has orphaned filter with no prover info available",
				zap.Uint("core_id", worker.CoreId),
				zap.String("filter", hex.EncodeToString(worker.Filter)),
				zap.Bool("allocated", worker.Allocated),
			)
			// Still clear it - if we can't verify the allocation, assume it's stale
		}

		e.logger.Info(
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
		if err := e.workerManager.RegisterWorker(worker); err != nil {
			e.logger.Warn(
				"failed to clear stale worker filter",
				zap.Uint("core_id", worker.CoreId),
				zap.Error(err),
			)
		}
	}
}

func (e *GlobalConsensusEngine) collectAllocationSnapshot(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	self *typesconsensus.ProverInfo,
	_ uint64, // effectiveSeniority – no longer used for ring prediction
) (*allocationSnapshot, bool) {
	appShards, err := e.shardsStore.RangeAppShards()
	if err != nil {
		e.logger.Error("could not obtain app shard info", zap.Error(err))
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

	registry, err := e.keyStore.GetKeyRegistryByProver(data.Frame.Header.Prover)
	if err != nil {
		e.logger.Info(
			"awaiting key registry info for prover",
			zap.String(
				"prover_address",
				hex.EncodeToString(data.Frame.Header.Prover),
			),
		)
		return nil, false
	}

	if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
		e.logger.Info("key registry info missing identity of prover")
		return nil, false
	}

	pub, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		e.logger.Warn("error unmarshaling identity key", zap.Error(err))
		return nil, false
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		e.logger.Warn("error deriving peer id", zap.Error(err))
		return nil, false
	}

	info := e.peerInfoManager.GetPeerInfo([]byte(peerId))
	if info == nil {
		e.logger.Info(
			"no peer info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil, false
	}

	if len(info.Reachability) == 0 {
		e.logger.Info(
			"no reachability info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil, false
	}

	var client protobufs.GlobalServiceClient = nil
	if len(info.Reachability[0].StreamMultiaddrs) > 0 {
		s := info.Reachability[0].StreamMultiaddrs[0]
		creds, err := p2p.NewPeerAuthenticator(
			e.logger,
			e.config.P2P,
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
			e.logger.Debug(
				"could not establish direct channel, trying next multiaddr",
				zap.String("peer", peer.ID(peerId).String()),
				zap.String("multiaddr", ma.String()),
				zap.Error(err),
			)
			return nil, false
		}
		defer func() {
			if err := cc.Close(); err != nil {
				e.logger.Error("error while closing connection", zap.Error(err))
			}
		}()

		client = protobufs.NewGlobalServiceClient(cc)
	}

	if client == nil {
		e.logger.Debug("could not get app shards from prover")
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
			resp, err = e.getAppShardsFromProver(client, shardKey)
			if err == nil {
				break
			}
			e.logger.Debug(
				"retrying app shard retrieval",
				zap.Int("attempt", attempt+1),
				zap.Error(err),
			)
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
		if err != nil {
			e.logger.Debug("could not get app shards from prover after retries", zap.Error(err))
			return nil, false
		}

		for _, shard := range resp.Info {
			shardDivisions++
			worldBytes = worldBytes.Add(worldBytes, new(big.Int).SetBytes(shard.Size))
			bp := slices.Clone(shardInfo.L2)
			for _, p := range shard.Prefix {
				bp = append(bp, byte(p))
			}

			prs, err := e.proverRegistry.GetProvers(bp)
			if err != nil {
				e.logger.Error("failed to get provers", zap.Error(err))
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
						if allocation.Status == typesconsensus.ProverStatusLeaving {
							shardsLeaving++
							// Check if in the 360-720 decision window
							if allocation.LeaveFrameNumber+360 <= data.Frame.Header.FrameNumber &&
								data.Frame.Header.FrameNumber <= allocation.LeaveFrameNumber+pendingFilterGraceFrames {
								isPendingLeave = true
							}
						}
						if allocation.Status == typesconsensus.ProverStatusPaused {
							shardsPaused++
						}
						if e.config.P2P.Network != 0 ||
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
			// candidate list. A new joiner lands at the end, so predicted ring
			// = floor(totalActiveJoining / 8).
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

			// For shards this prover is already on, use the current count.
			// For unallocated shards, add 1 (self would be a new joiner).
			currentRing := uint8(totalActiveJoining / 8)
			joinerRing := uint8((totalActiveJoining + 1) / 8)

			if allocated && pending {
				pendingFilters = append(pendingFilters, bp)
			}
			if !allocated {
				proposalDescriptors = append(
					proposalDescriptors,
					provers.ShardDescriptor{
						Filter: bp,
						Size:   size.Uint64(),
						Ring:   joinerRing,
						Shards: shard.DataShards,
					},
				)
			}
			if isActiveAllocation {
				leaveProposalCandidates = append(
					leaveProposalCandidates,
					provers.ShardDescriptor{
						Filter: bp,
						Size:   size.Uint64(),
						Ring:   currentRing,
						Shards: shard.DataShards,
					},
				)
			}
			if isPendingLeave {
				pendingLeaveFilters = append(pendingLeaveFilters, bp)
			}
			decideDescriptors = append(
				decideDescriptors,
				provers.ShardDescriptor{
					Filter: bp,
					Size:   size.Uint64(),
					Ring:   joinerRing,
					Shards: shard.DataShards,
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

func (e *GlobalConsensusEngine) logAllocationStatus(
	snapshot *allocationSnapshot,
) {
	if snapshot == nil {
		return
	}

	e.logger.Info(
		"status for allocations",
		snapshot.statusFields()...,
	)

	e.logger.Debug(
		"proposal evaluation snapshot",
		snapshot.proposalSnapshotFields()...,
	)
}

func (e *GlobalConsensusEngine) logAllocationStatusOnly(
	ctx context.Context,
	data *consensustime.GlobalEvent,
	self *typesconsensus.ProverInfo,
	effectiveSeniority uint64,
) {
	snapshot, ok := e.collectAllocationSnapshot(
		ctx,
		data,
		self,
		effectiveSeniority,
	)
	if !ok || snapshot == nil {
		e.logger.Info(
			"all workers already allocated or pending; skipping proposal cycle",
		)
		return
	}

	e.logger.Info(
		"all workers already allocated or pending; skipping proposal cycle",
		snapshot.statusFields()...,
	)
	e.logAllocationStatus(snapshot)
}

// checkAndSubmitSeniorityMerge submits a seniority merge if the prover exists
// with incorrect seniority and cooldowns have elapsed. This is called both from
// evaluateForProposals (when no join was proposed) and from the "all workers
// allocated" path, ensuring seniority is corrected regardless of allocation state.
func (e *GlobalConsensusEngine) checkAndSubmitSeniorityMerge(
	self *typesconsensus.ProverInfo,
	frameNumber uint64,
) {
	if self == nil {
		return
	}

	mergeSeniority := e.estimateSeniorityFromConfig()
	if mergeSeniority <= self.Seniority {
		return
	}

	lastJoin := e.lastJoinAttemptFrame.Load()
	lastMerge := e.lastSeniorityMergeFrame.Load()
	joinCooldownOk := lastJoin == 0 || frameNumber-lastJoin >= 10
	mergeCooldownOk := lastMerge == 0 || frameNumber-lastMerge >= 10

	if joinCooldownOk && mergeCooldownOk {
		frame := e.GetFrame()
		if frame != nil {
			helpers, peerIds := e.buildMergeHelpers()
			err := e.submitSeniorityMerge(
				frame, helpers, mergeSeniority, peerIds,
			)
			if err != nil {
				e.logger.Error(
					"could not submit seniority merge",
					zap.Error(err),
				)
			} else {
				e.lastSeniorityMergeFrame.Store(frameNumber)
			}
		}
	} else {
		e.logger.Debug(
			"seniority merge deferred due to cooldown",
			zap.Uint64("merge_seniority", mergeSeniority),
			zap.Uint64("existing_seniority", self.Seniority),
			zap.Uint64("last_join_frame", lastJoin),
			zap.Uint64("last_merge_frame", lastMerge),
			zap.Uint64("current_frame", frameNumber),
		)
	}
}

func (e *GlobalConsensusEngine) allocationContext() (
	*typesconsensus.ProverInfo,
	uint64,
) {
	self, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	if err != nil || self == nil {
		return nil, e.estimateSeniorityFromConfig()
	}
	return self, self.Seniority
}

func (e *GlobalConsensusEngine) checkExcessPendingJoins(
	self *typesconsensus.ProverInfo,
	frameNumber uint64,
) {
	excessFilters := e.selectExcessPendingFilters(self, frameNumber)
	if len(excessFilters) != 0 {
		e.logger.Debug(
			"identified excess pending joins",
			zap.Int("excess_count", len(excessFilters)),
			zap.Uint64("frame_number", frameNumber),
		)
		e.rejectExcessPending(excessFilters, frameNumber)
		return
	}

	e.logger.Debug(
		"no excess pending joins detected",
		zap.Uint64("frame_number", frameNumber),
	)
}

func (e *GlobalConsensusEngine) publishKeyRegistry() {
	vk, err := e.keyManager.GetAgreementKey("q-view-key")
	if err != nil {
		vk, err = e.keyManager.CreateAgreementKey(
			"q-view-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			e.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	sk, err := e.keyManager.GetAgreementKey("q-spend-key")
	if err != nil {
		sk, err = e.keyManager.CreateAgreementKey(
			"q-spend-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			e.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	pk, err := e.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		pk, _, err = e.keyManager.CreateSigningKey(
			"q-prover-key",
			crypto.KeyTypeBLS48581G1,
		)
		if err != nil {
			e.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	onion, err := e.keyManager.GetAgreementKey("q-onion-key")
	if err != nil {
		onion, err = e.keyManager.CreateAgreementKey(
			"q-onion-key",
			crypto.KeyTypeX448,
		)
		if err != nil {
			e.logger.Error("could not publish key registry", zap.Error(err))
			return
		}
	}

	sig, err := e.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			pk.Public().([]byte),
		),
	)
	if err != nil {
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigp, err := pk.SignWithDomain(
		e.pubsub.GetPublicKey(),
		[]byte("KEY_REGISTRY"),
	)
	if err != nil {
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigvk, err := e.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			vk.Public(),
		),
	)
	if err != nil {
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigsk, err := e.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			sk.Public(),
		),
	)
	if err != nil {
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	sigonion, err := e.pubsub.SignMessage(
		slices.Concat(
			[]byte("KEY_REGISTRY"),
			onion.Public(),
		),
	)
	if err != nil {
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	registry := &protobufs.KeyRegistry{
		LastUpdated: uint64(time.Now().UnixMilli()),
		IdentityKey: &protobufs.Ed448PublicKey{
			KeyValue: e.pubsub.GetPublicKey(),
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
					ParentKeyAddress: e.pubsub.GetPeerID(),
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
					ParentKeyAddress: e.pubsub.GetPeerID(),
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
					ParentKeyAddress: e.pubsub.GetPeerID(),
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
		e.logger.Error("could not publish key registry", zap.Error(err))
		return
	}
	e.pubsub.PublishToBitmask(
		GLOBAL_PEER_INFO_BITMASK,
		kr,
	)
}

func (e *GlobalConsensusEngine) getAppShardsFromProver(
	client protobufs.GlobalServiceClient,
	shardKey []byte,
) (
	*protobufs.GetAppShardsResponse,
	error,
) {
	getCtx, cancelGet := context.WithTimeout(
		context.Background(),
		e.config.Engine.SyncTimeout,
	)
	response, err := client.GetAppShards(
		getCtx,
		&protobufs.GetAppShardsRequest{
			ShardKey: shardKey, // buildutils:allow-slice-alias slice is static
		},
		// The message size limits are swapped because the server is the one
		// sending the data.
		grpc.MaxCallRecvMsgSize(
			e.config.Engine.SyncMessageLimits.MaxSendMsgSize,
		),
		grpc.MaxCallSendMsgSize(
			e.config.Engine.SyncMessageLimits.MaxRecvMsgSize,
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
