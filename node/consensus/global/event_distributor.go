package global

import (
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
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
					e.coverageMonitor.triggerCoverageCheckAsync(
						data.Frame.Header.FrameNumber,
						data.Frame.Header.Prover,
					)

					// Update global coordination metrics
					globalCoordinationTotal.Inc()
					timer.ObserveDuration()

					_, err := e.signerRegistry.GetIdentityKey(e.GetPeerInfo().PeerId)
					if err != nil && !e.hasSentKeyBundle {
						e.hasSentKeyBundle = true
						e.workerAllocator.publishKeyRegistry()
					}

					if e.workerAllocator.proposer != nil && !e.config.Engine.ArchiveMode {
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
								e.workerAllocator.evaluateForProposals(ctx, data, needsProposals)
							} else {
								self, effectiveSeniority := e.workerAllocator.allocationContext()
								// Still reconcile allocations even when all workers appear
								// allocated - this clears stale filters that no longer match
								// prover allocations in the registry.
								e.workerAllocator.reconcileWorkerAllocations(data.Frame.Header.FrameNumber, self)
								e.workerAllocator.checkExcessPendingJoins(self, data.Frame.Header.FrameNumber)
								e.workerAllocator.checkAndSubmitSeniorityMerge(self, data.Frame.Header.FrameNumber)
								e.workerAllocator.logAllocationStatusOnly(ctx, data, self, effectiveSeniority)
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
					e.coverageMonitor.handleShardSplitEvent(data)
				}

			case typesconsensus.ControlEventShardMergeEligible:
				if data, ok := event.Data.(*typesconsensus.BulkShardMergeEventData); ok {
					e.coverageMonitor.handleShardMergeEvent(data)
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

// filterByteSlices, filterDescriptors, evaluateForProposals,
// estimateSeniorityFromConfig, reconcileWorkerAllocations,
// collectAllocationSnapshot, logAllocationStatus, logAllocationStatusOnly,
// checkAndSubmitSeniorityMerge, allocationContext, checkExcessPendingJoins,
// publishKeyRegistry, getAppShardsFromProver, and the allocationSnapshot type
// have been moved to worker_allocator.go.
