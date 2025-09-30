package global

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

func (e *GlobalConsensusEngine) eventDistributorLoop() {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			if e.cancel != nil {
				e.cancel()
			}
			e.quit <- struct{}{}
		}
	}()
	defer e.wg.Done()

	// Subscribe to events from the event distributor
	eventCh := e.eventDistributor.Subscribe("global")
	defer e.eventDistributor.Unsubscribe("global")

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.quit:
			return
		case event, ok := <-eventCh:
			if !ok {
				e.logger.Error("event channel closed unexpectedly")
				return
			}

			// Handle the event based on its type
			switch event.Type {
			case typesconsensus.ControlEventGlobalNewHead:
				timer := prometheus.NewTimer(globalCoordinationDuration)

				// New global frame has been selected as the head by the time reel
				if data, ok := event.Data.(*consensustime.GlobalEvent); ok &&
					data.Frame != nil {
					e.logger.Debug(
						"received new global head event",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					// Check shard coverage
					if err := e.checkShardCoverage(); err != nil {
						e.logger.Error("failed to check shard coverage", zap.Error(err))
					}

					// Update global coordination metrics
					globalCoordinationTotal.Inc()
					timer.ObserveDuration()

					_, err := e.signerRegistry.GetIdentityKey(e.GetPeerInfo().PeerId)
					if err != nil && !e.hasSentKeyBundle {
						e.hasSentKeyBundle = true
						vk, err := e.keyManager.GetAgreementKey("q-view-key")
						if err != nil {
							vk, err = e.keyManager.CreateAgreementKey(
								"q-view-key",
								crypto.KeyTypeDecaf448,
							)
							if err != nil {
								continue
							}
						}

						sk, err := e.keyManager.GetAgreementKey("q-spend-key")
						if err != nil {
							sk, err = e.keyManager.CreateAgreementKey(
								"q-spend-key",
								crypto.KeyTypeDecaf448,
							)
							if err != nil {
								continue
							}
						}

						pk, err := e.keyManager.GetSigningKey("q-prover-key")
						if err != nil {
							pk, _, err = e.keyManager.CreateSigningKey(
								"q-prover-key",
								crypto.KeyTypeBLS48581G1,
							)
							if err != nil {
								continue
							}
						}
						sig, err := e.pubsub.SignMessage(
							slices.Concat(
								[]byte("KEY_REGISTRY"),
								pk.Public().([]byte),
							),
						)
						if err != nil {
							continue
						}
						sigp, err := pk.SignWithDomain(
							e.pubsub.GetPublicKey(),
							[]byte("KEY_REGISTRY"),
						)
						if err != nil {
							continue
						}
						sigvk, err := e.pubsub.SignMessage(
							slices.Concat(
								[]byte("KEY_REGISTRY"),
								vk.Public(),
							),
						)
						if err != nil {
							continue
						}
						sigsk, err := e.pubsub.SignMessage(
							slices.Concat(
								[]byte("KEY_REGISTRY"),
								sk.Public(),
							),
						)
						if err != nil {
							continue
						}
						registry := &protobufs.KeyRegistry{
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
								"view": &protobufs.KeyCollection{
									KeyPurpose: "view",
									Keys: []*protobufs.SignedX448Key{{
										Key: &protobufs.X448PublicKey{
											KeyValue: vk.Public(),
										},
										ParentKeyAddress: e.pubsub.GetPeerID(),
										Signature: &protobufs.SignedX448Key_Ed448Signature{
											Ed448Signature: &protobufs.Ed448Signature{
												Signature: sigvk,
											},
										},
									}},
								},
								"spend": &protobufs.KeyCollection{
									KeyPurpose: "spend",
									Keys: []*protobufs.SignedX448Key{{
										Key: &protobufs.X448PublicKey{
											KeyValue: sk.Public(),
										},
										ParentKeyAddress: e.pubsub.GetPeerID(),
										Signature: &protobufs.SignedX448Key_Ed448Signature{
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
							continue
						}
						e.pubsub.PublishToBitmask(
							GLOBAL_PEER_INFO_BITMASK,
							kr,
						)
					}
					if e.proposer != nil {
						shardDescriptors := []provers.ShardDescriptor{}
						shardKeys := e.hypergraph.Commit()
						for key := range shardKeys {
							shards, err := e.shardsStore.GetAppShards(
								slices.Concat(key.L1[:], key.L2[:]),
								[]uint32{},
							)
							if err != nil {
								e.logger.Error("failed to retrieve shards", zap.Error(err))
								continue
							}

							ps, err := e.proverRegistry.GetActiveProvers(nil)
							if err != nil {
								e.logger.Error("could not find global provers", zap.Error(err))
								continue
							}

							idx := rand.Int63n(int64(len(ps)))
							e.syncProvider.hyperSyncWithProver(ps[idx].Address, key)

							for _, shard := range shards {
								path := []int{}
								bp := []byte{}
								for _, p := range shard.Path {
									path = append(path, int(p))
									bp = append(bp, byte(p))
								}

								filter := slices.Concat(key.L1[:], key.L2[:], bp)
								info, err := e.proverRegistry.GetActiveProvers(filter)
								if err != nil {
									e.logger.Error("failed to get active provers", zap.Error(err))
									continue
								}

								size := e.hypergraph.GetSize(&key, path)
								resp, err := e.hypergraph.GetChildrenForPath(
									e.ctx,
									&protobufs.GetChildrenForPathRequest{
										ShardKey: slices.Concat(key.L1[:], key.L2[:]),
										Path:     shard.Path,
									},
								)
								if err != nil {
									e.logger.Error("failed to get shard info", zap.Error(err))
									continue
								}

								if len(resp.PathSegments) == 0 {
									continue
								}

								if len(
									resp.PathSegments[len(resp.PathSegments)-1].Segments,
								) != 1 {
									continue
								}

								shardCount := uint64(0)
								if resp.PathSegments[len(resp.PathSegments)-1].Segments[0].GetBranch() != nil {
									shardCount = resp.PathSegments[len(resp.PathSegments)-1].Segments[0].GetBranch().LeafCount
								} else {
									shardCount = 1
								}

								shardDescriptors = append(
									shardDescriptors,
									provers.ShardDescriptor{
										Filter: filter,
										Size:   size.Uint64(),
										Ring:   uint8(len(info) / 8),
										Shards: shardCount,
									},
								)
							}
						}
						proposals, err := e.proposer.PlanAndAllocate(
							uint64(data.Frame.Header.Difficulty),
							shardDescriptors,
							0,
						)
						if err != nil {
							e.logger.Error("could not plan shard allocations", zap.Error(err))
						} else {
							e.logger.Info(
								"proposed joins",
								zap.Int("proposals", len(proposals)),
							)
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
						if err := e.pubsub.PublishToBitmask(
							GLOBAL_PROVER_BITMASK,
							kickBytes,
						); err != nil {
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

			case typesconsensus.ControlEventHalt:
				data, ok := event.Data.(*typesconsensus.ErrorEventData)
				if ok && data.Error != nil {
					e.logger.Error(
						"full halt detected, leaving system in halted state",
						zap.Error(data.Error),
					)
					e.halt()
					if err := e.stateMachine.Stop(); err != nil {
						e.logger.Error(
							"error occurred while halting consensus",
							zap.Error(err),
						)
					}
					go func() {
						for {
							select {
							case <-e.ctx.Done():
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

			default:
				e.logger.Debug(
					"received unhandled event type",
					zap.Int("event_type", int(event.Type)),
				)
			}
		}
	}
}

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

func (e *GlobalConsensusEngine) emitMergeEvent(
	data *typesconsensus.ShardMergeEventData,
) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventShardMergeEligible,
		Data: data,
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info(
		"emitted merge eligible event",
		zap.Int("shard_count", len(data.ShardAddresses)),
		zap.Int("total_provers", data.TotalProvers),
		zap.Uint64("attested_storage", data.AttestedStorage),
		zap.Uint64("required_storage", data.RequiredStorage),
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
