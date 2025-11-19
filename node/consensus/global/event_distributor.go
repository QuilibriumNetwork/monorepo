package global

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
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
					e.logger.Info(
						"received new global head event",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					// Check shard coverage
					if err := e.checkShardCoverage(
						data.Frame.Header.FrameNumber,
					); err != nil {
						e.logger.Error("failed to check shard coverage", zap.Error(err))
					}

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
							allocated := true
							for _, w := range workers {
								allocated = allocated && w.Allocated
							}
							if !allocated {
								e.evaluateForProposals(ctx, data)
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
) {
	self, err := e.proverRegistry.GetProverInfo(e.getProverAddress())
	var effectiveSeniority uint64
	if err != nil || self == nil {
		effectiveSeniority = e.estimateSeniorityFromConfig()
	} else {
		effectiveSeniority = self.Seniority
	}

	pendingFilters := [][]byte{}
	proposalDescriptors := []provers.ShardDescriptor{}
	decideDescriptors := []provers.ShardDescriptor{}
	appShards, err := e.shardsStore.RangeAppShards()
	if err != nil {
		e.logger.Error("could not obtain app shard info", zap.Error(err))
		return
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
		return
	}

	if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
		e.logger.Info("key registry info missing identity of prover")
		return
	}

	pub, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		e.logger.Warn("error unmarshaling identity key", zap.Error(err))
		return
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		e.logger.Warn("error deriving peer id", zap.Error(err))
		return
	}

	info := e.peerInfoManager.GetPeerInfo([]byte(peerId))
	if info == nil {
		e.logger.Info(
			"no peer info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return
	}

	if len(info.Reachability) == 0 {
		e.logger.Info(
			"no reachability info known yet",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return
	}

	var client protobufs.GlobalServiceClient = nil
	for _, s := range info.Reachability[0].StreamMultiaddrs {
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
			return
		}

		ma, err := multiaddr.StringCast(s)
		if err != nil {
			return
		}

		mga, err := mn.ToNetAddr(ma)
		if err != nil {
			return
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
			return
		}
		defer func() {
			if err := cc.Close(); err != nil {
				e.logger.Error("error while closing connection", zap.Error(err))
			}
		}()

		client = protobufs.NewGlobalServiceClient(cc)
		break
	}

	if client == nil {
		e.logger.Debug("could not get app shards from prover")
		return
	}

	for _, info := range shards {
		resp, err := e.getAppShardsFromProver(
			client,
			slices.Concat(info.L1, info.L2),
		)
		if err != nil {
			e.logger.Debug("could not get app shards from prover", zap.Error(err))
			return
		}

		for _, shard := range resp.Info {
			bp := slices.Clone(info.L2)
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
			if self != nil {
				e.logger.Debug("checking allocations")
				for _, allocation := range self.Allocations {
					e.logger.Debug(
						"checking allocation",
						zap.String(
							"filter",
							hex.EncodeToString(allocation.ConfirmationFilter),
						),
					)
					if bytes.Equal(allocation.ConfirmationFilter, bp) {
						allocated = allocation.Status != 4
						if e.config.P2P.Network != 0 ||
							data.Frame.Header.FrameNumber > token.FRAME_2_1_EXTENDED_ENROLL_END {
							e.logger.Info(
								"checking pending status of allocation",
								zap.Int("status", int(allocation.Status)),
								zap.Uint64("join_frame_number", allocation.JoinFrameNumber),
								zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
							)
							pending = allocation.Status ==
								typesconsensus.ProverStatusJoining &&
								allocation.JoinFrameNumber+360 <= data.Frame.Header.FrameNumber
						}
					}
				}
			}

			e.logger.Debug(
				"checking descriptor for eligibility",
				zap.String("shard_key", hex.EncodeToString(bp)),
			)

			size := new(big.Int).SetBytes(shard.Size)
			if size.Cmp(big.NewInt(0)) == 0 {
				e.logger.Debug(
					"no data in shard",
					zap.String("shard_key", hex.EncodeToString(bp)),
				)
				continue
			}

			e.logger.Debug(
				"logical shard count",
				zap.Int("shard_count", int(shard.DataShards)),
			)

			above := []*typesconsensus.ProverInfo{}
			for _, i := range prs {
				if i.Seniority >= effectiveSeniority {
					above = append(above, i)
				}
			}

			if allocated && pending {
				pendingFilters = append(pendingFilters, bp)
			}
			if !allocated {
				e.logger.Debug(
					"appending descriptor for allocation planning",
					zap.String("shard_key", hex.EncodeToString(bp)),
					zap.Uint64("size", size.Uint64()),
					zap.Int("ring", len(above)/8),
					zap.Int("shard_count", int(shard.DataShards)),
				)

				proposalDescriptors = append(
					proposalDescriptors,
					provers.ShardDescriptor{
						Filter: bp,
						Size:   size.Uint64(),
						Ring:   uint8(len(above) / 8),
						Shards: shard.DataShards,
					},
				)
			}
			decideDescriptors = append(
				decideDescriptors,
				provers.ShardDescriptor{
					Filter: bp,
					Size:   size.Uint64(),
					Ring:   uint8(len(above) / 8),
					Shards: shard.DataShards,
				},
			)
		}
	}
	if len(proposalDescriptors) != 0 {
		proposals, err := e.proposer.PlanAndAllocate(
			uint64(data.Frame.Header.Difficulty),
			proposalDescriptors,
			0,
		)
		if err != nil {
			e.logger.Error("could not plan shard allocations", zap.Error(err))
		} else {
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
				zap.Int("proposals", len(proposals)),
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
	}
	if len(pendingFilters) != 0 {
		err = e.proposer.DecideJoins(
			uint64(data.Frame.Header.Difficulty),
			decideDescriptors,
			pendingFilters,
		)
		if err != nil {
			e.logger.Error("could not decide shard allocations", zap.Error(err))
		} else {
			e.logger.Info(
				"decided on joins",
				zap.Int("joins", len(pendingFilters)),
			)
		}
	}
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
			ShardKey: shardKey,
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
