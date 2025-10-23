package app

import (
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/global"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

func (e *AppConsensusEngine) eventDistributorLoop() {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("fatal error encountered", zap.Any("panic", r))
			if e.cancel != nil {
				e.cancel()
			}
			// Avoid blocking on quit channel during panic recovery
			select {
			case e.quit <- struct{}{}:
			default:
			}
		}
	}()
	defer e.wg.Done()

	// Subscribe to events from the event distributor
	eventCh := e.eventDistributor.Subscribe(hex.EncodeToString(e.appAddress))
	defer e.eventDistributor.Unsubscribe(hex.EncodeToString(e.appAddress))

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

			switch event.Type {
			case typesconsensus.ControlEventAppNewHead:
				if data, ok := event.Data.(*consensustime.AppEvent); ok &&
					data.Frame != nil {
					e.logger.Debug(
						"received new app head event",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					// Record the fee vote from the accepted frame
					if err := e.dynamicFeeManager.AddFrameFeeVote(
						e.appAddress,
						data.Frame.Header.FrameNumber,
						data.Frame.Header.FeeMultiplierVote,
					); err != nil {
						e.logger.Error(
							"failed to add frame fee vote",
							zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
							zap.Uint64("fee_vote", data.Frame.Header.FeeMultiplierVote),
							zap.Error(err),
						)
					}
				}
			case typesconsensus.ControlEventAppEquivocation:
				// Handle equivocation by constructing and publishing a ProverKick
				// message
				if data, ok := event.Data.(*consensustime.AppEvent); ok &&
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
							global.GLOBAL_PROVER_BITMASK,
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

			case typesconsensus.ControlEventAppFork:
				if data, ok := event.Data.(*consensustime.AppEvent); ok &&
					data.Frame != nil {
					e.logger.Debug(
						"received new app fork event",
						zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
					)

					// Remove the forked fee votes
					removed, err := e.dynamicFeeManager.RewindToFrame(
						e.appAddress,
						data.Frame.Header.FrameNumber,
					)
					if err != nil {
						e.logger.Error(
							"failed to rewind frame fee vote",
							zap.Uint64("frame_number", data.Frame.Header.FrameNumber),
							zap.Error(err),
						)
					}

					e.logger.Info("rewound fee votes", zap.Int("removed_votes", removed))
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

func (e *AppConsensusEngine) emitAlertEvent(alertMessage string) {
	event := typesconsensus.ControlEvent{
		Type: typesconsensus.ControlEventHalt,
		Data: &typesconsensus.ErrorEventData{
			Error: errors.New(alertMessage),
		},
	}

	go e.eventDistributor.Publish(event)

	e.logger.Info("emitted alert message")
}
