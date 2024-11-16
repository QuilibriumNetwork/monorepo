package data

import (
	"bytes"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/cas"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	frameProverTries := make(
		[]*tries.RollingFrecencyCritbitTrie,
		len(e.frameProverTries),
	)

	for i, trie := range e.frameProverTries {
		newTrie := &tries.RollingFrecencyCritbitTrie{}
		b, err := trie.Serialize()
		if err != nil {
			panic(err)
		}

		err = newTrie.Deserialize(b)
		if err != nil {
			panic(err)
		}
		frameProverTries[i] = newTrie
	}

	e.frameProverTriesMx.RUnlock()
	return frameProverTries
}

func (e *DataClockConsensusEngine) runSync() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case enqueuedFrame := <-e.requestSyncCh:
			if _, err := e.collect(enqueuedFrame); err != nil {
				e.logger.Error("could not collect", zap.Error(err))
			}
		}
	}
}

func (e *DataClockConsensusEngine) runLoop() {
	dataFrameCh := e.dataTimeReel.NewFrameCh()
	runOnce := true
	for e.GetState() < consensus.EngineStateStopping {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			time.Sleep(1 * time.Second)
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			select {
			case dataFrame := <-dataFrameCh:
				runOnce = false
				if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
					if err = e.publishProof(dataFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.stateMx.Lock()
						if e.state < consensus.EngineStateStopping {
							e.state = consensus.EngineStateCollecting
						}
						e.stateMx.Unlock()
					}
				}
				latestFrame = e.processFrame(latestFrame, dataFrame)
			case <-time.After(20 * time.Second):
				if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) && !runOnce {
					continue
				}

				if runOnce {
					runOnce = false
				}

				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				latestFrame = e.processFrame(latestFrame, dataFrame)
			}
		}
	}
}

func (e *DataClockConsensusEngine) processFrame(
	latestFrame *protobufs.ClockFrame,
	dataFrame *protobufs.ClockFrame,
) *protobufs.ClockFrame {
	e.logger.Info(
		"current frame head",
		zap.Uint64("frame_number", dataFrame.FrameNumber),
		zap.Duration("frame_age", frametime.Since(dataFrame)),
	)
	var err error
	if !e.GetFrameProverTries()[0].Contains(e.provingKeyBytes) {
		select {
		case e.requestSyncCh <- dataFrame:
		default:
		}
	}

	if latestFrame != nil && dataFrame.FrameNumber > latestFrame.FrameNumber {
		latestFrame = dataFrame
	}

	cas.IfLessThanUint64(&e.latestFrameReceived, latestFrame.FrameNumber)
	e.frameProverTriesMx.Lock()
	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()
	e.frameProverTriesMx.Unlock()

	trie := e.GetFrameProverTries()[0]
	selBI, _ := dataFrame.GetSelector()
	sel := make([]byte, 32)
	sel = selBI.FillBytes(sel)

	if bytes.Equal(
		trie.FindNearest(sel).Key,
		e.provingKeyAddress,
	) {
		var nextFrame *protobufs.ClockFrame
		if nextFrame, err = e.prove(dataFrame); err != nil {
			e.logger.Error("could not prove", zap.Error(err))
			e.stateMx.Lock()
			if e.state < consensus.EngineStateStopping {
				e.state = consensus.EngineStateCollecting
			}
			e.stateMx.Unlock()
			return dataFrame
		}

		e.dataTimeReel.Insert(nextFrame, true)

		return nextFrame
	} else {
		if latestFrame.Timestamp > time.Now().UnixMilli()-120000 {
			if !e.IsInProverTrie(e.pubSub.GetPeerID()) {
				e.logger.Info("announcing prover join")
				for _, eng := range e.executionEngines {
					eng.AnnounceProverJoin()
					break
				}
			} else {
				if e.previousFrameProven != nil &&
					e.previousFrameProven.FrameNumber == latestFrame.FrameNumber {
					return latestFrame
				}

				h, err := poseidon.HashBytes(e.pubSub.GetPeerID())
				if err != nil {
					panic(err)
				}
				peerProvingKeyAddress := h.FillBytes(make([]byte, 32))

				ring := -1
				if len(e.GetFrameProverTries()) > 1 {
					for i, tries := range e.GetFrameProverTries()[1:] {
						i := i
						if tries.Contains(peerProvingKeyAddress) {
							ring = i
						}
					}
				}

				e.clientReconnectTest++
				if e.clientReconnectTest >= 10 {
					wg := sync.WaitGroup{}
					wg.Add(len(e.clients))
					for i, client := range e.clients {
						i := i
						client := client
						go func() {
							for j := 3; j >= 0; j-- {
								var err error
								if client == nil {
									if len(e.config.Engine.DataWorkerMultiaddrs) != 0 {
										e.logger.Error(
											"client failed, reconnecting after 50ms",
											zap.Uint32("client", uint32(i)),
										)
										time.Sleep(50 * time.Millisecond)
										client, err = e.createParallelDataClientsFromListAndIndex(uint32(i))
										if err != nil {
											e.logger.Error("failed to reconnect", zap.Error(err))
										}
									} else if len(e.config.Engine.DataWorkerMultiaddrs) == 0 {
										e.logger.Error(
											"client failed, reconnecting after 50ms",
											zap.Uint32("client", uint32(i)),
										)
										time.Sleep(50 * time.Millisecond)
										client, err =
											e.createParallelDataClientsFromBaseMultiaddrAndIndex(uint32(i))
										if err != nil {
											e.logger.Error(
												"failed to reconnect",
												zap.Uint32("client", uint32(i)),
												zap.Error(err),
											)
										}
									}
									e.clients[i] = client
									continue
								}
							}
							wg.Done()
						}()
					}
					wg.Wait()
					e.clientReconnectTest = 0
				}

				outputs := e.PerformTimeProof(latestFrame, latestFrame.Difficulty, ring)
				if outputs == nil || len(outputs) < 3 {
					e.logger.Error("could not successfully build proof, reattempting")
					return latestFrame
				}
				modulo := len(outputs)
				proofTree, payload, output, err := tries.PackOutputIntoPayloadAndProof(
					outputs,
					modulo,
					latestFrame,
					e.previousTree,
				)
				if err != nil {
					e.logger.Error(
						"could not successfully pack proof, reattempting",
						zap.Error(err),
					)
					return latestFrame
				}
				e.previousFrameProven = latestFrame
				e.previousTree = proofTree

				sig, err := e.pubSub.SignMessage(
					payload,
				)
				if err != nil {
					panic(err)
				}

				e.logger.Info(
					"submitting data proof",
					zap.Int("ring", ring),
					zap.Int("active_workers", len(outputs)),
					zap.Uint64("frame_number", latestFrame.FrameNumber),
					zap.Duration("frame_age", frametime.Since(latestFrame)),
				)

				e.publishMessage(e.txFilter, &protobufs.TokenRequest{
					Request: &protobufs.TokenRequest_Mint{
						Mint: &protobufs.MintCoinRequest{
							Proofs: output,
							Signature: &protobufs.Ed448Signature{
								PublicKey: &protobufs.Ed448PublicKey{
									KeyValue: e.pubSub.GetPublicKey(),
								},
								Signature: sig,
							},
						},
					},
					Timestamp: time.Now().UnixMilli(),
				})

				if e.config.Engine.AutoMergeCoins {
					_, addrs, _, err := e.coinStore.GetCoinsForOwner(
						peerProvingKeyAddress,
					)
					if err != nil {
						e.logger.Error(
							"received error while iterating coins",
							zap.Error(err),
						)
						return latestFrame
					}

					if len(addrs) > 25 {
						message := []byte("merge")
						refs := []*protobufs.CoinRef{}
						for _, addr := range addrs {
							message = append(message, addr...)
							refs = append(refs, &protobufs.CoinRef{
								Address: addr,
							})
						}

						sig, _ := e.pubSub.SignMessage(
							message,
						)

						e.publishMessage(e.txFilter, &protobufs.TokenRequest{
							Request: &protobufs.TokenRequest_Merge{
								Merge: &protobufs.MergeCoinRequest{
									Coins: refs,
									Signature: &protobufs.Ed448Signature{
										PublicKey: &protobufs.Ed448PublicKey{
											KeyValue: e.pubSub.GetPublicKey(),
										},
										Signature: sig,
									},
								},
							},
							Timestamp: time.Now().UnixMilli(),
						})
					}
				}
			}
		}
		return latestFrame
	}
}
