package data

import (
	"bytes"
	"context"
	"slices"
	"time"

	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data/internal"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	mt "github.com/txaty/go-merkletree"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) syncWithMesh() error {
	e.logger.Info("collecting vdf proofs")

	latest, err := e.dataTimeReel.Head()
	if err != nil {
		return errors.Wrap(err, "sync")
	}
	var doneChs []<-chan struct{}
	for {
		candidates := e.GetAheadPeers(max(latest.FrameNumber, e.latestFrameReceived))
		if len(candidates) == 0 {
			break
		}
		for _, candidate := range candidates {
			head, err := e.dataTimeReel.Head()
			if err != nil {
				return errors.Wrap(err, "sync")
			}
			if latest.FrameNumber < head.FrameNumber {
				latest = head
			}
			if candidate.MaxFrame <= max(latest.FrameNumber, e.latestFrameReceived) {
				continue
			}
			latest, doneChs, err = e.syncWithPeer(latest, doneChs, candidate.MaxFrame, candidate.PeerID)
			if err != nil {
				e.logger.Debug("error syncing frame", zap.Error(err))
			}
		}
	}

	for _, doneCh := range doneChs {
		select {
		case <-e.ctx.Done():
			return e.ctx.Err()
		case <-doneCh:
		}
	}

	e.logger.Info(
		"returning leader frame",
		zap.Uint64("frame_number", latest.FrameNumber),
		zap.Duration("frame_age", frametime.Since(latest)),
	)

	return nil
}

func (e *DataClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	time.Sleep(40 * time.Second)
	if e.lastProven >= previousFrame.FrameNumber && e.lastProven != 0 {
		return previousFrame, nil
	}
	executionOutput := &protobufs.IntrinsicExecutionOutput{}
	_, tries, err := e.clockStore.GetDataClockFrame(
		e.filter,
		previousFrame.FrameNumber,
		false,
	)
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		previousFrame,
		tries,
		e.coinStore,
		e.clockStore,
		e.pubSub,
		e.logger,
		e.frameProver,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.stagedTransactionsMx.Lock()
	stagedTransactions := e.stagedTransactions
	if stagedTransactions == nil {
		stagedTransactions = &protobufs.TokenRequests{}
	}
	e.stagedTransactions = &protobufs.TokenRequests{
		Requests: make([]*protobufs.TokenRequest, 0, len(stagedTransactions.Requests)),
	}
	e.stagedTransactionsSet = make(map[string]struct{}, len(e.stagedTransactionsSet))
	e.stagedTransactionsMx.Unlock()

	e.logger.Info(
		"proving new frame",
		zap.Int("transactions", len(stagedTransactions.Requests)),
	)

	var validTransactions *protobufs.TokenRequests
	var invalidTransactions *protobufs.TokenRequests
	app, validTransactions, invalidTransactions, err = app.ApplyTransitions(
		previousFrame.FrameNumber+1,
		stagedTransactions,
		true,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Info(
		"applied transitions",
		zap.Int("successful", len(validTransactions.Requests)),
		zap.Int("failed", len(invalidTransactions.Requests)),
	)

	outputState, err := app.MaterializeStateFromApplication()
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Address = application.TOKEN_ADDRESS
	executionOutput.Output, err = proto.Marshal(outputState)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Proof, err = proto.Marshal(validTransactions)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("encoded execution output")
	digest := sha3.NewShake256()
	_, err = digest.Write(data)
	if err != nil {
		e.logger.Error(
			"error writing digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	expand := make([]byte, 1024)
	_, err = digest.Read(expand)
	if err != nil {
		e.logger.Error(
			"error expanding digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	commitment, err := e.inclusionProver.CommitRaw(
		expand,
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("creating kzg proof")
	proof, err := e.inclusionProver.ProveRaw(
		expand,
		int(expand[0]%16),
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("finalizing execution proof")

	frame, err := e.frameProver.ProveDataClockFrame(
		previousFrame,
		[][]byte{proof},
		[]*protobufs.InclusionAggregateProof{
			{
				Filter:      e.filter,
				FrameNumber: previousFrame.FrameNumber + 1,
				InclusionCommitments: []*protobufs.InclusionCommitment{
					{
						Filter:      e.filter,
						FrameNumber: previousFrame.FrameNumber + 1,
						TypeUrl:     protobufs.IntrinsicExecutionOutputType,
						Commitment:  commitment,
						Data:        data,
						Position:    0,
					},
				},
				Proof: proof,
			},
		},
		e.provingKey,
		time.Now().UnixMilli(),
		e.difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.lastProven = previousFrame.FrameNumber
	e.logger.Info(
		"returning new proven frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
		zap.Int("commitment_count", len(frame.Input[516:])/74),
	)
	return frame, nil
}

func (e *DataClockConsensusEngine) GetAheadPeers(frameNumber uint64) []internal.PeerCandidate {
	if e.FrameProverTrieContains(0, e.provingKeyAddress) {
		return nil
	}

	e.peerMapMx.RLock()
	peerMapLen, uncooperativePeerMapLen := len(e.peerMap), len(e.uncooperativePeersMap)
	e.peerMapMx.RUnlock()

	e.logger.Debug(
		"checking peer list",
		zap.Int("peers", peerMapLen),
		zap.Int("uncooperative_peers", uncooperativePeerMapLen),
		zap.Uint64("current_head_frame", frameNumber),
	)

	nearCandidates, nearMaxDiff := make([]internal.WeightedPeerCandidate, 0, peerMapLen), uint64(0)
	reachableCandidates, reachableMaxDiff := make([]internal.WeightedPeerCandidate, 0, peerMapLen), uint64(0)
	unreachableCandidates, unreachableMaxDiff := make([]internal.WeightedPeerCandidate, 0, peerMapLen), uint64(0)
	unknownCandidates, unknownMaxDiff := make([]internal.WeightedPeerCandidate, 0, peerMapLen), uint64(0)

	e.peerMapMx.RLock()
	for _, v := range e.peerMap {
		e.logger.Debug(
			"checking peer info",
			zap.Binary("peer_id", v.peerId),
			zap.Uint64("max_frame_number", v.maxFrame),
			zap.Int64("timestamp", v.timestamp),
			zap.Binary("version", v.version),
		)
		if v.maxFrame <= frameNumber {
			continue
		}
		if _, ok := e.uncooperativePeersMap[string(v.peerId)]; ok {
			continue
		}
		if v.timestamp <= config.GetMinimumVersionCutoff().UnixMilli() {
			continue
		}
		if bytes.Compare(v.version, config.GetMinimumVersion()) < 0 {
			continue
		}
		candidate, diff := internal.WeightedPeerCandidate{
			PeerCandidate: internal.PeerCandidate{
				PeerID:   v.peerId,
				MaxFrame: v.maxFrame,
			},
		}, v.maxFrame-frameNumber
		switch {
		case e.pubSub.IsPeerConnected(v.peerId):
			nearMaxDiff = max(nearMaxDiff, diff)
			nearCandidates = append(nearCandidates, candidate)
		case v.reachability == nil:
			unknownMaxDiff = max(unknownMaxDiff, diff)
			unknownCandidates = append(unknownCandidates, candidate)
		case v.reachability.Value:
			reachableMaxDiff = max(reachableMaxDiff, diff)
			reachableCandidates = append(reachableCandidates, candidate)
		default:
			unreachableMaxDiff = max(unreachableMaxDiff, diff)
			unreachableCandidates = append(unreachableCandidates, candidate)
		}
	}
	e.peerMapMx.RUnlock()

	if len(nearCandidates)+len(reachableCandidates)+len(unreachableCandidates)+len(unknownCandidates) == 0 {
		return nil
	}

	for _, pair := range []struct {
		maxDiff    uint64
		candidates []internal.WeightedPeerCandidate
	}{
		{nearMaxDiff, nearCandidates},
		{reachableMaxDiff, reachableCandidates},
		{unknownMaxDiff, unknownCandidates},
		{unreachableMaxDiff, unreachableCandidates},
	} {
		maxDiff, candidates := pair.maxDiff, pair.candidates
		for i := range candidates {
			candidates[i].Weight = float64(candidates[i].MaxFrame-frameNumber) / float64(maxDiff)
		}
	}

	syncCandidates := e.config.Engine.SyncCandidates
	return slices.Concat(
		internal.WeightedSampleWithoutReplacement(nearCandidates, min(len(nearCandidates), syncCandidates)),
		internal.WeightedSampleWithoutReplacement(reachableCandidates, min(len(reachableCandidates), syncCandidates)),
		internal.WeightedSampleWithoutReplacement(unknownCandidates, min(len(unknownCandidates), syncCandidates)),
		internal.WeightedSampleWithoutReplacement(unreachableCandidates, min(len(unreachableCandidates), syncCandidates)),
	)
}

func (e *DataClockConsensusEngine) syncWithPeer(
	latest *protobufs.ClockFrame,
	doneChs []<-chan struct{},
	maxFrame uint64,
	peerId []byte,
) (*protobufs.ClockFrame, []<-chan struct{}, error) {
	e.syncingStatus = SyncStatusSynchronizing
	defer func() { e.syncingStatus = SyncStatusNotSyncing }()
	e.logger.Info(
		"polling peer for new frames",
		zap.String("peer_id", peer.ID(peerId).String()),
		zap.Uint64("current_frame", latest.FrameNumber),
		zap.Uint64("max_frame", maxFrame),
	)

	var cooperative bool = true
	defer func() {
		if cooperative {
			return
		}
		e.peerMapMx.Lock()
		defer e.peerMapMx.Unlock()
		if _, ok := e.peerMap[string(peerId)]; ok {
			e.uncooperativePeersMap[string(peerId)] = e.peerMap[string(peerId)]
			e.uncooperativePeersMap[string(peerId)].timestamp = time.Now().UnixMilli()
			delete(e.peerMap, string(peerId))
		}
	}()

	syncTimeout := e.config.Engine.SyncTimeout
	dialCtx, cancelDial := context.WithTimeout(e.ctx, syncTimeout)
	defer cancelDial()
	cc, err := e.pubSub.GetDirectChannel(dialCtx, peerId, "sync")
	if err != nil {
		e.logger.Debug(
			"could not establish direct channel",
			zap.Error(err),
		)
		cooperative = false
		return latest, doneChs, errors.Wrap(err, "sync")
	}
	defer func() {
		if err := cc.Close(); err != nil {
			e.logger.Error("error while closing connection", zap.Error(err))
		}
	}()

	client := protobufs.NewDataServiceClient(cc)
	for {
		getCtx, cancelGet := context.WithTimeout(e.ctx, syncTimeout)
		response, err := client.GetDataFrame(
			getCtx,
			&protobufs.GetDataFrameRequest{
				FrameNumber: latest.FrameNumber + 1,
			},
			// The message size limits are swapped because the server is the one
			// sending the data.
			grpc.MaxCallRecvMsgSize(e.config.Engine.SyncMessageLimits.MaxSendMsgSize),
			grpc.MaxCallSendMsgSize(e.config.Engine.SyncMessageLimits.MaxRecvMsgSize),
		)
		cancelGet()
		if err != nil {
			e.logger.Debug(
				"could not get frame",
				zap.Error(err),
			)
			cooperative = false
			return latest, doneChs, errors.Wrap(err, "sync")
		}

		if response == nil {
			e.logger.Debug("received no response from peer")
			return latest, doneChs, nil
		}

		if response.ClockFrame == nil ||
			response.ClockFrame.FrameNumber != latest.FrameNumber+1 ||
			response.ClockFrame.Timestamp < latest.Timestamp {
			e.logger.Debug("received invalid response from peer")
			cooperative = false
			return latest, doneChs, nil
		}
		e.logger.Info(
			"received new leading frame",
			zap.Uint64("frame_number", response.ClockFrame.FrameNumber),
			zap.Duration("frame_age", frametime.Since(response.ClockFrame)),
		)

		if !e.IsInProverTrie(
			response.ClockFrame.GetPublicKeySignatureEd448().PublicKey.KeyValue,
		) {
			cooperative = false
		}

		if err := e.frameProver.VerifyDataClockFrame(
			response.ClockFrame,
		); err != nil {
			return latest, doneChs, errors.Wrap(err, "sync")
		}

		// Useful for testnet, immediately handles equivocation from multiple
		// genesis events:
		if response.ClockFrame.FrameNumber == 1 {
			genesis, _, _ := e.clockStore.GetDataClockFrame(e.filter, 0, true)
			selector, _ := genesis.GetSelector()
			if !bytes.Equal(
				response.ClockFrame.ParentSelector,
				selector.FillBytes(make([]byte, 32)),
			) {
				cooperative = false
				return latest, doneChs, errors.Wrap(errors.New("invalid frame"), "sync")
			}
		}

		doneCh, err := e.dataTimeReel.Insert(e.ctx, response.ClockFrame)
		if err != nil {
			return latest, doneChs, errors.Wrap(err, "sync")
		}

		doneChs = append(doneChs, doneCh)
		latest = response.ClockFrame

		if latest.FrameNumber >= maxFrame {
			return latest, doneChs, nil
		}
	}
}

func (e *DataClockConsensusEngine) initiateProvers(
	latestFrame *protobufs.ClockFrame,
) {
	logger := utils.GetLogger()
	if latestFrame.Timestamp > time.Now().UnixMilli()-60000 {
		if !e.IsInProverTrie(e.pubSub.GetPeerID()) {
			e.logger.Info("announcing prover join")
			for _, eng := range e.executionEngines {
				eng.AnnounceProverJoin()
				break
			}
		} else {
			if e.previousFrameProven != nil &&
				e.previousFrameProven.FrameNumber == latestFrame.FrameNumber {
				return
			}

			h, err := poseidon.HashBytes(e.pubSub.GetPeerID())
			if err != nil {
				logger.Panic("could not hash peer id", zap.Error(err))
			}
			peerProvingKeyAddress := h.FillBytes(make([]byte, 32))

			ring := -1
			if tries := e.GetFrameProverTries(); len(tries) > 1 {
				for i, tries := range tries[1:] {
					i := i
					if tries.Contains(peerProvingKeyAddress) {
						ring = i
					}
				}
			}

			e.clientReconnectTest++
			if e.clientReconnectTest >= 10 {
				e.tryReconnectDataWorkerClients()
				e.clientReconnectTest = 0
			}

			previousTreeRoot := []byte{}
			if e.previousTree != nil {
				previousTreeRoot = e.previousTree.Root
			}
			outputs := e.PerformTimeProof(latestFrame, previousTreeRoot, latestFrame.Difficulty, ring)
			if outputs == nil || len(outputs) < 3 {
				e.logger.Info("workers not yet available for proving")
				return
			}
			modulo := len(outputs)
			var proofTree *mt.MerkleTree
			var output [][]byte
			if latestFrame.FrameNumber >= application.PROOF_FRAME_COMBINE_CUTOFF {
				proofTree, output, err = tries.PackOutputIntoMultiPayloadAndProof(
					outputs,
					modulo,
					latestFrame,
					e.previousTree,
				)
			} else {
				proofTree, output, err = tries.PackOutputIntoPayloadAndProof(
					outputs,
					modulo,
					latestFrame,
					e.previousTree,
				)
			}
			if err != nil {
				e.logger.Error(
					"could not successfully pack proof, reattempting",
					zap.Error(err),
				)
				return
			}
			e.previousFrameProven = latestFrame
			e.previousTree = proofTree

			mint := &protobufs.MintCoinRequest{
				Proofs: output,
			}
			if err := mint.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
				e.logger.Error("could not sign mint", zap.Error(err))
				return
			}
			if err := mint.Validate(); err != nil {
				e.logger.Error("mint validation failed", zap.Error(err))
				return
			}

			e.logger.Info(
				"submitting data proof",
				zap.Int("ring", ring),
				zap.Int("active_workers", len(outputs)),
				zap.Uint64("frame_number", latestFrame.FrameNumber),
				zap.Duration("frame_age", frametime.Since(latestFrame)),
			)

			if err := e.publishMessage(e.txFilter, mint.TokenRequest()); err != nil {
				e.logger.Error("could not publish mint", zap.Error(err))
			}

			if e.config.Engine.AutoMergeCoins {
				_, addrs, _, err := e.coinStore.GetCoinsForOwner(
					peerProvingKeyAddress,
				)
				if err != nil {
					e.logger.Error(
						"received error while iterating coins",
						zap.Error(err),
					)
					return
				}

				if len(addrs) > 25 {
					refs := []*protobufs.CoinRef{}
					for _, addr := range addrs {
						refs = append(refs, &protobufs.CoinRef{
							Address: addr,
						})
					}

					merge := &protobufs.MergeCoinRequest{
						Coins: refs,
					}
					if err := merge.SignED448(
						e.pubSub.GetPublicKey(),
						e.pubSub.SignMessage,
					); err != nil {
						e.logger.Error("could not sign merge", zap.Error(err))
						return
					}
					if err := merge.Validate(); err != nil {
						e.logger.Error("merge validation failed", zap.Error(err))
						return
					}

					if err := e.publishMessage(e.txFilter, merge.TokenRequest()); err != nil {
						e.logger.Warn("could not publish merge", zap.Error(err))
					}
				}
			}
		}
	}
}
