package data

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

func (e *DataClockConsensusEngine) runFrameMessageHandler() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.frameMessageProcessorCh:
			e.logger.Debug("handling frame message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("cannot unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				e.logger.Debug("cannot unmarshal payload", zap.Error(err))
				continue
			}

			switch a.TypeUrl {
			case protobufs.ClockFrameType:
				if err := e.handleClockFrameData(
					message.From,
					msg.Address,
					a,
				); err != nil {
					e.logger.Debug("could not handle clock frame data", zap.Error(err))
				}
			}
		}
	}
}

func (e *DataClockConsensusEngine) runFrameFragmentMessageHandler() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.frameFragmentMessageProcessorCh:
			e.logger.Debug("handling frame fragment message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("cannot unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				e.logger.Debug("cannot unmarshal payload", zap.Error(err))
				continue
			}

			switch a.TypeUrl {
			case protobufs.ClockFrameFragmentType:
				if err := e.handleClockFrameFragmentData(
					message.From,
					msg.Address,
					a,
				); err != nil {
					e.logger.Debug("could not handle clock frame fragment data", zap.Error(err))
				}
			}
		}
	}
}

func (e *DataClockConsensusEngine) runTxMessageHandler() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.txMessageProcessorCh:
			e.logger.Debug("handling tx message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("could not unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				e.logger.Debug("could not unmarshal payload", zap.Error(err))
				continue
			}

			if e.FrameProverTrieContains(0, e.provingKeyAddress) {
				wg := &sync.WaitGroup{}
				for name := range e.executionEngines {
					name := name
					wg.Add(1)
					go func() error {
						defer wg.Done()
						messages, err := e.executionEngines[name].ProcessMessage(
							application.TOKEN_ADDRESS,
							msg,
						)
						if err != nil {
							e.logger.Debug(
								"could not process message for engine",
								zap.Error(err),
								zap.String("engine_name", name),
							)
							return nil
						}

						for _, appMessage := range messages {
							a := &anypb.Any{}
							err := proto.Unmarshal(appMessage.Payload, a)
							if err != nil {
								e.logger.Error(
									"could not unmarshal app message",
									zap.Error(err),
									zap.String("engine_name", name),
								)
								continue
							}

							switch a.TypeUrl {
							case protobufs.TokenRequestType:
								t := &protobufs.TokenRequest{}
								err := proto.Unmarshal(a.Value, t)
								if err != nil {
									e.logger.Debug("could not unmarshal token request", zap.Error(err))
									continue
								}

								if err := e.handleTokenRequest(t); err != nil {
									e.logger.Debug("could not handle token request", zap.Error(err))
								}
							}
						}

						return nil
					}()
				}
				wg.Wait()
			}
		}
	}
}

func (e *DataClockConsensusEngine) runInfoMessageHandler() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case message := <-e.infoMessageProcessorCh:
			e.logger.Debug("handling info message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("could not unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				e.logger.Debug("could not unmarshal payload", zap.Error(err))
				continue
			}

			switch a.TypeUrl {
			case protobufs.DataPeerListAnnounceType:
				if err := e.handleDataPeerListAnnounce(
					message.From,
					msg.Address,
					a,
				); err != nil {
					e.logger.Debug("could not handle data peer list announce", zap.Error(err))
				}
			}
		}
	}
}

func (e *DataClockConsensusEngine) handleClockFrame(
	peerID []byte,
	address []byte,
	frame *protobufs.ClockFrame,
) error {
	if frame == nil {
		return errors.Wrap(errors.New("frame is nil"), "handle clock frame")
	}

	addr, err := poseidon.HashBytes(
		frame.GetPublicKeySignatureEd448().PublicKey.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	if !e.FrameProverTrieContains(0, addr.FillBytes(make([]byte, 32))) {
		e.logger.Debug(
			"prover not in trie at frame, address may be in fork",
			zap.Binary("address", address),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		return nil
	}

	if _, ok := e.recentlyProcessedFrames.Peek(string(frame.Output)); ok {
		return nil
	}

	e.recentlyProcessedFrames.Add(string(frame.Output), struct{}{})

	e.logger.Debug(
		"got clock frame",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := e.frameProver.VerifyDataClockFrame(frame); err != nil {
		e.logger.Debug("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	e.logger.Debug(
		"clock frame was valid",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	head, err := e.dataTimeReel.Head()
	if err != nil {
		e.logger.Panic("failed to get head frame", zap.Error(err))
	}

	if frame.FrameNumber > head.FrameNumber {
		go e.initiateProvers(frame)

		if _, err := e.dataTimeReel.Insert(e.ctx, frame); err != nil {
			e.logger.Debug("could not insert frame", zap.Error(err))
		}
	}

	return nil
}

func (e *DataClockConsensusEngine) handleClockFrameFragment(
	peerID []byte,
	address []byte,
	fragment *protobufs.ClockFrameFragment,
) error {
	if fragment == nil {
		return errors.Wrap(errors.New("fragment is nil"), "handle clock frame fragment")
	}

	addr, err := poseidon.HashBytes(
		fragment.GetPublicKeySignatureEd448().PublicKey.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "handle clock frame fragment data")
	}

	if !e.FrameProverTrieContains(0, addr.FillBytes(make([]byte, 32))) {
		e.logger.Debug(
			"prover not in trie at frame fragment, address may be in fork",
			zap.Binary("address", address),
			zap.Binary("filter", fragment.Filter),
			zap.Uint64("frame_number", fragment.FrameNumber),
		)
		return nil
	}

	e.logger.Debug(
		"got clock frame fragment",
		zap.Binary("address", address),
		zap.Binary("filter", fragment.Filter),
		zap.Uint64("frame_number", fragment.FrameNumber),
	)

	frame, err := e.clockFrameFragmentBuffer.AccumulateClockFrameFragment(fragment)
	if err != nil {
		e.logger.Debug("could not accumulate clock frame fragment", zap.Error(err))
		return errors.Wrap(err, "handle clock frame fragment data")
	}
	if frame == nil {
		return nil
	}

	e.logger.Info(
		"accumulated clock frame",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	return e.handleClockFrame(peerID, address, frame)
}

func (e *DataClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	address []byte,
	a *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	frame := &protobufs.ClockFrame{}
	if err := a.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	return e.handleClockFrame(peerID, address, frame)
}

func (e *DataClockConsensusEngine) handleClockFrameFragmentData(
	peerID []byte,
	address []byte,
	a *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	fragment := &protobufs.ClockFrameFragment{}
	if err := a.UnmarshalTo(fragment); err != nil {
		return errors.Wrap(err, "handle clock frame fragment data")
	}

	return e.handleClockFrameFragment(peerID, address, fragment)
}

func (e *DataClockConsensusEngine) handleDataPeerListAnnounce(
	peerID []byte,
	address []byte,
	a *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	announce := &protobufs.DataPeerListAnnounce{}
	if err := a.UnmarshalTo(announce); err != nil {
		return errors.Wrap(err, "handle data peer list announce")
	}

	p := announce.Peer
	if p == nil {
		return nil
	}

	head, err := e.dataTimeReel.Head()
	if err != nil {
		return errors.Wrap(err, "handle data peer list announce")
	}
	if p.MaxFrame <= head.FrameNumber {
		return nil
	}

	patchVersion := byte(0)
	if len(p.PatchVersion) == 1 {
		patchVersion = p.PatchVersion[0]
	}

	if p.Version != nil &&
		bytes.Compare(p.Version, config.GetMinimumVersion()) < 0 &&
		p.Timestamp > config.GetMinimumVersionCutoff().UnixMilli() {
		e.logger.Debug(
			"peer provided outdated version, penalizing app score",
			zap.String("peer_id", peer.ID(peerID).String()),
		)
		e.pubSub.AddPeerScore(peerID, -1000)
		return nil
	}

	e.peerMapMx.RLock()
	if _, ok := e.uncooperativePeersMap[string(peerID)]; ok {
		e.peerMapMx.RUnlock()
		return nil
	}
	e.peerMapMx.RUnlock()

	e.pubSub.AddPeerScore(peerID, 10)

	e.peerMapMx.RLock()
	existing, ok := e.peerMap[string(peerID)]
	e.peerMapMx.RUnlock()

	if ok && existing.timestamp > p.Timestamp {
		return nil
	}

	multiaddr := e.pubSub.GetMultiaddrOfPeer(peerID)
	e.peerMapMx.Lock()
	e.peerMap[string(peerID)] = &peerInfo{
		peerId:        peerID,
		multiaddr:     multiaddr,
		maxFrame:      p.MaxFrame,
		lastSeen:      time.Now().Unix(),
		timestamp:     p.Timestamp,
		version:       p.Version,
		patchVersion:  patchVersion,
		totalDistance: p.TotalDistance,
		reachability:  p.ExternallyReachable,
	}
	e.peerMapMx.Unlock()

	select {
	case <-e.ctx.Done():
		return nil
	case e.requestSyncCh <- struct{}{}:
	default:
	}

	return nil
}

func TokenRequestIdentifiers(transition *protobufs.TokenRequest) []string {
	switch t := transition.Request.(type) {
	case *protobufs.TokenRequest_Transfer:
		return []string{fmt.Sprintf("transfer-%x", t.Transfer.OfCoin.Address)}
	case *protobufs.TokenRequest_Split:
		return []string{fmt.Sprintf("split-%x", t.Split.OfCoin.Address)}
	case *protobufs.TokenRequest_Merge:
		identifiers := make([]string, len(t.Merge.Coins))
		for i, coin := range t.Merge.Coins {
			identifiers[i] = fmt.Sprintf("merge-%x", coin.Address)
		}
		return identifiers
	case *protobufs.TokenRequest_Mint:
		if len(t.Mint.Proofs) == 1 {
			return []string{fmt.Sprintf("mint-proof-%x", sha3.Sum512(t.Mint.Proofs[0]))}
		} else if len(t.Mint.Proofs) >= 3 {
			frameNumber := binary.BigEndian.Uint64(t.Mint.Proofs[2])
			return []string{fmt.Sprintf("mint-sign-%d-%x", frameNumber, t.Mint.Signature.PublicKey.KeyValue)}
		}
		return []string{fmt.Sprintf("mint-sign-%x", t.Mint.Signature.PublicKey.KeyValue)}
	case *protobufs.TokenRequest_Announce:
		identifiers := make([]string, len(t.Announce.GetPublicKeySignaturesEd448()))
		for i, sig := range t.Announce.GetPublicKeySignaturesEd448() {
			identifiers[i] = fmt.Sprintf("announce-%x", sig.PublicKey.KeyValue)
		}
		return identifiers
	case *protobufs.TokenRequest_Join:
		return []string{fmt.Sprintf("join-%x", t.Join.GetPublicKeySignatureEd448().PublicKey.KeyValue)}
	case *protobufs.TokenRequest_Leave:
		return []string{fmt.Sprintf("leave-%x", t.Leave.GetPublicKeySignatureEd448().PublicKey.KeyValue)}
	case *protobufs.TokenRequest_Pause:
		return []string{fmt.Sprintf("pause-%x", t.Pause.GetPublicKeySignatureEd448().PublicKey.KeyValue)}
	case *protobufs.TokenRequest_Resume:
		return []string{fmt.Sprintf("resume-%x", t.Resume.GetPublicKeySignatureEd448().PublicKey.KeyValue)}
	default:
		utils.GetLogger().Panic("unhandled token request type",
			zap.String("transitionRequestType", fmt.Sprintf("%T", t)))
		panic("unhandled token request type")
	}
}

func (e *DataClockConsensusEngine) handleTokenRequest(
	transition *protobufs.TokenRequest,
) error {
	if e.FrameProverTrieContains(0, e.provingKeyAddress) {
		identifiers := TokenRequestIdentifiers(transition)

		e.stagedTransactionsMx.Lock()
		if e.stagedTransactions == nil {
			e.stagedTransactions = &protobufs.TokenRequests{}
			e.stagedTransactionsSet = make(map[string]struct{})
		}

		var found bool
		for _, identifier := range identifiers {
			if _, ok := e.stagedTransactionsSet[identifier]; ok {
				found = true
				break
			}
		}

		if !found {
			e.stagedTransactions.Requests = append(
				e.stagedTransactions.Requests,
				transition,
			)
			for _, identifier := range identifiers {
				e.stagedTransactionsSet[identifier] = struct{}{}
			}
		}
		e.stagedTransactionsMx.Unlock()
	}
	return nil
}

func nearestApplicablePowerOfTwo(number uint64) uint64 {
	power := uint64(128)
	if number > 2048 {
		power = 65536
	} else if number > 1024 {
		power = 2048
	} else if number > 128 {
		power = 1024
	}
	return power
}
