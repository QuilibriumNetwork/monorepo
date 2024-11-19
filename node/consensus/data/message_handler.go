package data

import (
	"bytes"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) runFrameMessageHandler() {
	for e.GetState() < consensus.EngineStateStopping {
		select {
		case message := <-e.frameMessageProcessorCh:
			e.logger.Debug("handling frame message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("bad message")
				continue
			}

			any := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, any); err != nil {
				e.logger.Error("error while unmarshaling", zap.Error(err))
				continue
			}

			accepted := false
			switch any.TypeUrl {
			//expand for future message types
			case protobufs.ClockFrameType:
				accepted = true
			default:
			}

			if !accepted {
				e.pubSub.AddPeerScore(message.From, -100000)
				continue
			}

			go func() {
				switch any.TypeUrl {
				case protobufs.ClockFrameType:
					if err := e.handleClockFrameData(
						message.From,
						msg.Address,
						any,
						false,
					); err != nil {
						return
					}
				}
			}()
		}
	}
}

func (e *DataClockConsensusEngine) runTxMessageHandler() {
	for e.GetState() < consensus.EngineStateStopping {
		select {
		case message := <-e.txMessageProcessorCh:
			e.logger.Debug("handling tx message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("bad message")
				continue
			}

			any := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, any); err != nil {
				continue
			}

			accepted := false
			switch any.TypeUrl {
			//expand for future message types
			case protobufs.TokenRequestType:
				accepted = true
			default:
			}

			if !accepted {
				e.pubSub.AddPeerScore(message.From, -100000)
				continue
			}

			if e.frameProverTries[0].Contains(e.provingKeyAddress) {
				for name := range e.executionEngines {
					name := name
					go func() error {
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
							appMsg := &anypb.Any{}
							err := proto.Unmarshal(appMessage.Payload, appMsg)
							if err != nil {
								e.logger.Error(
									"could not unmarshal app message",
									zap.Error(err),
									zap.String("engine_name", name),
								)
								continue
							}

							e.logger.Debug(appMsg.TypeUrl)

							switch appMsg.TypeUrl {
							case protobufs.TokenRequestType:
								t := &protobufs.TokenRequest{}
								err := proto.Unmarshal(appMsg.Value, t)
								if err != nil {
									continue
								}

								if err := e.handleTokenRequest(t); err != nil {
									continue
								}
							}
						}

						return nil
					}()
				}
			}
		}
	}
}

func (e *DataClockConsensusEngine) runInfoMessageHandler() {
	for e.GetState() < consensus.EngineStateStopping {
		select {
		case message := <-e.infoMessageProcessorCh:
			e.logger.Debug("handling info message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("bad message")
				continue
			}

			any := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, any); err != nil {
				e.logger.Error("error while unmarshaling", zap.Error(err))
				continue
			}

			accepted := false
			switch any.TypeUrl {
			//expand for future message types
			case protobufs.DataPeerListAnnounceType:
				accepted = true
			default:
			}

			if !accepted {
				e.pubSub.AddPeerScore(message.From, -100000)
				continue
			}

			go func() {
				switch any.TypeUrl {
				case protobufs.DataPeerListAnnounceType:
					if err := e.handleDataPeerListAnnounce(
						message.From,
						msg.Address,
						any,
					); err != nil {
						return
					}
				}
			}()
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

	trie := e.GetFrameProverTries()[0]
	if !trie.Contains(addr.FillBytes(make([]byte, 32))) {
		e.logger.Debug(
			"prover not in trie at frame, address may be in fork",
			zap.Binary("address", address),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		return nil
	}

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
		panic(err)
	}

	if frame.FrameNumber > head.FrameNumber {
		e.dataTimeReel.Insert(frame, false)
	}

	return nil
}

func (e *DataClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	address []byte,
	any *anypb.Any,
	isSync bool,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	return e.handleClockFrame(peerID, address, frame)
}

func (e *DataClockConsensusEngine) handleDataPeerListAnnounce(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	announce := &protobufs.DataPeerListAnnounce{}
	if err := any.UnmarshalTo(announce); err != nil {
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

	if p.Version != nil &&
		bytes.Compare(p.Version, config.GetMinimumVersion()) < 0 &&
		p.Timestamp > config.GetMinimumVersionCutoff().UnixMilli() {
		e.logger.Debug(
			"peer provided outdated version, penalizing app score",
			zap.String("peer_id", peer.ID(peerID).String()),
		)
		e.pubSub.SetPeerScore(peerID, -1000000)
		return nil
	}

	e.peerMapMx.RLock()
	if _, ok := e.uncooperativePeersMap[string(peerID)]; ok {
		e.peerMapMx.RUnlock()
		return nil
	}
	e.peerMapMx.RUnlock()

	e.pubSub.SetPeerScore(peerID, 10)

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
		totalDistance: p.TotalDistance,
	}
	e.peerMapMx.Unlock()

	select {
	case <-e.ctx.Done():
		return nil
	case e.requestSyncCh <- nil:
	default:
	}

	return nil
}

func (e *DataClockConsensusEngine) handleTokenRequest(
	transition *protobufs.TokenRequest,
) error {
	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
		e.stagedTransactionsMx.Lock()
		if e.stagedTransactions == nil {
			e.stagedTransactions = &protobufs.TokenRequests{}
		}

		found := false
		for _, ti := range e.stagedTransactions.Requests {
			switch t := ti.Request.(type) {
			case *protobufs.TokenRequest_Transfer:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Transfer:
					if bytes.Equal(r.Transfer.OfCoin.Address, t.Transfer.OfCoin.Address) {
						found = true
					}
				}
			case *protobufs.TokenRequest_Split:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Split:
					if bytes.Equal(r.Split.OfCoin.Address, r.Split.OfCoin.Address) {
						found = true
					}
				}
			case *protobufs.TokenRequest_Merge:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Merge:
				checkmerge:
					for i := range t.Merge.Coins {
						for j := range r.Merge.Coins {
							if bytes.Equal(t.Merge.Coins[i].Address, r.Merge.Coins[j].Address) {
								found = true
								break checkmerge
							}
						}
					}
				}
			case *protobufs.TokenRequest_Mint:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Mint:
				checkmint:
					for i := range t.Mint.Proofs {
						if len(r.Mint.Proofs) < 2 {
							for j := range r.Mint.Proofs {
								if bytes.Equal(t.Mint.Proofs[i], r.Mint.Proofs[j]) {
									found = true
									break checkmint
								}
							}
						}
					}
				}
			case *protobufs.TokenRequest_Announce:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Announce:
				checkannounce:
					for i := range t.Announce.GetPublicKeySignaturesEd448() {
						for j := range r.Announce.GetPublicKeySignaturesEd448() {
							if bytes.Equal(
								t.Announce.GetPublicKeySignaturesEd448()[i].PublicKey.KeyValue,
								r.Announce.GetPublicKeySignaturesEd448()[j].PublicKey.KeyValue,
							) {
								found = true
								break checkannounce
							}
						}
					}
				}
			case *protobufs.TokenRequest_Join:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Join:
					if bytes.Equal(
						t.Join.GetPublicKeySignatureEd448().PublicKey.KeyValue,
						r.Join.GetPublicKeySignatureEd448().PublicKey.KeyValue,
					) {
						found = true
					}
				}
			case *protobufs.TokenRequest_Leave:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Leave:
					if bytes.Equal(
						t.Leave.GetPublicKeySignatureEd448().PublicKey.KeyValue,
						r.Leave.GetPublicKeySignatureEd448().PublicKey.KeyValue,
					) {
						found = true
					}
				}
			case *protobufs.TokenRequest_Pause:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Pause:
					if bytes.Equal(
						t.Pause.GetPublicKeySignatureEd448().PublicKey.KeyValue,
						r.Pause.GetPublicKeySignatureEd448().PublicKey.KeyValue,
					) {
						found = true
					}
				}
			case *protobufs.TokenRequest_Resume:
				switch r := transition.Request.(type) {
				case *protobufs.TokenRequest_Resume:
					if bytes.Equal(
						t.Resume.GetPublicKeySignatureEd448().PublicKey.KeyValue,
						r.Resume.GetPublicKeySignatureEd448().PublicKey.KeyValue,
					) {
						found = true
					}
				}
			}
		}

		if !found {
			e.stagedTransactions.Requests = append(
				e.stagedTransactions.Requests,
				transition,
			)
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
