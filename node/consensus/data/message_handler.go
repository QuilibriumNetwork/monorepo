package data

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) runMessageHandler() {
	for {
		select {
		case message := <-e.messageProcessorCh:
			e.logger.Debug("handling message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				e.logger.Debug("bad message")
				continue
			}

			if e.frameProverTries[0].Contains(e.provingKeyAddress) &&
				e.syncingStatus == SyncStatusNotSyncing {
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

			any := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, any); err != nil {
				e.logger.Error("error while unmarshaling", zap.Error(err))
				continue
			}
			e.logger.Debug("message type", zap.String("type", any.TypeUrl))

			go func() {
				switch any.TypeUrl {
				case protobufs.FrameRebroadcastType:
					if err := e.handleRebroadcast(
						message.From,
						msg.Address,
						any,
					); err != nil {
						return
					}
				case protobufs.ClockFrameType:
					if err := e.handleClockFrameData(
						message.From,
						msg.Address,
						any,
						false,
					); err != nil {
						return
					}
				case protobufs.DataPeerListAnnounceType:
					if err := e.handleDataPeerListAnnounce(
						message.From,
						msg.Address,
						any,
					); err != nil {
						return
					}
				// case protobufs.AnnounceProverJoinType:
				// 	if err := e.handleDataAnnounceProverJoin(
				// 		message.From,
				// 		msg.Address,
				// 		any,
				// 	); err != nil {
				// 		return
				// 	}
				// case protobufs.AnnounceProverLeaveType:
				// 	if !e.IsInProverTrie(peer.peerId) {
				// 		return
				// 	}
				// 	if err := e.handleDataAnnounceProverLeave(
				// 		message.From,
				// 		msg.Address,
				// 		any,
				// 	); err != nil {
				// 		return
				// 	}
				case protobufs.AnnounceProverPauseType:
					// stop spamming
					e.pubSub.AddPeerScore(message.From, -1000)
				// 	if err := e.handleDataAnnounceProverPause(
				// 		message.From,
				// 		msg.Address,
				// 		any,
				// 	); err != nil {
				// 		return
				// 	}
				case protobufs.AnnounceProverResumeType:
					// stop spamming
					e.pubSub.AddPeerScore(message.From, -1000)
					// 	if err := e.handleDataAnnounceProverResume(
					// 		message.From,
					// 		msg.Address,
					// 		any,
					// 	); err != nil {
					// 		return
					// 	}
				}
			}()
		}
	}
}

func (e *DataClockConsensusEngine) handleRebroadcast(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	frames := &protobufs.FrameRebroadcast{}
	if err := any.UnmarshalTo(frames); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	head, err := e.dataTimeReel.Head()
	if err != nil {
		return nil
	}

	e.logger.Debug(
		"received rebroadcast",
		zap.Uint64("from", frames.From),
		zap.Uint64("to", frames.To),
	)
	if head.FrameNumber+1 < frames.From {
		return nil
	}

	if head.FrameNumber > frames.To {
		return nil
	}

	for _, frame := range frames.ClockFrames {
		if head.FrameNumber >= frame.FrameNumber {
			continue
		}

		e.logger.Info("receiving synchronization data")

		if err := e.handleClockFrame(peerID, address, frame); err != nil {
			// if they're sending invalid clock frames, nuke them.
			e.pubSub.AddPeerScore(peerID, -100000)
			return errors.Wrap(err, "handle rebroadcast")
		}
	}

	return nil
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
	if !trie.Contains(addr.Bytes()) {
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
	announce := &protobufs.DataPeerListAnnounce{}
	if err := any.UnmarshalTo(announce); err != nil {
		return errors.Wrap(err, "handle data peer list announce")
	}

	for _, p := range announce.PeerList {
		if bytes.Equal(p.PeerId, e.pubSub.GetPeerID()) {
			continue
		}

		if !bytes.Equal(p.PeerId, peerID) {
			continue
		}

		if p.PublicKey == nil || p.Signature == nil || p.Version == nil {
			continue
		}

		if p.PublicKey != nil && p.Signature != nil && p.Version != nil {
			key, err := pcrypto.UnmarshalEd448PublicKey(p.PublicKey)
			if err != nil {
				e.logger.Warn(
					"peer announcement contained invalid pubkey",
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			if !(peer.ID(p.PeerId)).MatchesPublicKey(key) {
				e.logger.Warn(
					"peer announcement peer id does not match pubkey",
					zap.Binary("peer_id", p.PeerId),
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			msg := binary.BigEndian.AppendUint64([]byte{}, p.MaxFrame)
			msg = append(msg, p.Version...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(p.Timestamp))
			b, err := key.Verify(msg, p.Signature)
			if err != nil || !b {
				e.logger.Warn(
					"peer provided invalid signature",
					zap.Binary("msg", msg),
					zap.Binary("public_key", p.PublicKey),
					zap.Binary("signature", p.Signature),
				)
				continue
			}

			if bytes.Compare(p.Version, config.GetMinimumVersion()) < 0 &&
				p.Timestamp > config.GetMinimumVersionCutoff().UnixMilli() {
				e.logger.Debug(
					"peer provided outdated version, penalizing app score",
					zap.Binary("peer_id", p.PeerId),
				)
				e.pubSub.SetPeerScore(p.PeerId, -1000000)
				continue
			}
		}

		e.peerMapMx.RLock()
		if _, ok := e.uncooperativePeersMap[string(p.PeerId)]; ok {
			e.peerMapMx.RUnlock()
			continue
		}
		e.peerMapMx.RUnlock()

		multiaddr := e.pubSub.GetMultiaddrOfPeer(p.PeerId)

		e.pubSub.SetPeerScore(p.PeerId, 10)

		e.peerMapMx.RLock()
		existing, ok := e.peerMap[string(p.PeerId)]
		e.peerMapMx.RUnlock()

		if ok {
			if existing.signature != nil && p.Signature == nil {
				continue
			}

			if existing.publicKey != nil && p.PublicKey == nil {
				continue
			}

			if existing.version != nil && p.Version == nil {
				continue
			}

			if existing.timestamp > p.Timestamp {
				continue
			}
		}

		e.peerMapMx.Lock()
		e.peerMap[string(p.PeerId)] = &peerInfo{
			peerId:        p.PeerId,
			multiaddr:     multiaddr,
			maxFrame:      p.MaxFrame,
			direct:        bytes.Equal(p.PeerId, peerID),
			lastSeen:      time.Now().Unix(),
			timestamp:     p.Timestamp,
			version:       p.Version,
			signature:     p.Signature,
			publicKey:     p.PublicKey,
			totalDistance: p.TotalDistance,
		}
		e.peerMapMx.Unlock()
	}
	return nil
}

func (e *DataClockConsensusEngine) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}
	addrBI, err := poseidon.HashBytes(sig.PublicKey.KeyValue)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return addrBI.FillBytes(make([]byte, 32)), nil
}

// func (e *DataClockConsensusEngine) handleDataAnnounceProverJoin(
// 	peerID []byte,
// 	address []byte,
// 	any *anypb.Any,
// ) error {
// 	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
// 		announce := &protobufs.AnnounceProverJoin{}
// 		if err := any.UnmarshalTo(announce); err != nil {
// 			return errors.Wrap(err, "handle data announce prover join")
// 		}

// 		if announce.PublicKeySignatureEd448 == nil || announce.Filter == nil {
// 			return errors.Wrap(
// 				errors.New("invalid data"),
// 				"handle data announce prover join",
// 			)
// 		}

// 		address, err := e.getAddressFromSignature(announce.PublicKeySignatureEd448)
// 		if err != nil {
// 			return errors.Wrap(err, "handle data announce prover join")
// 		}

// 		msg := []byte("join")
// 		msg = binary.BigEndian.AppendUint64(msg, announce.FrameNumber)
// 		msg = append(msg, announce.Filter...)
// 		if err := announce.GetPublicKeySignatureEd448().Verify(msg); err != nil {
// 			return errors.Wrap(err, "handle data announce prover join")
// 		}

// 		e.proverTrieRequestsMx.Lock()
// 		if len(announce.Filter) != len(e.filter) {
// 			return errors.Wrap(
// 				errors.New("filter width mismatch"),
// 				"handle data announce prover join",
// 			)
// 		}

// 		e.proverTrieJoinRequests[string(address)] = string(announce.Filter)
// 		e.proverTrieRequestsMx.Unlock()
// 	}
// 	return nil
// }

// func (e *DataClockConsensusEngine) handleDataAnnounceProverLeave(
// 	peerID []byte,
// 	address []byte,
// 	any *anypb.Any,
// ) error {
// 	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
// 		announce := &protobufs.AnnounceProverLeave{}
// 		if err := any.UnmarshalTo(announce); err != nil {
// 			return errors.Wrap(err, "handle data announce prover leave")
// 		}

// 		if announce.PublicKeySignatureEd448 == nil || announce.Filter == nil {
// 			return errors.Wrap(
// 				errors.New("invalid data"),
// 				"handle data announce prover leave",
// 			)
// 		}

// 		e.proverTrieRequestsMx.Lock()

// 		if len(announce.Filter) != len(e.filter) {
// 			return errors.Wrap(
// 				errors.New("filter width mismatch"),
// 				"handle data announce prover leave",
// 			)
// 		}

// 		msg := []byte("leave")
// 		msg = binary.BigEndian.AppendUint64(msg, announce.FrameNumber)
// 		msg = append(msg, announce.Filter...)
// 		if err := announce.GetPublicKeySignatureEd448().Verify(msg); err != nil {
// 			return errors.Wrap(err, "handle data announce prover leave")
// 		}

// 		address, err := e.getAddressFromSignature(announce.PublicKeySignatureEd448)
// 		if err != nil {
// 			return errors.Wrap(err, "handle data announce prover leave")
// 		}

// 		e.proverTrieLeaveRequests[string(address)] = string(announce.Filter)
// 		e.proverTrieRequestsMx.Unlock()
// 	}
// 	return nil
// }

// func (e *DataClockConsensusEngine) handleDataAnnounceProverPause(
// 	peerID []byte,
// 	address []byte,
// 	any *anypb.Any,
// ) error {
// 	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
// 		announce := &protobufs.AnnounceProverPause{}
// 		if err := any.UnmarshalTo(announce); err != nil {
// 			return errors.Wrap(err, "handle data announce prover pause")
// 		}

// 		if announce.PublicKeySignatureEd448 == nil || announce.Filter == nil {
// 			return errors.Wrap(
// 				errors.New("invalid data"),
// 				"handle data announce prover leave",
// 			)
// 		}

// 		e.proverTrieRequestsMx.Lock()
// 		if len(announce.Filter) != len(e.filter) {
// 			return errors.Wrap(
// 				errors.New("filter width mismatch"),
// 				"handle data announce prover pause",
// 			)
// 		}

// 		msg := []byte("pause")
// 		msg = binary.BigEndian.AppendUint64(msg, announce.FrameNumber)
// 		msg = append(msg, announce.Filter...)
// 		if err := announce.GetPublicKeySignatureEd448().Verify(msg); err != nil {
// 			return errors.Wrap(err, "handle data announce prover pause")
// 		}

// 		address, err := e.getAddressFromSignature(announce.PublicKeySignatureEd448)
// 		if err != nil {
// 			return errors.Wrap(err, "handle data announce prover pause")
// 		}

// 		e.proverTriePauseRequests[string(address)] = string(announce.Filter)
// 		e.proverTrieRequestsMx.Unlock()
// 	}
// 	return nil
// }

// func (e *DataClockConsensusEngine) handleDataAnnounceProverResume(
// 	peerID []byte,
// 	address []byte,
// 	any *anypb.Any,
// ) error {
// 	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
// 		announce := &protobufs.AnnounceProverResume{}
// 		if err := any.UnmarshalTo(announce); err != nil {
// 			return errors.Wrap(err, "handle data announce prover resume")
// 		}

// 		if announce.PublicKeySignatureEd448 == nil || announce.Filter == nil {
// 			return errors.Wrap(
// 				errors.New("invalid data"),
// 				"handle data announce prover resume",
// 			)
// 		}

// 		e.proverTrieRequestsMx.Lock()
// 		if len(announce.Filter) != len(e.filter) {
// 			return errors.Wrap(
// 				errors.New("filter width mismatch"),
// 				"handle data announce prover resume",
// 			)
// 		}

// 		address, err := e.getAddressFromSignature(announce.PublicKeySignatureEd448)
// 		if err != nil {
// 			return errors.Wrap(err, "handle data announce prover resume")
// 		}

// 		msg := []byte("resume")
// 		msg = binary.BigEndian.AppendUint64(msg, announce.FrameNumber)
// 		msg = append(msg, announce.Filter...)
// 		if err := announce.GetPublicKeySignatureEd448().Verify(msg); err != nil {
// 			return errors.Wrap(err, "handle data announce prover resume")
// 		}

// 		e.proverTrieResumeRequests[string(address)] = string(announce.Filter)
// 		e.proverTrieRequestsMx.Unlock()
// 	}
// 	return nil
// }

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
