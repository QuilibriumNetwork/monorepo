package data

import (
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) validateFrameMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		e.logger.Debug("could not unmarshal message", zap.Error(err))
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		e.logger.Debug("could not unmarshal payload", zap.Error(err))
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.ClockFrameType:
		frame := &protobufs.ClockFrame{}
		if err := proto.Unmarshal(a.Value, frame); err != nil {
			e.logger.Debug("could not unmarshal frame", zap.Error(err))
			return p2p.ValidationResultReject
		}
		if ts := time.UnixMilli(frame.Timestamp); time.Since(ts) > time.Hour {
			e.logger.Debug("frame is too old", zap.Time("timestamp", ts))
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		e.logger.Debug("unknown message type", zap.String("type_url", a.TypeUrl))
		return p2p.ValidationResultReject
	}
}

func (e *DataClockConsensusEngine) validateTxMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		e.logger.Debug("could not unmarshal message", zap.Error(err))
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		e.logger.Debug("could not unmarshal payload", zap.Error(err))
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.TokenRequestType:
		tx := &protobufs.TokenRequest{}
		if err := proto.Unmarshal(a.Value, tx); err != nil {
			e.logger.Debug("could not unmarshal token request", zap.Error(err))
			return p2p.ValidationResultReject
		}
		if mint := tx.GetMint(); mint != nil {
			if len(mint.Proofs) < 3 {
				e.logger.Debug("mint request is missing proofs")
				return p2p.ValidationResultReject
			}
			if len(mint.Proofs[1]) != 4 {
				e.logger.Debug("mint request has invalid modulo")
				return p2p.ValidationResultReject
			}
			if len(mint.Proofs[2]) != 8 {
				e.logger.Debug("mint request has invalid frame number")
				return p2p.ValidationResultReject
			}
			head, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}
			if frameNumber := binary.BigEndian.Uint64(mint.Proofs[2]); frameNumber+10 < head.FrameNumber {
				e.logger.Debug("mint request is too old", zap.Uint64("frame_number", frameNumber))
				return p2p.ValidationResultIgnore
			}
		}
		if tx.Timestamp == 0 {
			// NOTE: The timestamp was added in later versions of the protocol,
			// and as such it is possible to receive requests without it.
			// We avoid logging due to this reason.
			return p2p.ValidationResultAccept
		}
		if ts := time.UnixMilli(tx.Timestamp); time.Since(ts) > 10*time.Minute {
			e.logger.Debug("token request is too old", zap.Time("timestamp", ts))
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		e.logger.Debug("unknown message type", zap.String("type_url", a.TypeUrl))
		return p2p.ValidationResultReject
	}
}

func (e *DataClockConsensusEngine) validateInfoMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		e.logger.Debug("could not unmarshal message", zap.Error(err))
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		e.logger.Debug("could not unmarshal payload", zap.Error(err))
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.DataPeerListAnnounceType:
		announce := &protobufs.DataPeerListAnnounce{}
		if err := proto.Unmarshal(a.Value, announce); err != nil {
			e.logger.Debug("could not unmarshal network info request", zap.Error(err))
			return p2p.ValidationResultReject
		}
		if announce.Peer == nil {
			e.logger.Debug("peer list announce is missing peer")
			return p2p.ValidationResultIgnore
		}
		if ts := time.UnixMilli(announce.Peer.Timestamp); time.Since(ts) > 10*time.Minute {
			e.logger.Debug("peer list announce is too old", zap.Time("timestamp", ts))
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		e.logger.Debug("unknown message type", zap.String("type_url", a.TypeUrl))
		return p2p.ValidationResultReject
	}
}
