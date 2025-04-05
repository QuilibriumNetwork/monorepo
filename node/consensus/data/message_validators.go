package data

import (
	"encoding/binary"
	"fmt"
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
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.ClockFrameType:
		frame := &protobufs.ClockFrame{}
		if err := proto.Unmarshal(a.Value, frame); err != nil {
			return p2p.ValidationResultReject
		}
		if ts := time.UnixMilli(frame.Timestamp); time.Since(ts) > 2*time.Minute {
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		return p2p.ValidationResultReject
	}
}

func (e *DataClockConsensusEngine) validateFrameFragmentMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.ClockFrameFragmentType:
		fragment := &protobufs.ClockFrameFragment{}
		if err := proto.Unmarshal(a.Value, fragment); err != nil {
			return p2p.ValidationResultReject
		}
		if err := fragment.Validate(); err != nil {
			return p2p.ValidationResultReject
		}
		if ts := time.UnixMilli(fragment.Timestamp); time.Since(ts) > 2*time.Minute {
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		return p2p.ValidationResultReject
	}
}

func (e *DataClockConsensusEngine) validateTxMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.TokenRequestType:
		tx := &protobufs.TokenRequest{}
		if err := proto.Unmarshal(a.Value, tx); err != nil {
			return p2p.ValidationResultReject
		}
		if err := tx.Validate(); err != nil {
			return p2p.ValidationResultReject
		}
		if mint := tx.GetMint(); mint != nil {
			if len(mint.Proofs) < 3 {
				return p2p.ValidationResultReject
			}
			if len(mint.Proofs[1]) != 4 {
				return p2p.ValidationResultReject
			}
			if len(mint.Proofs[2]) != 8 {
				return p2p.ValidationResultReject
			}

			// cheap hack for handling protobuf trickery: because protobufs can be
			// serialized in infinite ways, message ids can be regenerated simply by
			// modifying the data without affecting the underlying signed message.
			// if this is encountered, go scorched earth on the sender – a thank you
			// message for destabilizing the network.
			frameNumber := binary.BigEndian.Uint64(mint.Proofs[2])
			id := fmt.Sprintf(
				"mint-sign-%d-%x",
				frameNumber,
				mint.Signature.PublicKey.KeyValue,
			)
			e.validationFilterMx.Lock()
			_, ok := e.validationFilter[id]
			e.validationFilter[id] = struct{}{}
			e.validationFilterMx.Unlock()
			if ok {
				e.pubSub.AddPeerScore(message.From, -1000000)
				return p2p.ValidationResultIgnore
			}

			head, err := e.dataTimeReel.Head()
			if err != nil {
				e.logger.Panic("failed to get head", zap.Error(err))
			}
			if frameNumber+1 < head.FrameNumber {
				return p2p.ValidationResultIgnore
			}
		}
		if ts := time.UnixMilli(tx.Timestamp); time.Since(ts) > 10*time.Minute {
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		return p2p.ValidationResultReject
	}
}

func (e *DataClockConsensusEngine) validateInfoMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.DataPeerListAnnounceType:
		announce := &protobufs.DataPeerListAnnounce{}
		if err := proto.Unmarshal(a.Value, announce); err != nil {
			return p2p.ValidationResultReject
		}
		if announce.Peer == nil {
			return p2p.ValidationResultIgnore
		}
		if ts := time.UnixMilli(announce.Peer.Timestamp); time.Since(ts) > 10*time.Minute {
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		return p2p.ValidationResultReject
	}
}
