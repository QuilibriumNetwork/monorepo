package data

import (
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) handleFrameMessage(
	message *pb.Message,
) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.frameMessageProcessorCh <- message:
	default:
		e.logger.Warn("dropping frame message")
	}
	return nil
}

func (e *DataClockConsensusEngine) handleTxMessage(
	message *pb.Message,
) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.txMessageProcessorCh <- message:
	default:
		e.logger.Warn("dropping tx message")
	}
	return nil
}

func (e *DataClockConsensusEngine) handleInfoMessage(
	message *pb.Message,
) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.infoMessageProcessorCh <- message:
	default:
		e.logger.Warn("dropping info message")
	}
	return nil
}

func (e *DataClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	e.logger.Debug(
		"publishing frame and aggregations",
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	timestamp := time.Now().UnixMilli()

	e.peerMapMx.Lock()
	e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
		peerId:       e.pubSub.GetPeerID(),
		multiaddr:    "",
		maxFrame:     frame.FrameNumber,
		version:      config.GetVersion(),
		patchVersion: config.GetPatchNumber(),
		timestamp:    timestamp,
		totalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
			make([]byte, 256),
		),
	}
	list := &protobufs.DataPeerListAnnounce{
		Peer: &protobufs.DataPeer{
			PeerId:       nil,
			Multiaddr:    "",
			MaxFrame:     frame.FrameNumber,
			Version:      config.GetVersion(),
			PatchVersion: []byte{config.GetPatchNumber()},
			Timestamp:    timestamp,
			TotalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
				make([]byte, 256),
			),
		},
	}
	e.peerMapMx.Unlock()
	if err := e.publishMessage(e.infoFilter, list); err != nil {
		e.logger.Debug("error publishing message", zap.Error(err))
	}

	e.publishMessage(e.frameFilter, frame)

	return nil
}

func (e *DataClockConsensusEngine) insertTxMessage(
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: e.provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	m := &pb.Message{
		Data:    data,
		Bitmask: filter,
		From:    e.pubSub.GetPeerID(),
		Seqno:   nil,
	}

	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.txMessageProcessorCh <- m:
	default:
		e.logger.Warn("dropping tx message")
	}

	return nil
}

func (e *DataClockConsensusEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: e.provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}
