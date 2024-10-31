package data

import (
	"encoding/binary"
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

func (e *DataClockConsensusEngine) handleMessage(
	message *pb.Message,
) error {
	go func() {
		e.messageProcessorCh <- message
	}()

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
	msg := binary.BigEndian.AppendUint64([]byte{}, frame.FrameNumber)
	msg = append(msg, config.GetVersion()...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(timestamp))
	sig, err := e.pubSub.SignMessage(msg)
	if err != nil {
		panic(err)
	}

	e.peerMapMx.Lock()
	e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
		peerId:    e.pubSub.GetPeerID(),
		multiaddr: "",
		maxFrame:  frame.FrameNumber,
		version:   config.GetVersion(),
		signature: sig,
		publicKey: e.pubSub.GetPublicKey(),
		timestamp: timestamp,
		totalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
			make([]byte, 256),
		),
	}
	list := &protobufs.DataPeerListAnnounce{
		PeerList: []*protobufs.DataPeer{},
	}
	list.PeerList = append(list.PeerList, &protobufs.DataPeer{
		PeerId:    e.pubSub.GetPeerID(),
		Multiaddr: "",
		MaxFrame:  frame.FrameNumber,
		Version:   config.GetVersion(),
		Signature: sig,
		PublicKey: e.pubSub.GetPublicKey(),
		Timestamp: timestamp,
		TotalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
			make([]byte, 256),
		),
	})
	e.peerMapMx.Unlock()
	if err := e.publishMessage(e.filter, list); err != nil {
		e.logger.Debug("error publishing message", zap.Error(err))
	}

	e.publishMessage(e.filter, frame)

	return nil
}

func (e *DataClockConsensusEngine) insertMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
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

	go func() {
		e.messageProcessorCh <- m
	}()

	return nil
}

func (e *DataClockConsensusEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
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
