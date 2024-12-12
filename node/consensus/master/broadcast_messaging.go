package master

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) handleMessage(message *pb.Message) error {
	e.logger.Debug(
		"received message",
		zap.Binary("data", message.Data),
		zap.Binary("from", message.From),
		zap.Binary("signature", message.Signature),
	)
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return errors.Wrap(err, "handle message")
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle message")
	}

	return errors.Wrap(errors.New("invalid message"), "handle message")
}

func (e *MasterClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	any *anypb.Any,
) error {
	if !bytes.Equal(peerID, []byte(e.beacon)) {
		return nil
	}

	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	head, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	if frame.FrameNumber < head.FrameNumber {
		return nil
	}

	if e.difficulty != frame.Difficulty {
		e.logger.Debug(
			"frame difficulty mismatched",
			zap.Uint32("difficulty", frame.Difficulty),
		)
		return errors.Wrap(
			errors.New("frame difficulty"),
			"handle clock frame data",
		)
	}

	e.logger.Debug(
		"got clock frame",
		zap.Binary("sender", peerID),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	go func() {
		select {
		case e.frameValidationCh <- frame:
		default:
			e.logger.Debug(
				"dropped frame due to overwhelmed queue",
				zap.Binary("sender", peerID),
				zap.Binary("filter", frame.Filter),
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Int("proof_count", len(frame.AggregateProofs)),
			)
		}
	}()

	return nil
}

func (e *MasterClockConsensusEngine) handleSelfTestReport(
	peerID []byte,
	any *anypb.Any,
) error {
	report := &protobufs.SelfTestReport{}
	if err := any.UnmarshalTo(report); err != nil {
		return errors.Wrap(err, "handle self test report")
	}

	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		info := e.peerInfoManager.GetPeerInfo(peerID)
		info.LastSeen = time.Now().UnixMilli()
		info.MasterHeadFrame = report.MasterHeadFrame
		return nil
	}

	info := e.peerInfoManager.GetPeerInfo(peerID)
	if info != nil {
		if (time.Now().UnixMilli() - info.LastSeen) < (270 * 1000) {
			return nil
		}
	}

	e.addPeerManifestReport(peerID, report)

	memory := binary.BigEndian.Uint64(report.Memory)
	e.logger.Debug(
		"received self test report",
		zap.String("peer_id", base58.Encode(peerID)),
		zap.Uint32("cores", report.Cores),
		zap.Uint64("memory", memory),
		zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
	)

	if report.Cores < 3 || memory < 16000000000 {
		e.logger.Debug(
			"peer reported invalid configuration",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Uint32("cores", report.Cores),
			zap.Uint64("memory", memory),
			zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
		)

		e.pubSub.SetPeerScore(peerID, -1000)
		return nil
	}

	return nil
}

func (e *MasterClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	if bytes.Equal(e.pubSub.GetPeerID(), []byte(e.beacon)) {
		e.logger.Debug(
			"publishing frame",
			zap.Uint64("frame_number", frame.FrameNumber),
		)

		e.masterTimeReel.Insert(context.TODO(), frame)
	}

	e.state = consensus.EngineStateCollecting

	return nil
}

func (e *MasterClockConsensusEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	// annoying protobuf any hack
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
		Address: e.filter,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}
