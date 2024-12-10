package data

import (
	"crypto"
	"crypto/rand"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data/fragmentation"
	qruntime "source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
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

func (e *DataClockConsensusEngine) handleFrameFragmentMessage(
	message *pb.Message,
) error {
	select {
	case <-e.ctx.Done():
		return e.ctx.Err()
	case e.frameFragmentMessageProcessorCh <- message:
	default:
		e.logger.Warn("dropping frame fragment message")
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
	reachability := e.pubSub.Reachability()

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
		reachability: reachability,
	}
	e.peerMapMx.Unlock()

	cfg := e.config.Engine.FramePublish
	if cfg.BallastSize > 0 {
		frame = proto.Clone(frame).(*protobufs.ClockFrame)
		frame.Padding = make([]byte, cfg.BallastSize)
	}

	publishFragmented := func() error {
		var splitter fragmentation.ClockFrameSplitter
		switch cfg := cfg.Fragmentation; cfg.Algorithm {
		case "reed-solomon":
			var err error
			splitter, err = fragmentation.NewReedSolomonClockFrameSplitter(
				cfg.ReedSolomon.DataShards,
				cfg.ReedSolomon.ParityShards,
			)
			if err != nil {
				return errors.Wrap(err, "creating reed-solomon splitter")
			}
		default:
			return errors.Errorf("unsupported fragmentation algorithm: %s", cfg.Algorithm)
		}
		fragments, err := splitter.SplitClockFrame(frame)
		if err != nil {
			return errors.Wrap(err, "splitting clock frame")
		}
		mrand.Shuffle(len(fragments), func(i, j int) {
			fragments[i], fragments[j] = fragments[j], fragments[i]
		})
		sign := func(b []byte) ([]byte, error) {
			return e.provingKey.Sign(rand.Reader, b, crypto.Hash(0))
		}
		var wg sync.WaitGroup
		defer wg.Wait()
		throttle := make(chan struct{}, qruntime.WorkerCount(0, false))
		for _, fragment := range fragments {
			throttle <- struct{}{}
			wg.Add(1)
			go func(fragment *protobufs.ClockFrameFragment) {
				defer func() { <-throttle }()
				defer wg.Done()
				if err := fragment.SignED448(e.provingKeyBytes, sign); err != nil {
					e.logger.Error("error signing clock frame fragment", zap.Error(err))
					return
				}
				if err := e.publishMessage(e.frameFragmentFilter, fragment); err != nil {
					e.logger.Error("error publishing clock frame fragment", zap.Error(err))
				}
			}(fragment)
		}
		return nil
	}
	publishFull := func() error {
		if err := e.publishMessage(e.frameFilter, frame); err != nil {
			e.logger.Error("error publishing clock frame", zap.Error(err))
		}
		return nil
	}
	switch cfg.Mode {
	case "full":
		if err := publishFull(); err != nil {
			return err
		}
	case "fragmented":
		if err := publishFragmented(); err != nil {
			return err
		}
	case "dual":
		if err := publishFragmented(); err != nil {
			return err
		}
		if err := publishFull(); err != nil {
			return err
		}
	case "threshold":
		if proto.Size(frame) >= cfg.Threshold {
			if err := publishFragmented(); err != nil {
				return err
			}
		} else {
			if err := publishFull(); err != nil {
				return err
			}
		}
	default:
		return errors.Errorf("unsupported frame publish mode: %s", cfg.Mode)
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
			ExternallyReachable: reachability,
		},
	}
	if err := e.publishMessage(e.infoFilter, list); err != nil {
		e.logger.Debug("error publishing data peer list announce", zap.Error(err))
	}

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
