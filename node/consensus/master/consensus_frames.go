package master

import (
	"bytes"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if bytes.Equal(e.pubSub.GetPeerID(), []byte(e.beacon)) {
		e.logger.Debug("proving new frame")
		e.collectedProverSlotsMx.Lock()
		collectedProverSlots := e.collectedProverSlots
		e.collectedProverSlots = []*protobufs.InclusionAggregateProof{}
		e.collectedProverSlotsMx.Unlock()

		frame, err := e.frameProver.ProveMasterClockFrame(
			previousFrame,
			time.Now().UnixMilli(),
			e.difficulty,
			collectedProverSlots,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		e.state = consensus.EngineStatePublishing
		e.logger.Debug("returning new proven frame")
		return frame, nil
	}

	return previousFrame, nil
}

func (e *MasterClockConsensusEngine) GetMostAheadPeers() (
	[][]byte,
	error,
) {
	frame, err := e.masterTimeReel.Head()
	if err != nil {
		e.logger.Panic("failed to get head", zap.Error(err))
	}

	// Needs to be enough to make the sync worthwhile:
	max := frame.FrameNumber + 10

	var peers [][]byte = [][]byte{}
	peerMap := e.peerInfoManager.GetPeerMap()
	for peerId, v := range peerMap {
		if v.MasterHeadFrame > max {
			peers = append(peers, []byte(peerId))
		}

		if len(peers) >= 30 {
			break
		}
	}

	if len(peers) == 0 {
		return nil, p2p.ErrNoPeersAvailable
	}

	return peers, nil
}

func (e *MasterClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	latest, err := e.masterTimeReel.Head()
	if err != nil {
		e.logger.Panic("failed to get head", zap.Error(err))
	}

	return latest, nil
}
