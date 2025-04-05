package master

import (
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) Sync(
	request *protobufs.SyncRequest,
	server protobufs.ValidationService_SyncServer,
) error {
	e.currentReceivingSyncPeersMx.Lock()
	if e.currentReceivingSyncPeers > 4 {
		e.currentReceivingSyncPeersMx.Unlock()

		e.logger.Debug("currently processing maximum sync requests, returning")
		return nil
	}
	e.currentReceivingSyncPeers++
	e.currentReceivingSyncPeersMx.Unlock()

	defer func() {
		e.currentReceivingSyncPeersMx.Lock()
		e.currentReceivingSyncPeers--
		e.currentReceivingSyncPeersMx.Unlock()
	}()

	from := request.FramesRequest.FromFrameNumber

	masterFrame, err := e.masterTimeReel.Head()
	if err != nil {
		e.logger.Panic("could not get master time reel head", zap.Error(err))
	}

	if masterFrame.FrameNumber < from {
		e.logger.Debug(
			"peer asked for undiscovered frame",
			zap.Uint64("frame_number", request.FramesRequest.FromFrameNumber),
		)

		return nil
	}

	to := request.FramesRequest.ToFrameNumber
	if to == 0 || to-request.FramesRequest.FromFrameNumber > 16 {
		to = request.FramesRequest.FromFrameNumber + 15
	}

	for {
		if int(to) > int(masterFrame.FrameNumber) {
			to = masterFrame.FrameNumber
		}

		e.logger.Debug(
			"sending response",
			zap.Uint64("from", from),
			zap.Uint64("to", to),
			zap.Uint64("total_frames", uint64(to-from+1)),
		)

		iter, err := e.clockStore.RangeMasterClockFrames(
			e.filter,
			from,
			to,
		)
		if err != nil {
			return errors.Wrap(err, "sync")
		}
		defer iter.Close()

		response := []*protobufs.ClockFrame{}

		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			if err != nil {
				return errors.Wrap(err, "sync")
			}

			response = append(response, frame)
		}

		if len(response) == 0 {
			return nil
		}

		if err := server.Send(&protobufs.SyncResponse{
			FramesResponse: &protobufs.ClockFramesResponse{
				Filter:          e.filter,
				FromFrameNumber: from,
				ToFrameNumber:   to,
				ClockFrames:     response,
			},
		}); err != nil {
			return errors.Wrap(err, "sync")
		}

		from = response[len(response)-1].FrameNumber + 1
		to = from + 15

		time.Sleep(1 * time.Second)
	}
}
