package time

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var unknownDistance = new(big.Int).SetBytes([]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})

// pendingFrame represents a frame that has been received but not yet processed
type pendingFrame struct {
	selector       *big.Int
	parentSelector *big.Int
	frameNumber    uint64
	distance       *big.Int // Store the distance for quick access
	done           chan struct{}
}

type DataTimeReel struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	filter       []byte
	engineConfig *config.EngineConfig
	logger       *zap.Logger
	clockStore   store.ClockStore
	frameProver  crypto.FrameProver
	exec         func(
		txn store.Transaction,
		frame *protobufs.ClockFrame,
		triesAtFrame []*tries.RollingFrecencyCritbitTrie,
	) (
		[]*tries.RollingFrecencyCritbitTrie,
		error,
	)

	origin                []byte
	initialInclusionProof *crypto.InclusionAggregateProof
	initialProverKeys     [][]byte
	head                  *protobufs.ClockFrame
	totalDistance         *big.Int
	headDistance          *big.Int
	lruFrames             *lru.Cache[string, string]
	proverTries           []*tries.RollingFrecencyCritbitTrie

	pending         map[uint64][]*pendingFrame
	childFrames     map[string][]*pendingFrame
	incompleteForks map[uint64][]*pendingFrame

	frames     chan *pendingFrame
	newFrameCh chan *protobufs.ClockFrame
	badFrameCh chan *protobufs.ClockFrame
	alwaysSend bool
}

func NewDataTimeReel(
	filter []byte,
	logger *zap.Logger,
	clockStore store.ClockStore,
	engineConfig *config.EngineConfig,
	frameProver crypto.FrameProver,
	exec func(
		txn store.Transaction,
		frame *protobufs.ClockFrame,
		triesAtFrame []*tries.RollingFrecencyCritbitTrie,
	) (
		[]*tries.RollingFrecencyCritbitTrie,
		error,
	),
	origin []byte,
	initialInclusionProof *crypto.InclusionAggregateProof,
	initialProverKeys [][]byte,
	alwaysSend bool,
) *DataTimeReel {
	if filter == nil {
		panic("filter is nil")
	}

	if logger == nil {
		panic("logger is nil")
	}

	if clockStore == nil {
		panic("clock store is nil")
	}

	if engineConfig == nil {
		panic("engine config is nil")
	}

	if exec == nil {
		panic("execution function is nil")
	}

	if frameProver == nil {
		panic("frame prover is nil")
	}

	cache, err := lru.New[string, string](10000)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &DataTimeReel{
		ctx:                   ctx,
		cancel:                cancel,
		logger:                logger.With(zap.String("stage", "data-time-reel")),
		filter:                filter,
		engineConfig:          engineConfig,
		clockStore:            clockStore,
		frameProver:           frameProver,
		exec:                  exec,
		origin:                origin,
		initialInclusionProof: initialInclusionProof,
		initialProverKeys:     initialProverKeys,
		lruFrames:             cache,
		pending:               make(map[uint64][]*pendingFrame),
		childFrames:           make(map[string][]*pendingFrame),
		incompleteForks:       make(map[uint64][]*pendingFrame),
		frames:                make(chan *pendingFrame, 65536),
		newFrameCh:            make(chan *protobufs.ClockFrame),
		badFrameCh:            make(chan *protobufs.ClockFrame),
		alwaysSend:            alwaysSend,
	}
}

func (d *DataTimeReel) createGenesisFrame() (
	*protobufs.ClockFrame,
	[]*tries.RollingFrecencyCritbitTrie,
) {
	if d.origin == nil {
		panic("origin is nil")
	}

	if d.initialInclusionProof == nil {
		panic("initial inclusion proof is nil")
	}

	if d.initialProverKeys == nil {
		panic("initial prover keys is nil")
	}
	difficulty := d.engineConfig.Difficulty
	if difficulty == 0 || difficulty == 10000 {
		difficulty = 200000
	}
	frame, tries, err := d.frameProver.CreateDataGenesisFrame(
		d.filter,
		d.origin,
		difficulty,
		d.initialInclusionProof,
		d.initialProverKeys,
	)
	if err != nil {
		panic(err)
	}
	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}
	txn, err := d.clockStore.NewTransaction(false)
	if err != nil {
		panic(err)
	}
	err = d.clockStore.StageDataClockFrame(
		selector.FillBytes(make([]byte, 32)),
		frame,
		txn,
	)
	if err != nil {
		txn.Abort()
		panic(err)
	}
	err = txn.Commit()
	if err != nil {
		txn.Abort()
		panic(err)
	}
	txn, err = d.clockStore.NewTransaction(false)
	if err != nil {
		panic(err)
	}
	if err := d.clockStore.CommitDataClockFrame(
		d.filter,
		0,
		selector.FillBytes(make([]byte, 32)),
		tries,
		txn,
		false,
	); err != nil {
		panic(err)
	}
	if err := txn.Commit(); err != nil {
		panic(err)
	}
	return frame, tries
}

func (d *DataTimeReel) Start() error {
	frame, tries, err := d.clockStore.GetLatestDataClockFrame(d.filter)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	if frame == nil {
		d.head, d.proverTries = d.createGenesisFrame()
		d.totalDistance = big.NewInt(0)
		d.headDistance = big.NewInt(0)
	} else {
		d.head = frame
		if err != nil {
			panic(err)
		}
		d.totalDistance = big.NewInt(0)
		d.proverTries = tries
		d.headDistance, err = d.GetDistance(frame)
	}

	d.wg.Add(1)
	go d.runLoop()

	return nil
}

// Insert enqueues a structurally valid frame into the time reel.
func (d *DataTimeReel) Insert(
	ctx context.Context,
	frame *protobufs.ClockFrame,
) (<-chan struct{}, error) {
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}

	d.logger.Info(
		"insert frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
	)

	// Check if we've already seen this frame
	if d.lruFrames.Contains(string(frame.Output[:64])) {
		return alreadyDone, nil
	}

	d.lruFrames.Add(string(frame.Output[:64]), string(frame.ParentSelector))

	parent := new(big.Int).SetBytes(frame.ParentSelector)
	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}

	distance, err := d.GetDistance(frame)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	d.storePending(selector, parent, distance, frame)

	parentHex := hex.EncodeToString(frame.ParentSelector)
	pendingFr := &pendingFrame{
		selector:       selector,
		parentSelector: parent,
		frameNumber:    frame.FrameNumber,
		distance:       distance,
	}

	d.childFrames[parentHex] = append(d.childFrames[parentHex], pendingFr)

	if d.head.FrameNumber < frame.FrameNumber {
		go d.setHead(frame, distance)

		d.addPending(selector, parent, frame.FrameNumber, distance)

		if d.head.FrameNumber+1 == frame.FrameNumber || d.canFillGap(frame) {
			done := make(chan struct{})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-d.ctx.Done():
				return nil, d.ctx.Err()
			case d.frames <- &pendingFrame{
				selector:       selector,
				parentSelector: parent,
				frameNumber:    frame.FrameNumber,
				distance:       distance,
				done:           done,
			}:
				return done, nil
			}
		}
	} else if d.head.FrameNumber == frame.FrameNumber {
		if !bytes.Equal(d.head.Output, frame.Output) {
			done := make(chan struct{})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-d.ctx.Done():
				return nil, d.ctx.Err()
			case d.frames <- &pendingFrame{
				selector:       selector,
				parentSelector: parent,
				frameNumber:    frame.FrameNumber,
				distance:       distance,
				done:           done,
			}:
				return done, nil
			}
		}
	}

	return alreadyDone, nil
}

func (d *DataTimeReel) canFillGap(frame *protobufs.ClockFrame) bool {
	if frame.FrameNumber <= d.head.FrameNumber+1 {
		return false
	}

	for f := d.head.FrameNumber + 1; f < frame.FrameNumber; f++ {
		if _, exists := d.pending[f]; !exists || len(d.pending[f]) == 0 {
			return false
		}
	}

	return true
}

func (d *DataTimeReel) addPending(
	selector *big.Int,
	parent *big.Int,
	frameNumber uint64,
	distance *big.Int,
) {
	d.logger.Info(
		"add pending",
		zap.Uint64("head_frame_number", d.head.FrameNumber),
		zap.Uint64("add_frame_number", frameNumber),
		zap.String("selector", selector.Text(16)),
		zap.String("parent", parent.Text(16)),
	)

	if d.head.FrameNumber <= frameNumber {
		if _, ok := d.pending[frameNumber]; !ok {
			d.pending[frameNumber] = []*pendingFrame{}
		}

		for _, frame := range d.pending[frameNumber] {
			if frame.selector.Cmp(selector) == 0 {
				d.logger.Info("exists in pending already")
				return
			}
		}

		d.logger.Info(
			"accumulate in pending",
			zap.Int("pending_neighbors", len(d.pending[frameNumber])),
		)

		d.pending[frameNumber] = append(
			d.pending[frameNumber],
			&pendingFrame{
				selector:       selector,
				parentSelector: parent,
				frameNumber:    frameNumber,
				distance:       distance,
			},
		)
	}
}

func (d *DataTimeReel) storePending(
	selector *big.Int,
	parent *big.Int,
	distance *big.Int,
	frame *protobufs.ClockFrame,
) {
	// Avoid DB thrashing by checking if we already have this frame
	existing, err := d.clockStore.GetStagedDataClockFrame(
		frame.Filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		true,
	)

	if err != nil && existing == nil {
		d.logger.Info(
			"not stored yet, save data candidate",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.String("selector", selector.Text(16)),
			zap.String("parent", parent.Text(16)),
			zap.String("distance", distance.Text(16)),
		)

		txn, err := d.clockStore.NewTransaction(false)
		if err != nil {
			d.logger.Panic("failed to create transaction", zap.Error(err))
		}
		err = d.clockStore.StageDataClockFrame(
			selector.FillBytes(make([]byte, 32)),
			frame,
			txn,
		)
		if err != nil {
			txn.Abort()
			d.logger.Panic("failed to stage data clock frame", zap.Error(err))
		}
		if err = txn.Commit(); err != nil {
			d.logger.Panic("failed to commit transaction", zap.Error(err))
		}
	}
}

// Main data consensus loop
func (d *DataTimeReel) runLoop() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case frame := <-d.frames:
			var frameDone chan struct{}
			if frame.done != nil {
				frameDone = frame.done
				frame.done = nil
			}

			rawFrame, err := d.clockStore.GetStagedDataClockFrame(
				d.filter,
				frame.frameNumber,
				frame.selector.FillBytes(make([]byte, 32)),
				false,
			)
			if err != nil {
				if frameDone != nil {
					close(frameDone)
				}
				d.logger.Panic("failed to get staged data clock frame", zap.Error(err))
			}

			d.logger.Info(
				"processing frame",
				zap.Uint64("frame_number", rawFrame.FrameNumber),
				zap.String("output_tag", hex.EncodeToString(rawFrame.Output[:64])),
				zap.Uint64("head_number", d.head.FrameNumber),
				zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
			)

			distance := frame.distance
			if distance == nil {
				var err error
				distance, err = d.GetDistance(rawFrame)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					if frameDone != nil {
						close(frameDone)
					}
					d.logger.Panic("failed to get distance", zap.Error(err))
				}
			}

			// Handle different scenarios based on frame number
			if d.head.FrameNumber < rawFrame.FrameNumber {
				d.logger.Info("frame is higher")

				// If there's a gap, try to fill it
				if rawFrame.FrameNumber > d.head.FrameNumber+1 {
					if d.tryFillGap(d.head.FrameNumber+1, rawFrame.FrameNumber-1) {
						// Gap was filled, now process this frame
						if err = d.validateAndSetHead(rawFrame, distance); err != nil {
							if frameDone != nil {
								close(frameDone)
							}
							continue
						}
					} else {
						// Couldn't fill gap, just add to pending
						d.processPending(d.head, frame)
						continue
					}
				} else if rawFrame.FrameNumber == d.head.FrameNumber+1 {
					// Direct next frame
					if err = d.validateAndSetHead(rawFrame, distance); err != nil {
						if frameDone != nil {
							close(frameDone)
						}
						continue
					}
				}

				// Process any pending frames that might now be valid
				d.processPending(d.head, frame)

			} else if d.head.FrameNumber == rawFrame.FrameNumber {
				// Same height, check if better
				if bytes.Equal(d.head.Output, rawFrame.Output) {
					d.logger.Info("equivalent frame")
					d.processPending(d.head, frame)
					continue
				}

				d.logger.Info(
					"frame is same height",
					zap.String("head_distance", d.headDistance.Text(16)),
					zap.String("distance", distance.Text(16)),
				)

				// If competing frames share a parent, use shorter distance
				if bytes.Equal(d.head.ParentSelector, rawFrame.ParentSelector) &&
					distance.Cmp(d.headDistance) < 0 {
					d.logger.Info(
						"frame shares parent, has shorter distance, short circuit",
					)
					d.totalDistance.Sub(d.totalDistance, d.headDistance)
					d.setHead(rawFrame, distance)
					d.processPending(d.head, frame)
					continue
				}

				// Different parent, need fork choice
				d.forkChoice(rawFrame, distance)
				d.processPending(d.head, frame)

			} else {
				// Frame is from the past
				d.logger.Info("frame is lower height")

				existing, _, err := d.clockStore.GetDataClockFrame(
					d.filter,
					rawFrame.FrameNumber,
					true,
				)
				if err != nil {
					if frameDone != nil {
						close(frameDone)
					}
					continue
				}

				// Only consider if different from existing
				if !bytes.Equal(existing.Output, rawFrame.Output) {
					// If same parent, compare distances
					if bytes.Equal(existing.ParentSelector, rawFrame.ParentSelector) {
						ld := d.getTotalDistance(existing)
						rd := d.getTotalDistance(rawFrame)
						if rd.Cmp(ld) < 0 {
							// This frame offers a better path
							d.forkChoice(rawFrame, distance)
							d.processPending(d.head, frame)
						} else {
							d.processPending(d.head, frame)
						}
					} else {
						// Different parents, evaluate based on total chain distance
						d.evaluateCompetingChains(rawFrame, existing)
						d.processPending(d.head, frame)
					}
				}
			}

			if frameDone != nil {
				close(frameDone)
			}
		}
	}
}

func (d *DataTimeReel) processPending(
	frame *protobufs.ClockFrame,
	lastReceived *pendingFrame,
) {
	d.logger.Info(
		"process pending",
		zap.Uint64("head_frame", frame.FrameNumber),
		zap.Uint64("last_received_frame", lastReceived.frameNumber),
		zap.Int("pending_frame_numbers", len(d.pending)),
	)

	for frameNum := range d.pending {
		if frameNum < d.head.FrameNumber {
			delete(d.pending, frameNum)
		}
	}

	headSelector, err := d.head.GetSelector()
	if err != nil {
		d.logger.Panic("failed to get head selector", zap.Error(err))
	}

	selectorHex := hex.EncodeToString(headSelector.Bytes())
	childFrames := d.childFrames[selectorHex]

	if len(childFrames) > 0 {
		var bestChild *pendingFrame
		bestDistance := unknownDistance

		for _, child := range childFrames {
			if child.frameNumber != d.head.FrameNumber+1 {
				continue
			}

			if bestChild == nil || child.distance.Cmp(bestDistance) < 0 {
				bestChild = child
				bestDistance = child.distance
			}
		}

		if bestChild != nil {
			rawFrame, err := d.clockStore.GetStagedDataClockFrame(
				d.filter,
				bestChild.frameNumber,
				bestChild.selector.FillBytes(make([]byte, 32)),
				false,
			)

			if err == nil {
				d.logger.Info("found direct child of head",
					zap.Uint64("frame", rawFrame.FrameNumber),
					zap.String("selector", bestChild.selector.Text(16)))

				if err = d.setHead(rawFrame, bestChild.distance); err == nil {
					d.processPendingChain()
				}
			}
		}
	} else {
		d.processPendingChain()
	}
}

func (d *DataTimeReel) tryFillGap(startFrame, endFrame uint64) bool {
	d.logger.Info(
		"trying to fill gap",
		zap.Uint64("from", startFrame),
		zap.Uint64("to", endFrame),
	)

	headSelector, err := d.head.GetSelector()
	if err != nil {
		d.logger.Panic("failed to get head selector", zap.Error(err))
	}

	currentSelector := headSelector

	for frameNum := startFrame; frameNum <= endFrame; frameNum++ {
		pendingFrames, ok := d.pending[frameNum]
		if !ok || len(pendingFrames) == 0 {
			d.logger.Info(
				"gap cannot be filled, missing frame",
				zap.Uint64("frame", frameNum),
			)
			return false
		}

		// Find best candidate (minimum distance)
		var bestFrame *pendingFrame
		bestDistance := unknownDistance

		for _, frame := range pendingFrames {
			// First priority: parent matches current selector
			if bytes.Equal(frame.parentSelector.Bytes(), currentSelector.Bytes()) {
				if bestFrame == nil || frame.distance.Cmp(bestDistance) < 0 {
					bestFrame = frame
					bestDistance = frame.distance
				}
			}
		}

		// If no direct match, consider any frame at this height
		if bestFrame == nil {
			for _, frame := range pendingFrames {
				rawFrame, err := d.clockStore.GetStagedDataClockFrame(
					d.filter,
					frameNum,
					frame.selector.FillBytes(make([]byte, 32)),
					false,
				)

				if err != nil {
					continue
				}

				distance, err := d.GetDistance(rawFrame)
				if err != nil {
					continue
				}

				if bestFrame == nil || distance.Cmp(bestDistance) < 0 {
					bestFrame = frame
					bestDistance = distance
				}
			}
		}

		if bestFrame == nil {
			d.logger.Info(
				"gap cannot be filled, no valid candidate",
				zap.Uint64("frame", frameNum),
			)
			return false
		}

		rawFrame, err := d.clockStore.GetStagedDataClockFrame(
			d.filter,
			frameNum,
			bestFrame.selector.FillBytes(make([]byte, 32)),
			false,
		)

		if err != nil {
			d.logger.Info(
				"gap cannot be filled, frame not found",
				zap.Uint64("frame", frameNum),
			)
			return false
		}

		if err = d.validateAndSetHead(rawFrame, bestDistance); err != nil {
			d.logger.Info("gap cannot be filled, validation failed",
				zap.Uint64("frame", frameNum),
				zap.Error(err))
			return false
		}

		currentSelector, err = rawFrame.GetSelector()
		if err != nil {
			d.logger.Panic("failed to get selector", zap.Error(err))
		}
	}

	d.logger.Info("successfully filled gap",
		zap.Uint64("from", startFrame),
		zap.Uint64("to", endFrame))
	return true
}

func (d *DataTimeReel) validateAndSetHead(
	frame *protobufs.ClockFrame,
	distance *big.Int,
) error {
	// Ensure the frame is valid
	if frame.FrameNumber != d.head.FrameNumber+1 {
		return errors.New("frame is not next in sequence")
	}

	headSelector, err := d.head.GetSelector()
	if err != nil {
		return err
	}

	if !bytes.Equal(frame.ParentSelector, headSelector.Bytes()) {
		d.logger.Info("frame parent doesn't exactly match head selector",
			zap.String("parent", hex.EncodeToString(frame.ParentSelector)),
			zap.String("head_selector", headSelector.Text(16)))
	}

	return d.setHead(frame, distance)
}

// processPendingChain tries to construct the best chain from pending frames
func (d *DataTimeReel) processPendingChain() {
	for {
		next := d.head.FrameNumber + 1

		// Get all frames for next height
		rawFrames, err := d.clockStore.GetStagedDataClockFramesForFrameNumber(
			d.filter,
			next,
		)
		if err != nil {
			return
		}

		if len(rawFrames) == 0 {
			return
		}

		headSelector, err := d.head.GetSelector()
		if err != nil {
			d.logger.Panic("failed to get head selector", zap.Error(err))
		}

		var bestFrame *protobufs.ClockFrame
		bestDistance := unknownDistance

		for _, rawFrame := range rawFrames {
			if bytes.Equal(rawFrame.ParentSelector, headSelector.Bytes()) {
				distance, err := d.GetDistance(rawFrame)
				if err != nil {
					continue
				}

				if bestFrame == nil || distance.Cmp(bestDistance) < 0 {
					bestFrame = rawFrame
					bestDistance = distance
				}
			}
		}

		if bestFrame == nil {
			for _, rawFrame := range rawFrames {
				distance, err := d.GetDistance(rawFrame)
				if err != nil {
					continue
				}

				if bestFrame == nil || distance.Cmp(bestDistance) < 0 {
					bestFrame = rawFrame
					bestDistance = distance
				}
			}
		}

		if bestFrame == nil {
			return
		}

		if err = d.setHead(bestFrame, bestDistance); err != nil {
			return
		}
	}
}

func (d *DataTimeReel) evaluateCompetingChains(
	newFrame, existingFrame *protobufs.ClockFrame,
) {
	newTotal := d.getTotalDistance(newFrame)
	existingTotal := d.getTotalDistance(existingFrame)

	if newTotal.Cmp(existingTotal) < 0 {
		distance, _ := d.GetDistance(newFrame)
		d.forkChoice(newFrame, distance)
	}
}

func (d *DataTimeReel) GetDistance(frame *protobufs.ClockFrame) (
	*big.Int,
	error,
) {
	if frame.FrameNumber == 0 {
		return big.NewInt(0), nil
	}

	prev, _, err := d.clockStore.GetDataClockFrame(
		d.filter,
		frame.FrameNumber-1,
		false,
	)
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
	}

	prevSelector, err := prev.GetSelector()
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
	}

	addr, err := frame.GetAddress()
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
	}

	distance := new(big.Int).Sub(
		prevSelector,
		new(big.Int).SetBytes(addr),
	)
	distance.Abs(distance)

	return distance, nil
}

func (d *DataTimeReel) setHead(
	frame *protobufs.ClockFrame,
	distance *big.Int,
) error {
	d.logger.Info(
		"set frame to head",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)

	txn, err := d.clockStore.NewTransaction(false)
	if err != nil {
		d.logger.Panic("failed to create transaction", zap.Error(err))
	}

	d.logger.Info(
		"save data",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("distance", distance.Text(16)),
	)

	selector, err := frame.GetSelector()
	if err != nil {
		d.logger.Panic("failed to get selector", zap.Error(err))
	}

	_, tries, err := d.clockStore.GetDataClockFrame(
		d.filter,
		frame.FrameNumber-1,
		false,
	)
	if err != nil {
		d.logger.Error("could not get data clock frame", zap.Error(err))
	}

	if tries, err = d.exec(txn, frame, tries); err != nil {
		d.logger.Error("invalid frame execution, unwinding", zap.Error(err))
		txn.Abort()
		return errors.Wrap(err, "set head")
	}

	if err := d.clockStore.CommitDataClockFrame(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		tries,
		txn,
		false,
	); err != nil {
		d.logger.Panic("failed to commit data clock frame", zap.Error(err))
	}

	if err = txn.Commit(); err != nil {
		d.logger.Panic("failed to commit transaction", zap.Error(err))
	}

	d.proverTries = tries
	d.head = frame
	d.headDistance = distance

	if d.alwaysSend {
		select {
		case <-d.ctx.Done():
			return d.ctx.Err()
		case d.newFrameCh <- frame:
		}
	} else {
		select {
		case <-d.ctx.Done():
			return d.ctx.Err()
		case d.newFrameCh <- frame:
		default:
		}
	}

	headSelectorBytes := selector.FillBytes(make([]byte, 32))
	headSelectorHex := hex.EncodeToString(headSelectorBytes)

	if children, ok := d.pending[frame.FrameNumber+1]; ok {
		for _, child := range children {
			parentHex := hex.EncodeToString(child.parentSelector.Bytes())
			if parentHex == headSelectorHex {
				d.logger.Info("found child of new head",
					zap.Uint64("child_frame", child.frameNumber),
					zap.String("child_selector", child.selector.Text(16)))
			}
		}
	}

	return nil
}

func (d *DataTimeReel) forkChoice(
	frame *protobufs.ClockFrame,
	distance *big.Int,
) {
	d.logger.Info(
		"fork choice",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)
	_, selector, err := frame.GetParentAndSelector()
	if err != nil {
		d.logger.Panic("failed to get parent and selector", zap.Error(err))
	}

	leftIndex := d.head
	rightIndex := frame
	leftTotal := new(big.Int).Set(d.headDistance)
	overweight := big.NewInt(0)
	rightTotal := new(big.Int).Set(distance)
	left := d.head.ParentSelector
	right := frame.ParentSelector

	rightReplaySelectors := [][]byte{}

	// If right chain is longer, walk back until same height
	for rightIndex.FrameNumber > leftIndex.FrameNumber {
		rightReplaySelectors = append(
			append(
				[][]byte{},
				right,
			),
			rightReplaySelectors...,
		)

		rightIndex, err = d.clockStore.GetStagedDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
			true,
		)
		if err != nil {
			// If lineage cannot be verified, we can't proceed
			if errors.Is(err, store.ErrNotFound) {
				d.logger.Info("cannot verify lineage, aborting fork choice")
				return
			} else {
				d.logger.Panic("failed to get staged data clock frame", zap.Error(err))
			}
		}

		right = rightIndex.ParentSelector

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			d.logger.Panic("failed to get distance", zap.Error(err))
		}

		// We accumulate right on left when right is longer because we cannot know
		// where the left will lead and don't want it to disadvantage our comparison
		overweight.Add(overweight, rightIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}

	// Walk backwards through the parents, until we find a matching parent
	// selector:
	for !bytes.Equal(left, right) {
		d.logger.Info(
			"scan backwards",
			zap.String("left_parent", hex.EncodeToString(leftIndex.ParentSelector)),
			zap.String("right_parent", hex.EncodeToString(rightIndex.ParentSelector)),
		)

		rightReplaySelectors = append(
			append(
				[][]byte{},
				right,
			),
			rightReplaySelectors...,
		)

		leftIndex, err = d.clockStore.GetStagedDataClockFrame(
			d.filter,
			leftIndex.FrameNumber-1,
			leftIndex.ParentSelector,
			true,
		)
		if err != nil {
			d.logger.Error(
				"store corruption: a discontinuity has been found in your time reel",
				zap.String(
					"selector",
					hex.EncodeToString(leftIndex.ParentSelector),
				),
				zap.Uint64("frame_number", leftIndex.FrameNumber-1),
			)
			d.logger.Panic("failed to get staged data clock frame", zap.Error(err))
		}

		rightIndex, err = d.clockStore.GetStagedDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
			true,
		)
		if err != nil {
			// If lineage cannot be verified, abort
			if errors.Is(err, store.ErrNotFound) {
				d.logger.Info("cannot verify full lineage, aborting fork choice")
				return
			} else {
				d.logger.Panic("failed to get staged data clock frame", zap.Error(err))
			}
		}

		left = leftIndex.ParentSelector
		right = rightIndex.ParentSelector

		leftIndexDistance, err := d.GetDistance(leftIndex)
		if err != nil {
			d.logger.Panic("failed to get distance", zap.Error(err))
		}

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			d.logger.Panic("failed to get distance", zap.Error(err))
		}

		leftTotal.Add(leftTotal, leftIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}

	d.logger.Info("found mutual root")

	frameNumber := rightIndex.FrameNumber
	overweight.Add(overweight, leftTotal)

	// Choose new fork based on lightest distance sub-tree
	if rightTotal.Cmp(overweight) > 0 {
		d.logger.Info("proposed fork has greater distance, keeping current chain",
			zap.String("right_total", rightTotal.Text(16)),
			zap.String("left_total", overweight.Text(16)),
		)
		return
	}

	d.logger.Info("switching to new fork - better distance",
		zap.String("right_total", rightTotal.Text(16)),
		zap.String("current_total", overweight.Text(16)),
	)

	// Apply the right chain frames
	for {
		if len(rightReplaySelectors) == 0 {
			break
		}
		next := rightReplaySelectors[0]
		rightReplaySelectors = rightReplaySelectors[1:]

		txn, err := d.clockStore.NewTransaction(false)
		if err != nil {
			d.logger.Panic("failed to create transaction", zap.Error(err))
		}

		if err := d.clockStore.CommitDataClockFrame(
			d.filter,
			frameNumber,
			next,
			d.proverTries,
			txn,
			rightIndex.FrameNumber < d.head.FrameNumber,
		); err != nil {
			d.logger.Panic("failed to commit data clock frame", zap.Error(err))
		}

		if err = txn.Commit(); err != nil {
			d.logger.Panic("failed to commit transaction", zap.Error(err))
		}

		frameNumber++
	}

	txn, err := d.clockStore.NewTransaction(false)
	if err != nil {
		d.logger.Panic("failed to create transaction", zap.Error(err))
	}

	if err := d.clockStore.CommitDataClockFrame(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		d.proverTries,
		txn,
		false,
	); err != nil {
		d.logger.Panic("failed to commit data clock frame", zap.Error(err))
	}

	if err = txn.Commit(); err != nil {
		d.logger.Panic("failed to commit transaction", zap.Error(err))
	}

	d.head = frame
	d.totalDistance.Sub(d.totalDistance, leftTotal)
	d.totalDistance.Add(d.totalDistance, rightTotal)
	d.headDistance = distance

	d.logger.Info(
		"set total distance after fork choice",
		zap.String("total_distance", d.totalDistance.Text(16)),
	)

	d.clockStore.SetTotalDistance(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		d.totalDistance,
	)

	select {
	case <-d.ctx.Done():
	case d.newFrameCh <- frame:
	default:
	}
}

func (d *DataTimeReel) getTotalDistance(frame *protobufs.ClockFrame) *big.Int {
	selector, err := frame.GetSelector()
	if err != nil {
		d.logger.Panic("failed to get selector", zap.Error(err))
	}

	existingTotal, err := d.clockStore.GetTotalDistance(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
	)
	if err == nil && existingTotal != nil {
		return existingTotal
	}

	total, err := d.GetDistance(frame)
	if err != nil {
		return total
	}

	for index := frame; err == nil &&
		index.FrameNumber > 0; index, err = d.clockStore.GetStagedDataClockFrame(
		d.filter,
		index.FrameNumber-1,
		index.ParentSelector,
		true,
	) {
		distance, err := d.GetDistance(index)
		if err != nil {
			return total
		}

		total.Add(total, distance)
	}

	d.clockStore.SetTotalDistance(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		total,
	)

	return total
}

func (d *DataTimeReel) GetTotalDistance() *big.Int {
	return new(big.Int).Set(d.totalDistance)
}

func (
	d *DataTimeReel,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	return d.proverTries
}

func (d *DataTimeReel) NewFrameCh() <-chan *protobufs.ClockFrame {
	return d.newFrameCh
}

func (d *DataTimeReel) BadFrameCh() <-chan *protobufs.ClockFrame {
	return d.badFrameCh
}

func (d *DataTimeReel) Head() (*protobufs.ClockFrame, error) {
	return d.head, nil
}

func (d *DataTimeReel) Stop() {
	d.cancel()
	d.wg.Wait()
}

var alreadyDone chan struct{} = func() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

var _ TimeReel = (*DataTimeReel)(nil)
