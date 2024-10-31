package time

import (
	"bytes"
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

type pendingFrame struct {
	selector       *big.Int
	parentSelector *big.Int
	frameNumber    uint64
}

type DataTimeReel struct {
	rwMutex sync.RWMutex
	running bool

	filter       []byte
	engineConfig *config.EngineConfig
	logger       *zap.Logger
	clockStore   store.ClockStore
	frameProver  crypto.FrameProver
	exec         func(txn store.Transaction, frame *protobufs.ClockFrame) error

	origin                []byte
	initialInclusionProof *crypto.InclusionAggregateProof
	initialProverKeys     [][]byte
	head                  *protobufs.ClockFrame
	totalDistance         *big.Int
	headDistance          *big.Int
	lruFrames             *lru.Cache[string, string]
	proverTries           []*tries.RollingFrecencyCritbitTrie
	// pending               map[uint64][]*pendingFrame
	incompleteForks map[uint64][]*pendingFrame
	frames          chan *pendingFrame
	newFrameCh      chan *protobufs.ClockFrame
	badFrameCh      chan *protobufs.ClockFrame
	done            chan bool
}

func NewDataTimeReel(
	filter []byte,
	logger *zap.Logger,
	clockStore store.ClockStore,
	engineConfig *config.EngineConfig,
	frameProver crypto.FrameProver,
	exec func(txn store.Transaction, frame *protobufs.ClockFrame) error,
	origin []byte,
	initialInclusionProof *crypto.InclusionAggregateProof,
	initialProverKeys [][]byte,
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

	return &DataTimeReel{
		running:               false,
		logger:                logger,
		filter:                filter,
		engineConfig:          engineConfig,
		clockStore:            clockStore,
		frameProver:           frameProver,
		exec:                  exec,
		origin:                origin,
		initialInclusionProof: initialInclusionProof,
		initialProverKeys:     initialProverKeys,
		lruFrames:             cache,
		// pending:               make(map[uint64][]*pendingFrame),
		incompleteForks: make(map[uint64][]*pendingFrame),
		frames:          make(chan *pendingFrame),
		newFrameCh:      make(chan *protobufs.ClockFrame),
		badFrameCh:      make(chan *protobufs.ClockFrame),
		done:            make(chan bool),
	}
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

	d.running = true
	go d.runLoop()

	return nil
}

func (d *DataTimeReel) SetHead(frame *protobufs.ClockFrame) {
	if d.running == true {
		panic("internal test function should never be called outside of tests")
	}

	d.head = frame
}

func (d *DataTimeReel) Head() (*protobufs.ClockFrame, error) {
	return d.head, nil
}

// Insert enqueues a structurally valid frame into the time reel. If the frame
// is the next one in sequence, it advances the reel head forward and emits a
// new frame on the new frame channel.
func (d *DataTimeReel) Insert(frame *protobufs.ClockFrame, isSync bool) error {
	if !d.running {
		return nil
	}

	d.logger.Debug(
		"insert frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
	)

	// if d.lruFrames.Contains(string(frame.Output[:64])) {
	// 	return nil
	// }

	// d.lruFrames.Add(string(frame.Output[:64]), string(frame.ParentSelector))

	parent := new(big.Int).SetBytes(frame.ParentSelector)
	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}

	distance, _ := d.GetDistance(frame)

	if d.head.FrameNumber < frame.FrameNumber {
		d.storePending(selector, parent, distance, frame)

		if d.head.FrameNumber+1 == frame.FrameNumber {
			go func() {
				d.frames <- &pendingFrame{
					selector:       selector,
					parentSelector: parent,
					frameNumber:    frame.FrameNumber,
				}
			}()
		}
	}

	return nil
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

func (d *DataTimeReel) Stop() {
	d.done <- true
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

	txn, err := d.clockStore.NewTransaction()
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

	txn, err = d.clockStore.NewTransaction()
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

// Main data consensus loop
func (d *DataTimeReel) runLoop() {
	for {
		select {
		case frame := <-d.frames:
			rawFrame, err := d.clockStore.GetStagedDataClockFrame(
				d.filter,
				frame.frameNumber,
				frame.selector.FillBytes(make([]byte, 32)),
				false,
			)
			if err != nil {
				panic(err)
			}
			d.logger.Debug(
				"processing frame",
				zap.Uint64("frame_number", rawFrame.FrameNumber),
				zap.String("output_tag", hex.EncodeToString(rawFrame.Output[:64])),
				zap.Uint64("head_number", d.head.FrameNumber),
				zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
			)
			// Most common scenario: in order – new frame is higher number
			if d.head.FrameNumber < rawFrame.FrameNumber {
				d.logger.Debug("frame is higher")

				// parent := new(big.Int).SetBytes(rawFrame.ParentSelector)
				// selector, err := rawFrame.GetSelector()
				// if err != nil {
				// panic(err)
				// }

				distance, err := d.GetDistance(rawFrame)
				if err != nil {
					if !errors.Is(err, store.ErrNotFound) {
						panic(err)
					}

					// d.addPending(selector, parent, frame.frameNumber)
					d.processPending(d.head, frame)
					continue
				}

				// If the frame has a gap from the head or is not descendent, mark it as
				// pending:
				if rawFrame.FrameNumber-d.head.FrameNumber != 1 {
					d.processPending(d.head, frame)
					continue
				}

				// Otherwise set it as the next and process all pending
				d.setHead(rawFrame, distance)
				d.processPending(d.head, frame)
			} else if d.head.FrameNumber == rawFrame.FrameNumber {
				// frames are equivalent, no need to act
				if bytes.Equal(d.head.Output, rawFrame.Output) {
					d.logger.Debug("equivalent frame")
					d.processPending(d.head, frame)
					continue
				}

				// temp: remove fork choice until prover ring testing
				// distance, err := d.GetDistance(rawFrame)
				// if err != nil {
				// 	panic(err)
				// }
				// d.logger.Debug(
				// 	"frame is same height",
				// 	zap.String("head_distance", d.headDistance.Text(16)),
				// 	zap.String("distance", distance.Text(16)),
				// )

				// // Optimization: if competing frames share a parent we can short-circuit
				// // fork choice
				// if bytes.Equal(d.head.ParentSelector, rawFrame.ParentSelector) &&
				// 	distance.Cmp(d.headDistance) < 0 {
				// 	d.logger.Debug(
				// 		"frame shares parent, has shorter distance, short circuit",
				// 	)
				// 	d.totalDistance.Sub(d.totalDistance, d.headDistance)
				// 	d.setHead(rawFrame, distance)
				// 	d.processPending(d.head, frame)
				// 	continue
				// }

				// Choose fork
				// d.forkChoice(rawFrame, distance)
				d.processPending(d.head, frame)
			} else {
				// d.logger.Debug("frame is lower height")

				// existing, _, err := d.clockStore.GetDataClockFrame(
				// 	d.filter,
				// 	rawFrame.FrameNumber,
				// 	true,
				// )
				// if err != nil {
				// 	// if this returns an error it's either not found (which shouldn't
				// 	// happen without corruption) or pebble is borked, either way, panic
				// 	panic(err)
				// }

				// if !bytes.Equal(existing.Output, rawFrame.Output) {
				// 	parent, selector, err := rawFrame.GetParentAndSelector()
				// 	if err != nil {
				// 		panic(err)
				// 	}

				// 	if bytes.Equal(existing.ParentSelector, rawFrame.ParentSelector) {
				// 		ld := d.getTotalDistance(existing)
				// 		rd := d.getTotalDistance(rawFrame)
				// 		if rd.Cmp(ld) < 0 {
				// 			d.forkChoice(rawFrame, rd)
				// 			d.processPending(d.head, frame)
				// 		} else {
				// 			d.addPending(selector, parent, frame.frameNumber)
				// 			d.processPending(d.head, frame)
				// 		}
				// 	} else {
				// 		d.addPending(selector, parent, frame.frameNumber)
				// 		d.processPending(d.head, frame)
				// 	}
				// }
			}
		case <-d.done:
			return
		}
	}
}

// func (d *DataTimeReel) addPending(
// 	selector *big.Int,
// 	parent *big.Int,
// 	frameNumber uint64,
// ) {
// 	// d.logger.Debug(
// 	// 	"add pending",
// 	// 	zap.Uint64("head_frame_number", d.head.FrameNumber),
// 	// 	zap.Uint64("add_frame_number", frameNumber),
// 	// 	zap.String("selector", selector.Text(16)),
// 	// 	zap.String("parent", parent.Text(16)),
// 	// )

// 	if d.head.FrameNumber <= frameNumber {
// 		if _, ok := d.pending[frameNumber]; !ok {
// 			d.pending[frameNumber] = []*pendingFrame{}
// 		}

// 		// avoid heavy thrashing
// 		for _, frame := range d.pending[frameNumber] {
// 			if frame.selector.Cmp(selector) == 0 {
// 				d.logger.Debug("exists in pending already")
// 				return
// 			}
// 		}
// 	}

// 	if d.head.FrameNumber <= frameNumber {
// 		// d.logger.Debug(
// 		// 	"accumulate in pending",
// 		// 	zap.Int("pending_neighbors", len(d.pending[frameNumber])),
// 		// )

// 		d.pending[frameNumber] = append(
// 			d.pending[frameNumber],
// 			&pendingFrame{
// 				selector:       selector,
// 				parentSelector: parent,
// 				frameNumber:    frameNumber,
// 			},
// 		)
// 	}
// }

func (d *DataTimeReel) storePending(
	selector *big.Int,
	parent *big.Int,
	distance *big.Int,
	frame *protobufs.ClockFrame,
) {
	// avoid db thrashing
	if existing, err := d.clockStore.GetStagedDataClockFrame(
		frame.Filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		true,
	); err != nil && existing == nil {
		d.logger.Debug(
			"not stored yet, save data candidate",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.String("selector", selector.Text(16)),
			zap.String("parent", parent.Text(16)),
			zap.String("distance", distance.Text(16)),
		)

		txn, err := d.clockStore.NewTransaction()
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
		if err = txn.Commit(); err != nil {
			panic(err)
		}
	}
}

func (d *DataTimeReel) processPending(
	frame *protobufs.ClockFrame,
	lastReceived *pendingFrame,
) {
	// d.logger.Debug(
	// 	"process pending",
	// 	zap.Uint64("head_frame", frame.FrameNumber),
	// 	zap.Uint64("last_received_frame", lastReceived.frameNumber),
	// 	zap.Int("pending_frame_numbers", len(d.pending)),
	// )

	for {
		next := d.head.FrameNumber + 1
		sel, err := d.head.GetSelector()
		if err != nil {
			panic(err)
		}

		selector := sel.FillBytes(make([]byte, 32))
		// d.logger.Debug(
		// 	"checking frame set",
		// 	zap.Uint64("pending_frame_number", f),
		// 	zap.Uint64("frame_number", frame.FrameNumber),
		// )
		// Pull the next
		d.logger.Debug("try process next")

		//// todo: revise for prover rings
		rawFrames, err := d.clockStore.GetStagedDataClockFramesForFrameNumber(
			d.filter,
			next,
		)
		if err != nil {
			panic(err)
		}

		found := false
		for _, rawFrame := range rawFrames {
			if !bytes.Equal(rawFrame.ParentSelector, selector) {
				continue
			}

			d.logger.Debug(
				"processing frame",
				zap.Uint64("frame_number", rawFrame.FrameNumber),
				zap.String("output_tag", hex.EncodeToString(rawFrame.Output[:64])),
				zap.Uint64("head_number", d.head.FrameNumber),
				zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
			)

			distance, err := d.GetDistance(rawFrame)
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					panic(err)
				}

				continue
			}

			// Otherwise set it as the next and process all pending
			d.setHead(rawFrame, distance)
			found = true
			break
		}

		if !found {
			break
		}
	}
}

func (d *DataTimeReel) setHead(frame *protobufs.ClockFrame, distance *big.Int) {
	d.logger.Debug(
		"set frame to head",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)
	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	d.logger.Debug(
		"save data",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("distance", distance.Text(16)),
	)

	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}

	if err := d.clockStore.CommitDataClockFrame(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		d.proverTries,
		txn,
		false,
	); err != nil {
		panic(err)
	}
	if err = d.exec(txn, frame); err != nil {
		d.logger.Debug("invalid frame execution, unwinding", zap.Error(err))
		txn.Abort()
		return
	}

	if err = txn.Commit(); err != nil {
		panic(err)
	}

	d.head = frame

	d.headDistance = distance
	go func() {
		select {
		case d.newFrameCh <- frame:
		default:
		}
	}()
}

func (d *DataTimeReel) getTotalDistance(frame *protobufs.ClockFrame) *big.Int {
	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}

	total, err := d.clockStore.GetTotalDistance(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
	)
	if err == nil && total != nil {
		return total
	}

	total, err = d.GetDistance(frame)
	if err != nil {
		panic(err)
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
			panic(err)
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

	discriminatorNode :=
		d.proverTries[0].FindNearest(prevSelector.FillBytes(make([]byte, 32)))
	discriminator := discriminatorNode.External.Key
	addr, err := frame.GetAddress()
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
	}
	distance := new(big.Int).Sub(
		new(big.Int).SetBytes(discriminator),
		new(big.Int).SetBytes(addr),
	)
	distance.Abs(distance)

	return distance, nil
}

func (d *DataTimeReel) forkChoice(
	frame *protobufs.ClockFrame,
	distance *big.Int,
) {
	d.logger.Debug(
		"fork choice",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)
	_, selector, err := frame.GetParentAndSelector()
	if err != nil {
		panic(err)
	}

	leftIndex := d.head
	rightIndex := frame
	leftTotal := new(big.Int).Set(d.headDistance)
	overweight := big.NewInt(0)
	rightTotal := new(big.Int).Set(distance)
	left := d.head.ParentSelector
	right := frame.ParentSelector

	rightReplaySelectors := [][]byte{}

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
			// If lineage cannot be verified, set it for later
			if errors.Is(err, store.ErrNotFound) {
				// d.addPending(selector, parentSelector, frame.FrameNumber)
				return
			} else {
				panic(err)
			}
		}

		right = rightIndex.ParentSelector

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			panic(err)
		}

		// We accumulate right on left when right is longer because we cannot know
		// where the left will lead and don't want it to disadvantage our comparison
		overweight.Add(overweight, rightIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}

	// Walk backwards through the parents, until we find a matching parent
	// selector:
	for !bytes.Equal(left, right) {
		d.logger.Debug(
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
			panic(err)
		}

		rightIndex, err = d.clockStore.GetStagedDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
			true,
		)
		if err != nil {
			// If lineage cannot be verified, set it for later
			if errors.Is(err, store.ErrNotFound) {
				// d.addPending(selector, parentSelector, frame.FrameNumber)
				return
			} else {
				panic(err)
			}
		}

		left = leftIndex.ParentSelector
		right = rightIndex.ParentSelector
		leftIndexDistance, err := d.GetDistance(leftIndex)
		if err != nil {
			panic(err)
		}

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			panic(err)
		}

		leftTotal.Add(leftTotal, leftIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}
	d.logger.Debug("found mutual root")

	frameNumber := rightIndex.FrameNumber

	overweight.Add(overweight, leftTotal)

	// Choose new fork based on lightest distance sub-tree
	if rightTotal.Cmp(overweight) > 0 {
		d.logger.Debug("proposed fork has greater distance",
			zap.String("right_total", rightTotal.Text(16)),
			zap.String("left_total", overweight.Text(16)),
		)
		// d.addPending(selector, parentSelector, frame.FrameNumber)
		return
	}

	for {
		if len(rightReplaySelectors) == 0 {
			break
		}
		next := rightReplaySelectors[0]
		rightReplaySelectors =
			rightReplaySelectors[1:]

		txn, err := d.clockStore.NewTransaction()
		if err != nil {
			panic(err)
		}

		if err := d.clockStore.CommitDataClockFrame(
			d.filter,
			frameNumber,
			next,
			d.proverTries,
			txn,
			rightIndex.FrameNumber < d.head.FrameNumber,
		); err != nil {
			panic(err)
		}

		if err = txn.Commit(); err != nil {
			panic(err)
		}

		frameNumber++
	}

	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if err := d.clockStore.CommitDataClockFrame(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		d.proverTries,
		txn,
		false,
	); err != nil {
		panic(err)
	}

	if err = txn.Commit(); err != nil {
		panic(err)
	}

	d.head = frame
	d.totalDistance.Sub(d.totalDistance, leftTotal)
	d.totalDistance.Add(d.totalDistance, rightTotal)
	d.headDistance = distance
	d.logger.Debug(
		"set total distance",
		zap.String("total_distance", d.totalDistance.Text(16)),
	)

	d.clockStore.SetTotalDistance(
		d.filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		d.totalDistance,
	)

	go func() {
		select {
		case d.newFrameCh <- frame:
		default:
		}
	}()
}

func (d *DataTimeReel) GetTotalDistance() *big.Int {
	return new(big.Int).Set(d.totalDistance)
}

var _ TimeReel = (*DataTimeReel)(nil)
