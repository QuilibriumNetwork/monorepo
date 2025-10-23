package store

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math/big"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type PebbleClockStore struct {
	db     store.KVDB
	logger *zap.Logger
}

var _ store.ClockStore = (*PebbleClockStore)(nil)

type PebbleGlobalClockIterator struct {
	i  store.Iterator
	db *PebbleClockStore
}

type PebbleClockIterator struct {
	i  store.Iterator
	db *PebbleClockStore
}

var _ store.TypedIterator[*protobufs.GlobalFrame] = (*PebbleGlobalClockIterator)(nil)
var _ store.TypedIterator[*protobufs.AppShardFrame] = (*PebbleClockIterator)(nil)

func (p *PebbleGlobalClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleGlobalClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleGlobalClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleGlobalClockIterator) Value() (*protobufs.GlobalFrame, error) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	key := p.i.Key()
	value := p.i.Value()

	frameNumber, err := extractFrameNumberFromGlobalFrameKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "get global clock frame iterator value")
	}

	// Deserialize the GlobalFrameHeader
	header := &protobufs.GlobalFrameHeader{}
	if err := proto.Unmarshal(value, header); err != nil {
		return nil, errors.Wrap(err, "get global clock frame iterator value")
	}

	frame := &protobufs.GlobalFrame{
		Header: header,
	}

	// Retrieve all requests for this frame
	var requests []*protobufs.MessageBundle
	requestIndex := uint16(0)
	for {
		requestKey := clockGlobalFrameRequestKey(frameNumber, requestIndex)
		requestData, closer, err := p.db.db.Get(requestKey)
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				// No more requests
				break
			}
			return nil, errors.Wrap(err, "get global clock frame requests")
		}
		defer closer.Close()

		request := &protobufs.MessageBundle{}
		if err := proto.Unmarshal(requestData, request); err != nil {
			return nil, errors.Wrap(err, "get global clock frame requests")
		}

		requests = append(requests, request)
		requestIndex++
	}

	frame.Requests = requests

	return frame, nil
}

func (p *PebbleGlobalClockIterator) TruncatedValue() (
	*protobufs.GlobalFrame,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()

	// Deserialize the GlobalFrameHeader
	header := &protobufs.GlobalFrameHeader{}
	if err := proto.Unmarshal(value, header); err != nil {
		return nil, errors.Wrap(err, "get global clock frame iterator value")
	}

	frame := &protobufs.GlobalFrame{
		Header: header,
	}

	// TruncatedValue doesn't include requests

	return frame, nil
}

func (p *PebbleGlobalClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing global clock iterator")
}

func (p *PebbleClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleClockIterator) Prev() bool {
	return p.i.Prev()
}

func (p *PebbleClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleClockIterator) TruncatedValue() (
	*protobufs.AppShardFrame,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.AppShardFrame{}
	frameValue, frameCloser, err := p.db.db.Get(value)
	if err != nil {
		return nil, errors.Wrap(err, "get truncated clock frame iterator value")
	}
	defer frameCloser.Close()
	if err := proto.Unmarshal(frameValue, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get truncated clock frame iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleClockIterator) Value() (*protobufs.AppShardFrame, error) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.AppShardFrame{}

	frameValue, frameCloser, err := p.db.db.Get(value)
	if err != nil {
		return nil, errors.Wrap(err, "get clock frame iterator value")
	}
	defer frameCloser.Close()
	if err := proto.Unmarshal(frameValue, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get clock frame iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing clock frame iterator")
}

func NewPebbleClockStore(db store.KVDB, logger *zap.Logger) *PebbleClockStore {
	return &PebbleClockStore{
		db,
		logger,
	}
}

//
// DB Keys
//
// Keys are structured as:
// <core type><sub type | index>[<non-index increment>]<segment>
// Increment necessarily must be full width – elsewise the frame number would
// easily produce conflicts if filters are stepped by byte:
// 0x01 || 0xffff == 0x01ff || 0xff
//
// Global frames are serialized as output data only, Data frames are raw
// protobufs for fast disk-to-network output.

func clockFrameKey(filter []byte, frameNumber uint64, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	return key
}

func clockGlobalFrameKey(frameNumber uint64) []byte {
	return clockFrameKey([]byte{}, frameNumber, CLOCK_GLOBAL_FRAME)
}

func extractFrameNumberFromGlobalFrameKey(
	key []byte,
) (uint64, error) {
	if len(key) < 10 {
		return 0, errors.Wrap(
			store.ErrInvalidData,
			"extract frame number and filter from global frame key",
		)
	}

	copied := make([]byte, len(key))
	copy(copied, key)
	return binary.BigEndian.Uint64(copied[2:10]), nil
}

func clockShardFrameKey(
	filter []byte,
	frameNumber uint64,
) []byte {
	return clockFrameKey(filter, frameNumber, CLOCK_SHARD_FRAME_SHARD)
}

func clockLatestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockGlobalLatestIndex() []byte {
	return clockLatestIndex([]byte{}, CLOCK_GLOBAL_FRAME_INDEX_LATEST)
}

func clockShardLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_SHARD_FRAME_INDEX_LATEST)
}

func clockEarliestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockGlobalEarliestIndex() []byte {
	return clockEarliestIndex([]byte{}, CLOCK_GLOBAL_FRAME_INDEX_EARLIEST)
}

func clockDataEarliestIndex(filter []byte) []byte {
	return clockEarliestIndex(filter, CLOCK_SHARD_FRAME_INDEX_EARLIEST)
}

// Produces an index key of size: len(filter) + 42
func clockParentIndexKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	frameType byte,
) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(selector, 32)...)
	return key
}

func clockShardParentIndexKey(
	address []byte,
	frameNumber uint64,
	selector []byte,
) []byte {
	return clockParentIndexKey(
		address,
		frameNumber,
		rightAlign(selector, 32),
		CLOCK_SHARD_FRAME_INDEX_PARENT,
	)
}

// func clockShardCandidateFrameKey(
// 	address []byte,
// 	frameNumber uint64,
// 	parent []byte,
// 	distance []byte,
// ) []byte {
// 	key := []byte{CLOCK_FRAME, CLOCK_SHARD_FRAME_CANDIDATE_SHARD}
// 	key = binary.BigEndian.AppendUint64(key, frameNumber)
// 	key = append(key, address...)
// 	key = append(key, rightAlign(parent, 32)...)
// 	key = append(key, rightAlign(distance, 32)...)
// 	return key
// }

func clockProverTrieKey(filter []byte, ring uint16, frameNumber uint64) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_SHARD_FRAME_FRECENCY_SHARD}
	key = binary.BigEndian.AppendUint16(key, ring)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	return key
}

func clockDataTotalDistanceKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_SHARD_FRAME_DISTANCE_SHARD}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(selector, 32)...)
	return key
}

func clockDataSeniorityKey(
	filter []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_SHARD_FRAME_SENIORITY_SHARD}
	key = append(key, filter...)
	return key
}

func clockShardStateTreeKey(
	filter []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_SHARD_FRAME_STATE_TREE}
	key = append(key, filter...)
	return key
}

func clockGlobalFrameRequestKey(
	frameNumber uint64,
	requestIndex uint16,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_GLOBAL_FRAME_REQUEST}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = binary.BigEndian.AppendUint16(key, requestIndex)
	return key
}

func (p *PebbleClockStore) NewTransaction(indexed bool) (
	store.Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

// GetEarliestGlobalClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestGlobalClockFrame() (
	*protobufs.GlobalFrame,
	error,
) {
	idxValue, closer, err := p.db.Get(clockGlobalEarliestIndex())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest global clock frame")
	}
	defer closer.Close()

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetGlobalClockFrame(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest global clock frame")
	}

	return frame, nil
}

// GetLatestGlobalClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestGlobalClockFrame() (
	*protobufs.GlobalFrame,
	error,
) {
	idxValue, closer, err := p.db.Get(clockGlobalLatestIndex())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest global clock frame")
	}
	defer closer.Close()

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetGlobalClockFrame(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get latest global clock frame")
	}

	return frame, nil
}

// GetGlobalClockFrame implements ClockStore.
func (p *PebbleClockStore) GetGlobalClockFrame(
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	value, closer, err := p.db.Get(clockGlobalFrameKey(frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get global clock frame")
	}
	defer closer.Close()

	// Deserialize the GlobalFrameHeader
	header := &protobufs.GlobalFrameHeader{}
	if err := proto.Unmarshal(value, header); err != nil {
		return nil, errors.Wrap(err, "get global clock frame")
	}

	frame := &protobufs.GlobalFrame{
		Header: header,
	}

	// Retrieve all requests for this frame
	var requests []*protobufs.MessageBundle
	requestIndex := uint16(0)
	for {
		requestKey := clockGlobalFrameRequestKey(frameNumber, requestIndex)
		requestData, closer, err := p.db.Get(requestKey)
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				// No more requests
				break
			}
			return nil, errors.Wrap(err, "get global clock frame")
		}
		defer closer.Close()

		request := &protobufs.MessageBundle{}
		if err := proto.Unmarshal(requestData, request); err != nil {
			return nil, errors.Wrap(err, "get global clock frame")
		}

		requests = append(requests, request)
		requestIndex++
	}

	frame.Requests = requests

	return frame, nil
}

// RangeGlobalClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeGlobalClockFrames(
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.GlobalFrame], error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockGlobalFrameKey(startFrameNumber),
		clockGlobalFrameKey(endFrameNumber+1),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range global clock frames")
	}

	return &PebbleGlobalClockIterator{i: iter, db: p}, nil
}

// PutGlobalClockFrame implements ClockStore.
func (p *PebbleClockStore) PutGlobalClockFrame(
	frame *protobufs.GlobalFrame,
	txn store.Transaction,
) error {
	if frame.Header == nil {
		return errors.Wrap(
			errors.New("frame header is required"),
			"put global clock frame",
		)
	}

	frameNumber := frame.Header.FrameNumber

	// Serialize the full header using protobuf
	headerData, err := proto.Marshal(frame.Header)
	if err != nil {
		return errors.Wrap(err, "put global clock frame")
	}

	if err := txn.Set(
		clockGlobalFrameKey(frameNumber),
		headerData,
	); err != nil {
		return errors.Wrap(err, "put global clock frame")
	}

	// Store requests separately with iterative keys
	for i, request := range frame.Requests {
		requestData, err := proto.Marshal(request)
		if err != nil {
			return errors.Wrap(err, "put global clock frame request")
		}

		if err := txn.Set(
			clockGlobalFrameRequestKey(frameNumber, uint16(i)),
			requestData,
		); err != nil {
			return errors.Wrap(err, "put global clock frame request")
		}
	}

	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frameNumber)

	_, closer, err := p.db.Get(clockGlobalEarliestIndex())
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "put global clock frame")
		}

		if err = txn.Set(
			clockGlobalEarliestIndex(),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "put global clock frame")
		}
	} else {
		_ = closer.Close()
	}

	if err = txn.Set(
		clockGlobalLatestIndex(),
		frameNumberBytes,
	); err != nil {
		return errors.Wrap(err, "put global clock frame")
	}

	return nil
}

// GetShardClockFrame implements ClockStore.
func (p *PebbleClockStore) GetShardClockFrame(
	filter []byte,
	frameNumber uint64,
	truncate bool,
) (*protobufs.AppShardFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	value, closer, err := p.db.Get(clockShardFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, store.ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get shard clock frame")
	}
	defer closer.Close()

	frame := &protobufs.AppShardFrame{}

	// We do a bit of a cheap trick here while things are still stuck in the old
	// ways: we use the size of the parent index key to determine if it's the new
	// format, or the old raw frame
	if len(value) == (len(filter) + 42) {
		frameValue, frameCloser, err := p.db.Get(value)
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				return nil, nil, store.ErrNotFound
			}

			return nil, nil, errors.Wrap(err, "get shard clock frame")
		}
		defer frameCloser.Close()
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, store.ErrInvalidData.Error()),
				"get shard clock frame",
			)
		}
	} else {
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, store.ErrInvalidData.Error()),
				"get shard clock frame",
			)
		}
	}

	if !truncate {
		proverTries := []*tries.RollingFrecencyCritbitTrie{}
		i := uint16(0)
		for {
			proverTrie := &tries.RollingFrecencyCritbitTrie{}
			trieData, closer, err := p.db.Get(
				clockProverTrieKey(filter, i, frameNumber),
			)
			if err != nil {
				if !errors.Is(err, pebble.ErrNotFound) {
					return nil, nil, errors.Wrap(err, "get shard clock frame")
				}
				break
			}
			defer closer.Close()

			if err := proverTrie.Deserialize(trieData); err != nil {
				return nil, nil, errors.Wrap(err, "get shard clock frame")
			}

			i++
			proverTries = append(proverTries, proverTrie)
		}

		return frame, proverTries, nil
	}

	return frame, nil, nil
}

// GetEarliestShardClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestShardClockFrame(
	filter []byte,
) (*protobufs.AppShardFrame, error) {
	idxValue, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest shard clock frame")
	}
	defer closer.Close()

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, _, err := p.GetShardClockFrame(filter, frameNumber, false)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest shard clock frame")
	}

	return frame, nil
}

// GetLatestShardClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestShardClockFrame(
	filter []byte,
) (*protobufs.AppShardFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	idxValue, closer, err := p.db.Get(clockShardLatestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, store.ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get latest shard clock frame")
	}
	defer closer.Close()

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, tries, err := p.GetShardClockFrame(filter, frameNumber, false)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, store.ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get latest shard clock frame")
	}

	return frame, tries, nil
}

// GetStagedShardClockFrame implements ClockStore.
func (p *PebbleClockStore) GetStagedShardClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
	truncate bool,
) (*protobufs.AppShardFrame, error) {
	data, closer, err := p.db.Get(
		clockShardParentIndexKey(filter, frameNumber, parentSelector),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(store.ErrNotFound, "get parent shard clock frame")
		}
		return nil, errors.Wrap(err, "get parent shard clock frame")
	}
	defer closer.Close()

	parent := &protobufs.AppShardFrame{}
	if err := proto.Unmarshal(data, parent); err != nil {
		return nil, errors.Wrap(err, "get parent shard clock frame")
	}

	return parent, nil
}

func (p *PebbleClockStore) GetStagedShardClockFramesForFrameNumber(
	filter []byte,
	frameNumber uint64,
) ([]*protobufs.AppShardFrame, error) {
	iter, err := p.db.NewIter(
		clockShardParentIndexKey(
			filter,
			frameNumber,
			bytes.Repeat([]byte{0x00}, 32),
		),
		clockShardParentIndexKey(
			filter,
			frameNumber,
			bytes.Repeat([]byte{0xff}, 32),
		),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(
				store.ErrNotFound,
				"get staged shard clock frames",
			)
		}
		return nil, errors.Wrap(err, "get staged shard clock frames")
	}
	defer iter.Close()

	frames := []*protobufs.AppShardFrame{}
	for iter.First(); iter.Valid(); iter.Next() {
		data := iter.Value()
		frame := &protobufs.AppShardFrame{}
		if err := proto.Unmarshal(data, frame); err != nil {
			return nil, errors.Wrap(err, "get staged shard clock frames")
		}

		frames = append(frames, frame)
	}

	return frames, nil
}

// StageShardClockFrame implements ClockStore.
func (p *PebbleClockStore) StageShardClockFrame(
	selector []byte,
	frame *protobufs.AppShardFrame,
	txn store.Transaction,
) error {
	data, err := proto.Marshal(frame)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"stage shard clock frame",
		)
	}

	if err = txn.Set(
		clockShardParentIndexKey(
			frame.Header.Address,
			frame.Header.FrameNumber,
			selector,
		),
		data,
	); err != nil {
		return errors.Wrap(err, "stage shard clock frame")
	}

	return nil
}

// CommitShardClockFrame implements ClockStore.
func (p *PebbleClockStore) CommitShardClockFrame(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	proverTries []*tries.RollingFrecencyCritbitTrie,
	txn store.Transaction,
	backfill bool,
) error {
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frameNumber)

	if err := txn.Set(
		clockShardFrameKey(filter, frameNumber),
		clockShardParentIndexKey(filter, frameNumber, selector),
	); err != nil {
		return errors.Wrap(err, "commit shard clock frame")
	}

	for i, proverTrie := range proverTries {
		proverData, err := proverTrie.Serialize()
		if err != nil {
			return errors.Wrap(err, "commit shard clock frame")
		}

		if err = txn.Set(
			clockProverTrieKey(filter, uint16(i), frameNumber),
			proverData,
		); err != nil {
			return errors.Wrap(err, "commit shard clock frame")
		}
	}

	_, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "commit shard clock frame")
		}

		if err = txn.Set(
			clockDataEarliestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit shard clock frame")
		}
	} else {
		_ = closer.Close()
	}

	if !backfill {
		if err = txn.Set(
			clockShardLatestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit shard clock frame")
		}
	}

	return nil
}

// RangeShardClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeShardClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (store.TypedIterator[*protobufs.AppShardFrame], error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockShardFrameKey(filter, startFrameNumber),
		clockShardFrameKey(filter, endFrameNumber+1),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get shard clock frames")
	}

	return &PebbleClockIterator{i: iter, db: p}, nil
}

func (p *PebbleClockStore) SetLatestShardClockFrameNumber(
	filter []byte,
	frameNumber uint64,
) error {
	err := p.db.Set(
		clockShardLatestIndex(filter),
		binary.BigEndian.AppendUint64(nil, frameNumber),
	)

	return errors.Wrap(err, "set latest shard clock frame number")
}

func (p *PebbleClockStore) DeleteGlobalClockFrameRange(
	minFrameNumber uint64,
	maxFrameNumber uint64,
) error {
	err := p.db.DeleteRange(
		clockGlobalFrameKey(minFrameNumber),
		clockGlobalFrameKey(maxFrameNumber),
	)

	return errors.Wrap(err, "delete global clock frame range")
}

func (p *PebbleClockStore) DeleteShardClockFrameRange(
	filter []byte,
	fromFrameNumber uint64,
	toFrameNumber uint64,
) error {
	txn, err := p.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "delete shard clock frame range")
	}

	for i := fromFrameNumber; i < toFrameNumber; i++ {
		if err := txn.DeleteRange(
			clockShardParentIndexKey(filter, i, bytes.Repeat([]byte{0x00}, 32)),
			clockShardParentIndexKey(filter, i, bytes.Repeat([]byte{0xff}, 32)),
		); err != nil {
			if !errors.Is(err, pebble.ErrNotFound) {
				_ = txn.Abort()
				return errors.Wrap(err, "delete shard clock frame range")
			}
		}

		if err := txn.Delete(clockShardFrameKey(filter, i)); err != nil {
			if !errors.Is(err, pebble.ErrNotFound) {
				_ = txn.Abort()
				return errors.Wrap(err, "delete shard clock frame range")
			}
		}

		// The prover trie keys are not stored continuously with respect
		// to the same frame number. As such, we need to manually iterate
		// and discover such keys.
		for t := uint16(0); true; t++ {
			_, closer, err := p.db.Get(clockProverTrieKey(filter, t, i))
			if err != nil {
				if !errors.Is(err, pebble.ErrNotFound) {
					_ = txn.Abort()
					return errors.Wrap(err, "delete shard clock frame range")
				} else {
					break
				}
			}
			_ = closer.Close()
			if err := txn.Delete(clockProverTrieKey(filter, t, i)); err != nil {
				_ = txn.Abort()
				return errors.Wrap(err, "delete shard clock frame range")
			}
		}

		if err := txn.DeleteRange(
			clockDataTotalDistanceKey(filter, i, bytes.Repeat([]byte{0x00}, 32)),
			clockDataTotalDistanceKey(filter, i, bytes.Repeat([]byte{0xff}, 32)),
		); err != nil {
			if !errors.Is(err, pebble.ErrNotFound) {
				_ = txn.Abort()
				return errors.Wrap(err, "delete shard clock frame range")
			}
		}
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "delete shard clock frame range")
	}

	return nil
}

func (p *PebbleClockStore) ResetGlobalClockFrames() error {
	if err := p.db.DeleteRange(
		clockGlobalFrameKey(0),
		clockGlobalFrameKey(20000000),
	); err != nil {
		return errors.Wrap(err, "reset global clock frames")
	}

	if err := p.db.Delete(clockGlobalEarliestIndex()); err != nil {
		return errors.Wrap(err, "reset global clock frames")
	}

	if err := p.db.Delete(clockGlobalLatestIndex()); err != nil {
		return errors.Wrap(err, "reset global clock frames")
	}

	return nil
}

func (p *PebbleClockStore) ResetShardClockFrames(filter []byte) error {
	if err := p.db.DeleteRange(
		clockShardFrameKey(filter, 0),
		clockShardFrameKey(filter, 200000),
	); err != nil {
		return errors.Wrap(err, "reset shard clock frames")
	}

	if err := p.db.Delete(clockDataEarliestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset shard clock frames")
	}
	if err := p.db.Delete(clockShardLatestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset shard clock frames")
	}

	return nil
}

func (p *PebbleClockStore) Compact(
	dataFilter []byte,
) error {

	return nil
}

func (p *PebbleClockStore) GetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) (*big.Int, error) {
	value, closer, err := p.db.Get(
		clockDataTotalDistanceKey(filter, frameNumber, selector),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get total distance")
	}
	defer closer.Close()
	dist := new(big.Int).SetBytes(value)
	return dist, nil
}

func (p *PebbleClockStore) SetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	totalDistance *big.Int,
) error {
	err := p.db.Set(
		clockDataTotalDistanceKey(filter, frameNumber, selector),
		totalDistance.Bytes(),
	)

	return errors.Wrap(err, "set total distance")
}

func (p *PebbleClockStore) GetPeerSeniorityMap(filter []byte) (
	map[string]uint64,
	error,
) {
	value, closer, err := p.db.Get(clockDataSeniorityKey(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get peer seniority map")
	}
	defer closer.Close()
	var b bytes.Buffer
	b.Write(value)
	dec := gob.NewDecoder(&b)
	var seniorityMap map[string]uint64
	if err = dec.Decode(&seniorityMap); err != nil {
		return nil, errors.Wrap(err, "get peer seniority map")
	}
	return seniorityMap, nil
}

func (p *PebbleClockStore) PutPeerSeniorityMap(
	txn store.Transaction,
	filter []byte,
	seniorityMap map[string]uint64,
) error {
	b := new(bytes.Buffer)
	enc := gob.NewEncoder(b)

	if err := enc.Encode(&seniorityMap); err != nil {
		return errors.Wrap(err, "put peer seniority map")
	}

	return errors.Wrap(
		txn.Set(clockDataSeniorityKey(filter), b.Bytes()),
		"put peer seniority map",
	)
}

func (p *PebbleClockStore) SetProverTriesForGlobalFrame(
	frame *protobufs.GlobalFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
) error {
	// For global frames, filter is typically empty
	filter := []byte{}
	frameNumber := frame.Header.FrameNumber

	start := 0
	for i, proverTrie := range tries {
		proverData, err := proverTrie.Serialize()
		if err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}

		if err = p.db.Set(
			clockProverTrieKey(filter, uint16(i), frameNumber),
			proverData,
		); err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}
		start = i
	}

	start++
	for {
		_, closer, err := p.db.Get(
			clockProverTrieKey(filter, uint16(start), frameNumber),
		)
		if err != nil {
			if !errors.Is(err, pebble.ErrNotFound) {
				return errors.Wrap(err, "set prover tries for frame")
			}
			break
		}
		_ = closer.Close()

		if err = p.db.Delete(
			clockProverTrieKey(filter, uint16(start), frameNumber),
		); err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}

		start++
	}

	return nil
}

func (p *PebbleClockStore) SetProverTriesForShardFrame(
	frame *protobufs.AppShardFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
) error {
	filter := frame.Header.Address
	frameNumber := frame.Header.FrameNumber

	start := 0
	for i, proverTrie := range tries {
		proverData, err := proverTrie.Serialize()
		if err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}

		if err = p.db.Set(
			clockProverTrieKey(filter, uint16(i), frameNumber),
			proverData,
		); err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}
		start = i
	}

	start++
	for {
		_, closer, err := p.db.Get(
			clockProverTrieKey(filter, uint16(start), frameNumber),
		)
		if err != nil {
			if !errors.Is(err, pebble.ErrNotFound) {
				return errors.Wrap(err, "set prover tries for frame")
			}
			break
		}
		_ = closer.Close()

		if err = p.db.Delete(
			clockProverTrieKey(filter, uint16(start), frameNumber),
		); err != nil {
			return errors.Wrap(err, "set prover tries for frame")
		}

		start++
	}

	return nil
}

func (p *PebbleClockStore) GetShardStateTree(filter []byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	data, closer, err := p.db.Get(clockShardStateTreeKey(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get data state tree")
	}
	defer closer.Close()
	tree := &tries.VectorCommitmentTree{}
	var b bytes.Buffer
	b.Write(data)
	dec := gob.NewDecoder(&b)
	if err = dec.Decode(tree); err != nil {
		return nil, errors.Wrap(err, "get data state tree")
	}

	return tree, nil
}

func (p *PebbleClockStore) SetShardStateTree(
	txn store.Transaction,
	filter []byte,
	tree *tries.VectorCommitmentTree,
) error {
	b := new(bytes.Buffer)
	enc := gob.NewEncoder(b)

	if err := enc.Encode(tree); err != nil {
		return errors.Wrap(err, "set data state tree")
	}

	return errors.Wrap(
		txn.Set(clockShardStateTreeKey(filter), b.Bytes()),
		"set data state tree",
	)
}
