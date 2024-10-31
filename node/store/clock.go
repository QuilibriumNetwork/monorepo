package store

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/cockroachdb/pebble"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type ClockStore interface {
	NewTransaction() (Transaction, error)
	GetLatestMasterClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetEarliestMasterClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetMasterClockFrame(
		filter []byte,
		frameNumber uint64,
	) (*protobufs.ClockFrame, error)
	RangeMasterClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (*PebbleMasterClockIterator, error)
	PutMasterClockFrame(frame *protobufs.ClockFrame, txn Transaction) error
	GetLatestDataClockFrame(
		filter []byte,
	) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error)
	GetEarliestDataClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetDataClockFrame(
		filter []byte,
		frameNumber uint64,
		truncate bool,
	) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error)
	RangeDataClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (*PebbleClockIterator, error)
	CommitDataClockFrame(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		proverTries []*tries.RollingFrecencyCritbitTrie,
		txn Transaction,
		backfill bool,
	) error
	StageDataClockFrame(
		selector []byte,
		frame *protobufs.ClockFrame,
		txn Transaction,
	) error
	GetStagedDataClockFrame(
		filter []byte,
		frameNumber uint64,
		parentSelector []byte,
		truncate bool,
	) (*protobufs.ClockFrame, error)
	GetStagedDataClockFramesForFrameNumber(
		filter []byte,
		frameNumber uint64,
	) ([]*protobufs.ClockFrame, error)
	SetLatestDataClockFrameNumber(
		filter []byte,
		frameNumber uint64,
	) error
	ResetMasterClockFrames(filter []byte) error
	ResetDataClockFrames(filter []byte) error
	Compact(
		dataFilter []byte,
	) error
	GetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
	) (*big.Int, error)
	SetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		totalDistance *big.Int,
	) error
}

type PebbleClockStore struct {
	db     KVDB
	logger *zap.Logger
}

var _ ClockStore = (*PebbleClockStore)(nil)

type PebbleMasterClockIterator struct {
	i Iterator
}

type PebbleClockIterator struct {
	i  Iterator
	db *PebbleClockStore
}

var _ TypedIterator[*protobufs.ClockFrame] = (*PebbleMasterClockIterator)(nil)
var _ TypedIterator[*protobufs.ClockFrame] = (*PebbleClockIterator)(nil)

func (p *PebbleMasterClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleMasterClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleMasterClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleMasterClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	key := p.i.Key()
	value := p.i.Value()
	frame := &protobufs.ClockFrame{}

	frameNumber, filter, err := extractFrameNumberAndFilterFromMasterFrameKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame iterator value")
	}

	frame.FrameNumber = frameNumber
	frame.Filter = make([]byte, len(filter))
	copy(frame.Filter, filter)

	if len(value) < 521 {
		return nil, errors.Wrap(
			ErrInvalidData,
			"get master clock frame iterator value",
		)
	}

	copied := make([]byte, len(value))
	copy(copied, value)

	frame.Difficulty = binary.BigEndian.Uint32(copied[:4])
	frame.Input = copied[4 : len(copied)-516]
	frame.Output = copied[len(copied)-516:]

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame iterator value")
	}

	frame.ParentSelector = parent.FillBytes(make([]byte, 32))

	return frame, nil
}

func (p *PebbleMasterClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing master clock iterator")
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
	*protobufs.ClockFrame,
	error,
) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	if len(value) == (len(p.i.Key()) + 32) {
		frameValue, frameCloser, err := p.db.db.Get(value)
		if err != nil {
			return nil, errors.Wrap(err, "get truncated clock frame iterator value")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get truncated clock frame iterator value",
			)
		}
		frameCloser.Close()
	} else {
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get truncated clock frame iterator value",
			)
		}
	}

	return frame, nil
}

func (p *PebbleClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	genesisFramePreIndex := false

	// We do a bit of a cheap trick here while things are still stuck in the old
	// ways: we use the size of the parent index key to determine if it's the new
	// format, or the old raw frame
	if len(value) == (len(p.i.Key()) + 32) {
		frameValue, frameCloser, err := p.db.db.Get(value)
		if err != nil {
			return nil, errors.Wrap(err, "get clock frame iterator value")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
		defer frameCloser.Close()
	} else {
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
		genesisFramePreIndex = frame.FrameNumber == 0
	}

	if err := p.db.fillAggregateProofs(frame, genesisFramePreIndex); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get clock frame iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing clock frame iterator")
}

func NewPebbleClockStore(db KVDB, logger *zap.Logger) *PebbleClockStore {
	return &PebbleClockStore{
		db,
		logger,
	}
}

const CLOCK_FRAME = 0x00
const CLOCK_MASTER_FRAME_DATA = 0x00
const CLOCK_DATA_FRAME_DATA = 0x01
const CLOCK_DATA_FRAME_CANDIDATE_DATA = 0x02
const CLOCK_DATA_FRAME_FRECENCY_DATA = 0x03
const CLOCK_DATA_FRAME_DISTANCE_DATA = 0x04
const CLOCK_COMPACTION_DATA = 0x05
const CLOCK_MASTER_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_LATEST = 0x20 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_PARENT = 0x30 | CLOCK_MASTER_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_LATEST = 0x20 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_PARENT = 0x30 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_CANDIDATE_INDEX_LATEST = 0x20 |
	CLOCK_DATA_FRAME_CANDIDATE_DATA

//
// DB Keys
//
// Keys are structured as:
// <core type><sub type | index>[<non-index increment>]<segment>
// Increment necessarily must be full width – elsewise the frame number would
// easily produce conflicts if filters are stepped by byte:
// 0x01 || 0xffff == 0x01ff || 0xff
//
// Master frames are serialized as output data only, Data frames are raw
// protobufs for fast disk-to-network output.

func clockFrameKey(filter []byte, frameNumber uint64, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	return key
}

func clockMasterFrameKey(filter []byte, frameNumber uint64) []byte {
	return clockFrameKey(filter, frameNumber, CLOCK_MASTER_FRAME_DATA)
}

func extractFrameNumberAndFilterFromMasterFrameKey(
	key []byte,
) (uint64, []byte, error) {
	if len(key) < 11 {
		return 0, nil, errors.Wrap(
			ErrInvalidData,
			"extract frame number and filter from master frame key",
		)
	}

	copied := make([]byte, len(key))
	copy(copied, key)
	return binary.BigEndian.Uint64(copied[2:10]), copied[10:], nil
}

func clockDataFrameKey(
	filter []byte,
	frameNumber uint64,
) []byte {
	return clockFrameKey(filter, frameNumber, CLOCK_DATA_FRAME_DATA)
}

func clockLatestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockMasterLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_MASTER_FRAME_INDEX_LATEST)
}

func clockDataLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_DATA_FRAME_INDEX_LATEST)
}

func clockDataCandidateLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_DATA_FRAME_CANDIDATE_INDEX_LATEST)
}

func clockEarliestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockMasterEarliestIndex(filter []byte) []byte {
	return clockEarliestIndex(filter, CLOCK_MASTER_FRAME_INDEX_EARLIEST)
}

func clockDataEarliestIndex(filter []byte) []byte {
	return clockEarliestIndex(filter, CLOCK_DATA_FRAME_INDEX_EARLIEST)
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

func clockDataParentIndexKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) []byte {
	return clockParentIndexKey(
		filter,
		frameNumber,
		rightAlign(selector, 32),
		CLOCK_DATA_FRAME_INDEX_PARENT,
	)
}

func clockDataCandidateFrameKey(
	filter []byte,
	frameNumber uint64,
	parent []byte,
	distance []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_CANDIDATE_DATA}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(parent, 32)...)
	key = append(key, rightAlign(distance, 32)...)
	return key
}

func clockProverTrieKey(filter []byte, ring uint16, frameNumber uint64) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_FRECENCY_DATA}
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
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_DISTANCE_DATA}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(selector, 32)...)
	return key
}

func (p *PebbleClockStore) NewTransaction() (Transaction, error) {
	return p.db.NewBatch(), nil
}

// GetEarliestMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestMasterClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockMasterEarliestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest master clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetMasterClockFrame(filter, frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest master clock frame")
	}

	return frame, nil
}

// GetLatestMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestMasterClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockMasterLatestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest master clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetMasterClockFrame(filter, frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get latest master clock frame")
	}

	return frame, nil
}

// GetMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetMasterClockFrame(
	filter []byte,
	frameNumber uint64,
) (*protobufs.ClockFrame, error) {
	value, closer, err := p.db.Get(clockMasterFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get master clock frame")
	}

	copied := make([]byte, len(value))
	copy(copied[:], value[:])

	defer closer.Close()
	frame := &protobufs.ClockFrame{}
	frame.FrameNumber = frameNumber
	frame.Filter = filter
	frame.Difficulty = binary.BigEndian.Uint32(copied[:4])
	frame.Input = copied[4 : len(copied)-516]
	frame.Output = copied[len(copied)-516:]

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame")
	}

	frame.ParentSelector = parent.FillBytes(make([]byte, 32))

	return frame, nil
}

// RangeMasterClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeMasterClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (*PebbleMasterClockIterator, error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockMasterFrameKey(filter, startFrameNumber),
		clockMasterFrameKey(filter, endFrameNumber),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range master clock frames")
	}

	return &PebbleMasterClockIterator{i: iter}, nil
}

// PutMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) PutMasterClockFrame(
	frame *protobufs.ClockFrame,
	txn Transaction,
) error {
	data := binary.BigEndian.AppendUint32([]byte{}, frame.Difficulty)
	data = append(data, frame.Input...)
	data = append(data, frame.Output...)

	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frame.FrameNumber)

	if err := txn.Set(
		clockMasterFrameKey(frame.Filter, frame.FrameNumber),
		data,
	); err != nil {
		return errors.Wrap(err, "put master clock frame")
	}

	_, closer, err := p.db.Get(clockMasterEarliestIndex(frame.Filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "put master clock frame")
		}

		if err = txn.Set(
			clockMasterEarliestIndex(frame.Filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "put master clock frame")
		}
	}

	if err == nil && closer != nil {
		closer.Close()
	}

	if err = txn.Set(
		clockMasterLatestIndex(frame.Filter),
		frameNumberBytes,
	); err != nil {
		return errors.Wrap(err, "put master clock frame")
	}

	return nil
}

// GetDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetDataClockFrame(
	filter []byte,
	frameNumber uint64,
	truncate bool,
) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	value, closer, err := p.db.Get(clockDataFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get data clock frame")
	}

	frame := &protobufs.ClockFrame{}
	genesisFramePreIndex := false

	// We do a bit of a cheap trick here while things are still stuck in the old
	// ways: we use the size of the parent index key to determine if it's the new
	// format, or the old raw frame
	if len(value) == (len(filter) + 42) {
		frameValue, frameCloser, err := p.db.Get(value)
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				return nil, nil, ErrNotFound
			}

			return nil, nil, errors.Wrap(err, "get data clock frame")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}
		closer.Close()
		defer frameCloser.Close()
	} else {
		genesisFramePreIndex = frameNumber == 0
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}
		defer closer.Close()
	}

	if !truncate {
		if err = p.fillAggregateProofs(frame, genesisFramePreIndex); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}

		proverTries := []*tries.RollingFrecencyCritbitTrie{}
		i := uint16(0)
		for {
			proverTrie := &tries.RollingFrecencyCritbitTrie{}
			trieData, closer, err := p.db.Get(clockProverTrieKey(filter, i, frameNumber))
			if err != nil {
				break
			}

			if err := proverTrie.Deserialize(trieData); err != nil {
				closer.Close()
				return nil, nil, errors.Wrap(err, "get latest data clock frame")
			}

			closer.Close()
			i++
			proverTries = append(proverTries, proverTrie)
		}

		return frame, proverTries, nil
	}

	return frame, nil, nil
}

func (p *PebbleClockStore) fillAggregateProofs(
	frame *protobufs.ClockFrame,
	genesisFramePreIndex bool,
) error {
	if frame.FrameNumber == 0 && genesisFramePreIndex {
		return nil
	}

	for i := 0; i < len(frame.Input[516:])/74; i++ {
		commit := frame.Input[516+(i*74) : 516+((i+1)*74)]
		ap, err := internalGetAggregateProof(
			p.db,
			frame.Filter,
			commit,
			frame.FrameNumber,
		)
		if err != nil {
			return err
		}

		frame.AggregateProofs = append(frame.AggregateProofs, ap)
	}

	return nil
}

func (p *PebbleClockStore) saveAggregateProofs(
	txn Transaction,
	frame *protobufs.ClockFrame,
) error {
	shouldClose := false
	if txn == nil {
		var err error
		txn, err = p.NewTransaction()
		if err != nil {
			return err
		}

		shouldClose = true
	}

	for i := 0; i < len(frame.Input[516:])/74; i++ {
		commit := frame.Input[516+(i*74) : 516+((i+1)*74)]
		err := internalPutAggregateProof(
			p.db,
			txn,
			frame.AggregateProofs[i],
			commit,
		)
		if err != nil {
			if err = txn.Abort(); err != nil {
				return err
			}
		}
	}

	if shouldClose {
		txn.Commit()
	}

	return nil
}

// GetEarliestDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestDataClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest data clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, _, err := p.GetDataClockFrame(filter, frameNumber, false)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest data clock frame")
	}

	return frame, nil
}

// GetLatestDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestDataClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	idxValue, closer, err := p.db.Get(clockDataLatestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get latest data clock frame")
	}

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, tries, err := p.GetDataClockFrame(filter, frameNumber, false)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get latest data clock frame")
	}

	closer.Close()

	return frame, tries, nil
}

// GetStagedDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetStagedDataClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
	truncate bool,
) (*protobufs.ClockFrame, error) {
	data, closer, err := p.db.Get(
		clockDataParentIndexKey(filter, frameNumber, parentSelector),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(ErrNotFound, "get parent data clock frame")
		}
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	parent := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(data, parent); err != nil {
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	if !truncate {
		if err := p.fillAggregateProofs(parent, false); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
	}

	if closer != nil {
		closer.Close()
	}

	return parent, nil
}

func (p *PebbleClockStore) GetStagedDataClockFramesForFrameNumber(
	filter []byte,
	frameNumber uint64,
) ([]*protobufs.ClockFrame, error) {
	iter, err := p.db.NewIter(
		clockDataParentIndexKey(filter, frameNumber, bytes.Repeat([]byte{0x00}, 32)),
		clockDataParentIndexKey(filter, frameNumber, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(ErrNotFound, "get staged data clock frames")
		}
		return nil, errors.Wrap(err, "get staged data clock frames")
	}

	frames := []*protobufs.ClockFrame{}

	for iter.First(); iter.Valid(); iter.Next() {
		data := iter.Value()
		frame := &protobufs.ClockFrame{}
		if err := proto.Unmarshal(data, frame); err != nil {
			return nil, errors.Wrap(err, "get staged data clock frames")
		}

		if err := p.fillAggregateProofs(frame, false); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get staged data clock frames",
			)
		}

		frames = append(frames, frame)
	}

	iter.Close()

	return frames, nil
}

// StageDataClockFrame implements ClockStore.
func (p *PebbleClockStore) StageDataClockFrame(
	selector []byte,
	frame *protobufs.ClockFrame,
	txn Transaction,
) error {
	if err := p.saveAggregateProofs(txn, frame); err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"stage data clock frame",
		)
	}

	temp := append(
		[]*protobufs.InclusionAggregateProof{},
		frame.AggregateProofs...,
	)
	frame.AggregateProofs = []*protobufs.InclusionAggregateProof{}

	data, err := proto.Marshal(frame)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"stage data clock frame",
		)
	}

	frame.AggregateProofs = temp

	if err = txn.Set(
		clockDataParentIndexKey(
			frame.Filter,
			frame.FrameNumber,
			selector,
		),
		data,
	); err != nil {
		return errors.Wrap(err, "stage data clock frame")
	}

	return nil
}

// CommitDataClockFrame implements ClockStore.
func (p *PebbleClockStore) CommitDataClockFrame(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	proverTries []*tries.RollingFrecencyCritbitTrie,
	txn Transaction,
	backfill bool,
) error {
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frameNumber)

	if err := txn.Set(
		clockDataFrameKey(filter, frameNumber),
		clockDataParentIndexKey(filter, frameNumber, selector),
	); err != nil {
		return errors.Wrap(err, "commit data clock frame")
	}

	for i, proverTrie := range proverTries {
		proverData, err := proverTrie.Serialize()
		if err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}

		if err = txn.Set(
			clockProverTrieKey(filter, uint16(i), frameNumber),
			proverData,
		); err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}
	}

	_, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "commit data clock frame")
		}

		if err = txn.Set(
			clockDataEarliestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}
	}

	if err == nil && closer != nil {
		closer.Close()
	}

	if !backfill {
		if err = txn.Set(
			clockDataLatestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}
	}

	return nil
}

// RangeDataClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeDataClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (*PebbleClockIterator, error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockDataFrameKey(filter, startFrameNumber),
		clockDataFrameKey(filter, endFrameNumber),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get data clock frames")
	}

	return &PebbleClockIterator{i: iter, db: p}, nil
}

func (p *PebbleClockStore) SetLatestDataClockFrameNumber(
	filter []byte,
	frameNumber uint64,
) error {
	err := p.db.Set(
		clockDataLatestIndex(filter),
		binary.BigEndian.AppendUint64(nil, frameNumber),
	)

	return errors.Wrap(err, "set latest data clock frame number")
}

func (p *PebbleClockStore) DeleteDataClockFrameRange(
	filter []byte,
	fromFrameNumber uint64,
	toFrameNumber uint64,
) error {
	err := p.db.DeleteRange(
		clockDataFrameKey(
			filter,
			fromFrameNumber,
		),
		clockDataFrameKey(
			filter,
			toFrameNumber,
		),
	)
	return errors.Wrap(err, "delete data clock frame range")
}

func (p *PebbleClockStore) ResetMasterClockFrames(filter []byte) error {
	if err := p.db.DeleteRange(
		clockMasterFrameKey(filter, 0),
		clockMasterFrameKey(filter, 20000000),
	); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	if err := p.db.Delete(clockMasterEarliestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	if err := p.db.Delete(clockMasterLatestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	return nil
}

func (p *PebbleClockStore) ResetDataClockFrames(filter []byte) error {
	if err := p.db.DeleteRange(
		clockDataFrameKey(filter, 0),
		clockDataFrameKey(filter, 200000),
	); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}

	if err := p.db.Delete(clockDataEarliestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}
	if err := p.db.Delete(clockDataLatestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}

	return nil
}

func (p *PebbleClockStore) Compact(
	dataFilter []byte,
) error {
	version, closer, err := p.db.Get([]byte{CLOCK_COMPACTION_DATA})
	cleared := true
	if err != nil {
		cleared = false
	} else {
		if bytes.Compare(version, config.GetVersion()) < 0 {
			cleared = false
		}
		closer.Close()
	}

	if !cleared {
		if err := p.db.Compact(
			clockDataCandidateFrameKey(
				make([]byte, 32),
				0,
				make([]byte, 32),
				make([]byte, 32),
			),
			clockDataCandidateFrameKey(
				bytes.Repeat([]byte{0xff}, 32),
				1000000,
				bytes.Repeat([]byte{0xff}, 32),
				bytes.Repeat([]byte{0xff}, 32),
			),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.DeleteRange(
			clockDataParentIndexKey(
				make([]byte, 32),
				0,
				make([]byte, 32),
			),
			clockDataParentIndexKey(
				bytes.Repeat([]byte{0xff}, 32),
				0,
				bytes.Repeat([]byte{0xff}, 32),
			),
		); err != nil {
			return errors.Wrap(err, "compact")
		}
	}

	if dataFilter != nil && !cleared {
		parents := [][]byte{}
		proofs := map[string]struct{}{}
		commits := map[string]struct{}{}
		data := map[string]struct{}{}

		idxValue, closer, err := p.db.Get(clockDataLatestIndex(dataFilter))
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				return ErrNotFound
			}

			return errors.Wrap(err, "compact")
		}

		last := binary.BigEndian.Uint64(idxValue)

		closer.Close()

		for frameNumber := uint64(1); frameNumber <= last; frameNumber++ {
			value, closer, err := p.db.Get(clockDataFrameKey(dataFilter, frameNumber))
			if err != nil {
				if errors.Is(err, pebble.ErrNotFound) {
					return ErrNotFound
				}

				return errors.Wrap(err, "compact")
			}

			frame := &protobufs.ClockFrame{}

			if len(value) == (len(dataFilter) + 42) {
				frameValue, frameCloser, err := p.db.Get(value)
				if err != nil {
					return errors.Wrap(err, "compact")
				}
				if err := proto.Unmarshal(frameValue, frame); err != nil {
					return errors.Wrap(err, "compact")
				}

				selector, err := frame.GetSelector()
				if err != nil {
					panic(err)
				}

				parents = append(parents,
					clockDataParentIndexKey(dataFilter, frameNumber, selector.FillBytes(
						make([]byte, 32),
					)),
				)

				closer.Close()
				frameCloser.Close()
			} else {
				if err := proto.Unmarshal(value, frame); err != nil {
					return errors.Wrap(err, "compact")
				}

				selector, err := frame.GetSelector()
				if err != nil {
					panic(err)
				}

				err = p.db.Set(
					clockDataParentIndexKey(dataFilter, frameNumber, selector.FillBytes(
						make([]byte, 32),
					)),
					value,
				)
				if err != nil {
					return errors.Wrap(err, "compact")
				}

				err = p.db.Set(
					clockDataFrameKey(dataFilter, frameNumber),
					clockDataParentIndexKey(dataFilter, frameNumber, selector.FillBytes(
						make([]byte, 32),
					)),
				)

				parents = append(parents,
					clockDataParentIndexKey(dataFilter, frameNumber, selector.FillBytes(
						make([]byte, 32),
					)),
				)

				closer.Close()
			}

			for i := 0; i < len(frame.Input[516:])/74; i++ {
				p.logger.Info(
					"preparing indexes for frame compaction",
					zap.Uint64("frame_number", frameNumber),
					zap.Uint64("max_frame_number", last),
				)
				commit := frame.Input[516+(i*74) : 516+((i+1)*74)]
				frameProofs, frameCommits, frameData, err :=
					internalListAggregateProofKeys(
						p.db,
						dataFilter,
						commit,
						frameNumber,
					)
				if err != nil {
					return errors.Wrap(err, "compact")
				}
				for _, proof := range frameProofs {
					proof := proof
					proofs[string(proof)] = struct{}{}
				}
				for _, comm := range frameCommits {
					comm := comm
					commits[string(comm)] = struct{}{}
				}
				for _, d := range frameData {
					d := d
					data[string(d)] = struct{}{}
				}
			}
		}

		p.logger.Info("sorting indexes for bulk clear")

		sortedProofKeys := [][]byte{}
		for k := range proofs {
			k := k
			sortedProofKeys = append(sortedProofKeys, []byte(k))
		}
		proofs = nil
		sort.Slice(sortedProofKeys, func(i, j int) bool {
			return bytes.Compare(sortedProofKeys[i], sortedProofKeys[j]) < 0
		})

		sortedCommitKeys := [][]byte{}
		for k := range commits {
			k := k
			sortedCommitKeys = append(sortedCommitKeys, []byte(k))
		}
		commits = nil
		sort.Slice(sortedCommitKeys, func(i, j int) bool {
			return bytes.Compare(sortedCommitKeys[i], sortedCommitKeys[j]) < 0
		})

		sortedDataKeys := [][]byte{}
		for k := range data {
			k := k
			sortedDataKeys = append(sortedDataKeys, []byte(k))
		}
		data = nil
		sort.Slice(sortedDataKeys, func(i, j int) bool {
			return bytes.Compare(sortedDataKeys[i], sortedDataKeys[j]) < 0
		})

		for i := uint64(0); i < uint64(len(parents)); i++ {
			p.logger.Info(
				"clearing orphaned frames for frame number",
				zap.Uint64("frame_number", i+1),
				zap.Int("max_frame_number", len(parents)),
			)
			pre := clockDataParentIndexKey(
				dataFilter,
				i+1,
				bytes.Repeat([]byte{0x00}, 32),
			)

			err := p.db.DeleteRange(
				pre,
				parents[i],
			)
			if err != nil {
				return errors.Wrap(err, "compact")
			}
			start := new(big.Int).SetBytes(parents[i])
			start.Add(start, big.NewInt(1))
			startBytes := start.FillBytes(make([]byte, len(parents[i])))
			post := clockDataParentIndexKey(
				dataFilter,
				i+1,
				bytes.Repeat([]byte{0xff}, 32),
			)

			err = p.db.DeleteRange(
				startBytes,
				post,
			)
			if err != nil {
				return errors.Wrap(err, "compact")
			}
		}

		for i := -1; i < len(sortedProofKeys); i++ {
			p.logger.Info(
				"clearing orphaned proof metadata",
				zap.Int("proof_range_index", i+1),
				zap.Int("max_proof_range_index", len(sortedProofKeys)),
			)
			var start, end []byte
			if i == -1 {
				start = dataProofMetadataKey(
					dataFilter,
					bytes.Repeat([]byte{0x00}, 74),
				)
			} else {
				startBI := new(big.Int).SetBytes(sortedProofKeys[i])
				startBI.Add(startBI, big.NewInt(1))
				start = startBI.FillBytes(make([]byte, len(sortedProofKeys[i])))
			}

			if i == len(sortedProofKeys)-1 {
				end = dataProofMetadataKey(
					dataFilter,
					bytes.Repeat([]byte{0xff}, 74),
				)
			} else {
				end = sortedProofKeys[i+1]
			}
			err := p.db.DeleteRange(
				start,
				end,
			)
			if err != nil {
				return errors.Wrap(err, "compact")
			}
		}

		for i := -1; i < len(sortedCommitKeys); i++ {
			p.logger.Info(
				"clearing orphaned commits",
				zap.Int("commit_range_index", i+1),
				zap.Int("max_commit_range_index", len(sortedProofKeys)),
			)
			var start, end []byte
			if i == -1 {
				start = dataProofInclusionKey(
					dataFilter,
					bytes.Repeat([]byte{0x00}, 74),
					0,
				)
			} else {
				start = make([]byte, len(sortedCommitKeys[i]))
				copy(start[:], sortedCommitKeys[i][:])
				start[74] = 0xff
				start[75] = 0xff
				start[76] = 0xff
				start[77] = 0xff
				start[78] = 0xff
				start[79] = 0xff
				start[80] = 0xff
				start[81] = 0xff
			}

			if i == len(sortedCommitKeys)-1 {
				end = dataProofInclusionKey(
					dataFilter,
					bytes.Repeat([]byte{0xff}, 74),
					0xffffffffffffffff,
				)
			} else {
				end = sortedCommitKeys[i+1]
			}

			err := p.db.DeleteRange(
				start,
				end,
			)
			if err != nil {
				return errors.Wrap(err, "compact")
			}
		}

		for i := -1; i < len(sortedDataKeys); i++ {
			p.logger.Info(
				"clearing orphaned data",
				zap.Int("data_range_index", i+1),
				zap.Int("max_data_range_index", len(sortedProofKeys)),
			)
			var start, end []byte
			if i == -1 {
				start = dataProofSegmentKey(
					dataFilter,
					bytes.Repeat([]byte{0x00}, 32),
				)
			} else {
				startBI := new(big.Int).SetBytes(sortedDataKeys[i])
				startBI.Add(startBI, big.NewInt(1))
				start = startBI.FillBytes(make([]byte, len(sortedDataKeys[i])))
			}

			if i == len(sortedDataKeys)-1 {
				end = dataProofSegmentKey(
					dataFilter,
					bytes.Repeat([]byte{0xff}, 32),
				)
			} else {
				end = sortedDataKeys[i+1]
			}

			err := p.db.DeleteRange(
				start,
				end,
			)
			if err != nil {
				return errors.Wrap(err, "compact")
			}
		}

		if err := p.db.DeleteRange(
			clockDataCandidateFrameKey(
				dataFilter,
				0,
				make([]byte, 32),
				make([]byte, 32),
			),
			clockDataCandidateFrameKey(
				dataFilter,
				1000000,
				bytes.Repeat([]byte{0xff}, 32),
				bytes.Repeat([]byte{0xff}, 32),
			),
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		err = p.db.Set([]byte{CLOCK_COMPACTION_DATA}, config.GetVersion())
		if err != nil {
			return errors.Wrap(err, "compact")
		}
	}

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
			return nil, ErrNotFound
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
