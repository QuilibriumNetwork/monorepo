package store

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math/big"
	"slices"

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
	filter []byte
	start  uint64
	end    uint64
	cur    uint64
	db     *PebbleClockStore
}

type PebbleGlobalStateIterator struct {
	i  store.Iterator
	db *PebbleClockStore
}

type PebbleAppShardStateIterator struct {
	filter []byte
	start  uint64
	end    uint64
	cur    uint64
	db     *PebbleClockStore
}

type PebbleQuorumCertificateIterator struct {
	filter []byte
	start  uint64
	end    uint64
	cur    uint64
	db     *PebbleClockStore
}

type PebbleTimeoutCertificateIterator struct {
	filter []byte
	start  uint64
	end    uint64
	cur    uint64
	db     *PebbleClockStore
}

var _ store.TypedIterator[*protobufs.GlobalFrame] = (*PebbleGlobalClockIterator)(nil)
var _ store.TypedIterator[*protobufs.AppShardFrame] = (*PebbleClockIterator)(nil)
var _ store.TypedIterator[*protobufs.GlobalProposal] = (*PebbleGlobalStateIterator)(nil)
var _ store.TypedIterator[*protobufs.AppShardProposal] = (*PebbleAppShardStateIterator)(nil)
var _ store.TypedIterator[*protobufs.QuorumCertificate] = (*PebbleQuorumCertificateIterator)(nil)
var _ store.TypedIterator[*protobufs.TimeoutCertificate] = (*PebbleTimeoutCertificateIterator)(nil)

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
	p.cur = p.start
	return true
}

func (p *PebbleClockIterator) Next() bool {
	p.cur++
	return p.cur < p.end
}

func (p *PebbleClockIterator) Prev() bool {
	p.cur--
	return p.cur >= p.start
}

func (p *PebbleClockIterator) Valid() bool {
	return p.cur >= p.start && p.cur < p.end
}

func (p *PebbleClockIterator) TruncatedValue() (
	*protobufs.AppShardFrame,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	return p.Value()
}

func (p *PebbleClockIterator) Value() (*protobufs.AppShardFrame, error) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	frame, _, err := p.db.GetShardClockFrame(p.filter, p.cur, false)
	if err != nil {
		return nil, errors.Wrap(err, "get clock frame iterator value")
	}

	return frame, nil
}

func (p *PebbleClockIterator) Close() error {
	return nil
}

func (p *PebbleGlobalStateIterator) First() bool {
	return p.i.First()
}

func (p *PebbleGlobalStateIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleGlobalStateIterator) Prev() bool {
	return p.i.Prev()
}

func (p *PebbleGlobalStateIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleGlobalStateIterator) Value() (
	*protobufs.GlobalProposal,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	if len(value) != 24 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get certified global state",
		)
	}

	frameNumber := binary.BigEndian.Uint64(value[:8])
	qcRank := binary.BigEndian.Uint64(value[8:16])
	tcRank := binary.BigEndian.Uint64(value[16:])

	frame, err := p.db.GetGlobalClockFrame(frameNumber)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	qc, err := p.db.GetQuorumCertificate(nil, qcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	tc, err := p.db.GetTimeoutCertificate(nil, tcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	return &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     qc,
		PriorRankTimeoutCertificate: tc,
	}, nil
}

func (p *PebbleGlobalStateIterator) TruncatedValue() (
	*protobufs.GlobalProposal,
	error,
) {
	return p.Value()
}

func (p *PebbleGlobalStateIterator) Close() error {
	return p.i.Close()
}

func (p *PebbleAppShardStateIterator) First() bool {
	p.cur = p.start
	return true
}

func (p *PebbleAppShardStateIterator) Next() bool {
	p.cur++
	return p.cur < p.end
}

func (p *PebbleAppShardStateIterator) Prev() bool {
	p.cur--
	return p.cur >= p.start
}

func (p *PebbleAppShardStateIterator) Valid() bool {
	return p.cur >= p.start && p.cur < p.end
}

func (p *PebbleAppShardStateIterator) Close() error {
	return nil
}

func (p *PebbleAppShardStateIterator) Value() (
	*protobufs.AppShardProposal,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	state, err := p.db.GetCertifiedAppShardState(p.filter, p.cur)
	if err != nil {
		return nil, errors.Wrap(err, "get app shard state iterator value")
	}

	return state, nil
}

func (p *PebbleAppShardStateIterator) TruncatedValue() (
	*protobufs.AppShardProposal,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	return p.Value()
}

func (p *PebbleQuorumCertificateIterator) First() bool {
	p.cur = p.start
	return true
}

func (p *PebbleQuorumCertificateIterator) Next() bool {
	p.cur++
	return p.cur < p.end
}

func (p *PebbleQuorumCertificateIterator) Prev() bool {
	p.cur--
	return p.cur >= p.start
}

func (p *PebbleQuorumCertificateIterator) Valid() bool {
	return p.cur >= p.start && p.cur < p.end
}

func (p *PebbleQuorumCertificateIterator) Close() error {
	return nil
}

func (p *PebbleQuorumCertificateIterator) Value() (
	*protobufs.QuorumCertificate,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	qc, err := p.db.GetQuorumCertificate(p.filter, p.cur)
	if err != nil {
		return nil, errors.Wrap(err, "get quorum certificate iterator value")
	}

	return qc, nil
}

func (p *PebbleQuorumCertificateIterator) TruncatedValue() (
	*protobufs.QuorumCertificate,
	error,
) {
	return p.Value()
}

func (p *PebbleTimeoutCertificateIterator) First() bool {
	p.cur = p.start
	return true
}

func (p *PebbleTimeoutCertificateIterator) Next() bool {
	p.cur++
	return p.cur < p.end
}

func (p *PebbleTimeoutCertificateIterator) Prev() bool {
	p.cur--
	return p.cur >= p.start
}

func (p *PebbleTimeoutCertificateIterator) Valid() bool {
	return p.cur >= p.start && p.cur < p.end
}

func (p *PebbleTimeoutCertificateIterator) Close() error {
	return nil
}

func (p *PebbleTimeoutCertificateIterator) Value() (
	*protobufs.TimeoutCertificate,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	tc, err := p.db.GetTimeoutCertificate(p.filter, p.cur)
	if err != nil {
		return nil, errors.Wrap(err, "get timeout certificate iterator value")
	}

	return tc, nil
}

func (p *PebbleTimeoutCertificateIterator) TruncatedValue() (
	*protobufs.TimeoutCertificate,
	error,
) {
	if !p.Valid() {
		return nil, store.ErrNotFound
	}

	return p.Value()
}

func NewPebbleClockStore(db store.KVDB, logger *zap.Logger) *PebbleClockStore {
	return &PebbleClockStore{
		db,
		logger,
	}
}

func (p *PebbleClockStore) updateEarliestIndex(
	txn store.Transaction,
	key []byte,
	rank uint64,
) error {
	existing, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return txn.Set(
				key,
				binary.BigEndian.AppendUint64(nil, rank),
			)
		}
		return err
	}
	defer closer.Close()

	if len(existing) != 8 {
		return errors.Wrap(
			store.ErrInvalidData,
			"earliest index contained unexpected length",
		)
	}

	if binary.BigEndian.Uint64(existing) > rank {
		return txn.Set(
			key,
			binary.BigEndian.AppendUint64(nil, rank),
		)
	}

	return nil
}

func (p *PebbleClockStore) updateLatestIndex(
	txn store.Transaction,
	key []byte,
	rank uint64,
) error {
	existing, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return txn.Set(
				key,
				binary.BigEndian.AppendUint64(nil, rank),
			)
		}
		return err
	}
	defer closer.Close()

	if len(existing) != 8 {
		return errors.Wrap(
			store.ErrInvalidData,
			"latest index contained unexpected length",
		)
	}

	if binary.BigEndian.Uint64(existing) < rank {
		return txn.Set(
			key,
			binary.BigEndian.AppendUint64(nil, rank),
		)
	}

	return nil
}

func deleteIfExists(txn store.Transaction, key []byte) error {
	if err := txn.Delete(key); err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}

//
// DB Keys
//
// Keys are structured as:
// <core type><sub type | index>[<non-index increment>]<segment>
// Increment necessarily must be full width – elsewise the frame number would
// easily produce conflicts if filters are stepped by byte:
// 0x01 || 0xffff == 0x01ff || 0xff

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

func clockGlobalCertifiedStateEarliestIndex() []byte {
	return []byte{CLOCK_FRAME, CLOCK_GLOBAL_CERTIFIED_STATE_INDEX_EARLIEST}
}

func clockShardCertifiedStateEarliestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_SHARD_CERTIFIED_STATE_INDEX_EARLIEST},
		filter,
	)
}

func clockGlobalCertifiedStateLatestIndex() []byte {
	return []byte{CLOCK_FRAME, CLOCK_GLOBAL_CERTIFIED_STATE_INDEX_LATEST}
}

func clockShardCertifiedStateLatestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_SHARD_CERTIFIED_STATE_INDEX_LATEST},
		filter,
	)
}

func clockGlobalCertifiedStateKey(rank uint64) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_GLOBAL_CERTIFIED_STATE}
	key = binary.BigEndian.AppendUint64(key, rank)
	return key
}

func clockShardCertifiedStateKey(rank uint64, filter []byte) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_SHARD_CERTIFIED_STATE}
	key = binary.BigEndian.AppendUint64(key, rank)
	key = append(key, filter...)
	return key
}

func clockQuorumCertificateKey(rank uint64, filter []byte) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_QUORUM_CERTIFICATE}
	key = binary.BigEndian.AppendUint64(key, rank)
	return key
}

func clockQuorumCertificateEarliestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_QUORUM_CERTIFICATE_INDEX_EARLIEST},
		filter,
	)
}

func clockQuorumCertificateLatestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_QUORUM_CERTIFICATE_INDEX_LATEST},
		filter,
	)
}

func clockTimeoutCertificateKey(rank uint64, filter []byte) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_TIMEOUT_CERTIFICATE}
	key = binary.BigEndian.AppendUint64(key, rank)
	key = append(key, filter...)
	return key
}

func clockTimeoutCertificateEarliestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_TIMEOUT_CERTIFICATE_INDEX_EARLIEST},
		filter,
	)
}

func clockTimeoutCertificateLatestIndex(filter []byte) []byte {
	return slices.Concat(
		[]byte{CLOCK_FRAME, CLOCK_TIMEOUT_CERTIFICATE_INDEX_LATEST},
		filter,
	)
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

func clockProposalVoteKey(rank uint64, filter []byte, identity []byte) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_PROPOSAL_VOTE}
	key = binary.BigEndian.AppendUint64(key, rank)
	key = append(key, filter...)
	key = append(key, identity...)
	return key
}

func clockTimeoutVoteKey(rank uint64, filter []byte, identity []byte) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_TIMEOUT_VOTE}
	key = binary.BigEndian.AppendUint64(key, rank)
	key = append(key, filter...)
	key = append(key, identity...)
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

	return &PebbleClockIterator{
		filter: filter,
		start:  startFrameNumber,
		end:    endFrameNumber + 1,
		cur:    startFrameNumber,
		db:     p,
	}, nil
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

func (p *PebbleClockStore) GetLatestCertifiedGlobalState() (
	*protobufs.GlobalProposal,
	error,
) {
	idxValue, closer, err := p.db.Get(clockGlobalCertifiedStateLatestIndex())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get latest certified global state")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get latest certified global state",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetCertifiedGlobalState(rank)
}

func (p *PebbleClockStore) GetEarliestCertifiedGlobalState() (
	*protobufs.GlobalProposal,
	error,
) {
	idxValue, closer, err := p.db.Get(clockGlobalCertifiedStateEarliestIndex())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get earliest certified global state")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get earliest certified global state",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetCertifiedGlobalState(rank)
}

func (p *PebbleClockStore) GetCertifiedGlobalState(rank uint64) (
	*protobufs.GlobalProposal,
	error,
) {
	key := clockGlobalCertifiedStateKey(rank)
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get certified global state")
	}
	defer closer.Close()

	if len(value) != 24 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get certified global state",
		)
	}

	frameNumber := binary.BigEndian.Uint64(value[:8])
	qcRank := binary.BigEndian.Uint64(value[8:16])
	tcRank := binary.BigEndian.Uint64(value[16:])

	frame, err := p.GetGlobalClockFrame(frameNumber)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	vote, err := p.GetProposalVote(nil, frame.GetRank(), frame.Header.Prover)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified app shard state")
	}

	qc, err := p.GetQuorumCertificate(nil, qcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	tc, err := p.GetTimeoutCertificate(nil, tcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified global state")
	}

	return &protobufs.GlobalProposal{
		State:                       frame,
		ParentQuorumCertificate:     qc,
		PriorRankTimeoutCertificate: tc,
		Vote:                        vote,
	}, nil
}

func (p *PebbleClockStore) RangeCertifiedGlobalStates(
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.GlobalProposal], error) {
	if startRank > endRank {
		startRank, endRank = endRank, startRank
	}

	iter, err := p.db.NewIter(
		clockGlobalCertifiedStateKey(startRank),
		clockGlobalCertifiedStateKey(endRank+1),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range certified global states")
	}

	return &PebbleGlobalStateIterator{i: iter, db: p}, nil
}

func (p *PebbleClockStore) PutCertifiedGlobalState(
	state *protobufs.GlobalProposal,
	txn store.Transaction,
) error {
	if state == nil {
		return errors.Wrap(
			errors.New("proposal is required"),
			"put certified global state",
		)
	}

	rank := uint64(0)
	frameNumber := uint64(0xffffffffffffffff)
	qcRank := uint64(0xffffffffffffffff)
	tcRank := uint64(0xffffffffffffffff)
	if state.State != nil {
		if state.State.Header.Rank > rank {
			rank = state.State.Header.Rank
		}
		frameNumber = state.State.Header.FrameNumber
		if err := p.PutGlobalClockFrame(state.State, txn); err != nil {
			return errors.Wrap(err, "put certified global state")
		}
		if err := p.PutProposalVote(txn, state.Vote); err != nil {
			return errors.Wrap(err, "put certified global state")
		}
	}
	if state.ParentQuorumCertificate != nil {
		if state.ParentQuorumCertificate.Rank > rank {
			rank = state.ParentQuorumCertificate.Rank
		}
		qcRank = state.ParentQuorumCertificate.Rank
		if err := p.PutQuorumCertificate(
			state.ParentQuorumCertificate,
			txn,
		); err != nil {
			return errors.Wrap(err, "put certified global state")
		}
	}
	if state.PriorRankTimeoutCertificate != nil {
		if state.PriorRankTimeoutCertificate.Rank > rank {
			rank = state.PriorRankTimeoutCertificate.Rank
		}
		tcRank = state.PriorRankTimeoutCertificate.Rank
		if err := p.PutTimeoutCertificate(
			state.PriorRankTimeoutCertificate,
			txn,
		); err != nil {
			return errors.Wrap(err, "put certified global state")
		}
	}

	key := clockGlobalCertifiedStateKey(rank)
	value := []byte{}
	value = binary.BigEndian.AppendUint64(value, frameNumber)
	value = binary.BigEndian.AppendUint64(value, qcRank)
	value = binary.BigEndian.AppendUint64(value, tcRank)

	if err := txn.Set(key, value); err != nil {
		return errors.Wrap(err, "put certified global state")
	}

	if err := p.updateEarliestIndex(
		txn,
		clockGlobalCertifiedStateEarliestIndex(),
		rank,
	); err != nil {
		return errors.Wrap(err, "put certified global state")
	}

	if err := txn.Set(
		clockGlobalCertifiedStateLatestIndex(),
		binary.BigEndian.AppendUint64(nil, rank),
	); err != nil {
		return errors.Wrap(err, "put certified global state")
	}

	return nil
}

func (p *PebbleClockStore) GetLatestCertifiedAppShardState(
	filter []byte,
) (
	*protobufs.AppShardProposal,
	error,
) {
	idxValue, closer, err := p.db.Get(
		clockShardCertifiedStateLatestIndex([]byte{}),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get latest certified app shard state")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get latest certified app shard state",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetCertifiedAppShardState(filter, rank)
}

func (p *PebbleClockStore) GetEarliestCertifiedAppShardState(
	filter []byte,
) (
	*protobufs.AppShardProposal,
	error,
) {
	idxValue, closer, err := p.db.Get(
		clockShardCertifiedStateEarliestIndex([]byte{}),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get earliest certified app shard state")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get earliest certified app shard state",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetCertifiedAppShardState(filter, rank)
}

func (p *PebbleClockStore) GetCertifiedAppShardState(
	filter []byte,
	rank uint64,
) (
	*protobufs.AppShardProposal,
	error,
) {
	key := clockShardCertifiedStateKey(rank, filter)
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get certified app shard state")
	}
	defer closer.Close()

	if len(value) != 24 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get certified app shard state",
		)
	}

	frameNumber := binary.BigEndian.Uint64(value[:8])
	qcRank := binary.BigEndian.Uint64(value[8:16])
	tcRank := binary.BigEndian.Uint64(value[16:])

	frame, _, err := p.GetShardClockFrame(filter, frameNumber, false)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified app shard state")
	}

	vote, err := p.GetProposalVote(filter, frame.GetRank(), frame.Header.Prover)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified app shard state")
	}

	qc, err := p.GetQuorumCertificate(filter, qcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified app shard state")
	}

	tc, err := p.GetTimeoutCertificate(filter, tcRank)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errors.Wrap(err, "get certified app shard state")
	}

	return &protobufs.AppShardProposal{
		State:                       frame,
		ParentQuorumCertificate:     qc,
		PriorRankTimeoutCertificate: tc,
		Vote:                        vote,
	}, nil
}

func (p *PebbleClockStore) RangeCertifiedAppShardStates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.AppShardProposal], error) {
	if startRank > endRank {
		startRank, endRank = endRank, startRank
	}

	return &PebbleAppShardStateIterator{
		filter: filter,
		start:  startRank,
		end:    endRank + 1,
		cur:    startRank,
		db:     p,
	}, nil
}

func (p *PebbleClockStore) PutCertifiedAppShardState(
	state *protobufs.AppShardProposal,
	txn store.Transaction,
) error {
	if state == nil {
		return errors.Wrap(
			errors.New("proposal is required"),
			"put certified app shard state",
		)
	}

	rank := uint64(0)
	filter := []byte{}
	frameNumber := uint64(0xffffffffffffffff)
	qcRank := uint64(0xffffffffffffffff)
	tcRank := uint64(0xffffffffffffffff)
	if state.State != nil {
		if state.State.Header.Rank > rank {
			rank = state.State.Header.Rank
		}
		frameNumber = state.State.Header.FrameNumber
		if err := p.StageShardClockFrame(
			[]byte(state.State.Identity()),
			state.State,
			txn,
		); err != nil {
			return errors.Wrap(err, "put certified app shard state")
		}
		if err := p.CommitShardClockFrame(
			state.State.Header.Address,
			frameNumber,
			[]byte(state.State.Identity()),
			nil,
			txn,
			false,
		); err != nil {
			return errors.Wrap(err, "put certified app shard state")
		}
		if err := p.PutProposalVote(txn, state.Vote); err != nil {
			return errors.Wrap(err, "put certified app shard state")
		}
		filter = state.State.Header.Address
	}
	if state.ParentQuorumCertificate != nil {
		if state.ParentQuorumCertificate.Rank > rank {
			rank = state.ParentQuorumCertificate.Rank
		}
		qcRank = state.ParentQuorumCertificate.Rank
		if err := p.PutQuorumCertificate(
			state.ParentQuorumCertificate,
			txn,
		); err != nil {
			return errors.Wrap(err, "put certified app shard state")
		}
		filter = state.ParentQuorumCertificate.Filter
	}
	if state.PriorRankTimeoutCertificate != nil {
		if state.PriorRankTimeoutCertificate.Rank > rank {
			rank = state.PriorRankTimeoutCertificate.Rank
		}
		tcRank = state.PriorRankTimeoutCertificate.Rank
		if err := p.PutTimeoutCertificate(
			state.PriorRankTimeoutCertificate,
			txn,
		); err != nil {
			return errors.Wrap(err, "put certified app shard state")
		}
		filter = state.PriorRankTimeoutCertificate.Filter
	}

	if bytes.Equal(filter, []byte{}) {
		return errors.Wrap(
			errors.New("invalid filter"),
			"put certified app shard state",
		)
	}

	key := clockShardCertifiedStateKey(rank, filter)
	value := []byte{}
	value = binary.BigEndian.AppendUint64(value, frameNumber)
	value = binary.BigEndian.AppendUint64(value, qcRank)
	value = binary.BigEndian.AppendUint64(value, tcRank)

	if err := txn.Set(key, value); err != nil {
		return errors.Wrap(err, "put certified app shard state")
	}

	if err := p.updateEarliestIndex(
		txn,
		clockShardCertifiedStateEarliestIndex(filter),
		rank,
	); err != nil {
		return errors.Wrap(err, "put certified app shard state")
	}

	if err := txn.Set(
		clockShardCertifiedStateLatestIndex(filter),
		binary.BigEndian.AppendUint64(nil, rank),
	); err != nil {
		return errors.Wrap(err, "put certified app shard state")
	}

	return nil
}

func (p *PebbleClockStore) GetLatestQuorumCertificate(
	filter []byte,
) (*protobufs.QuorumCertificate, error) {
	idxValue, closer, err := p.db.Get(
		clockQuorumCertificateLatestIndex(filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get latest quorum certificate")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get latest quorum certificate",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetQuorumCertificate(filter, rank)
}

func (p *PebbleClockStore) GetEarliestQuorumCertificate(
	filter []byte,
) (*protobufs.QuorumCertificate, error) {
	idxValue, closer, err := p.db.Get(
		clockQuorumCertificateEarliestIndex(filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get earliest quorum certificate")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get earliest quorum certificate",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetQuorumCertificate(filter, rank)
}

func (p *PebbleClockStore) GetQuorumCertificate(
	filter []byte,
	rank uint64,
) (*protobufs.QuorumCertificate, error) {
	key := clockQuorumCertificateKey(rank, filter)
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get quorum certificate")
	}
	defer closer.Close()

	qc := &protobufs.QuorumCertificate{}
	if err := qc.FromCanonicalBytes(slices.Clone(value)); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get quorum certificate",
		)
	}

	return qc, nil
}

func (p *PebbleClockStore) RangeQuorumCertificates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.QuorumCertificate], error) {
	if startRank > endRank {
		startRank, endRank = endRank, startRank
	}

	return &PebbleQuorumCertificateIterator{
		filter: filter,
		start:  startRank,
		end:    endRank + 1,
		cur:    startRank,
		db:     p,
	}, nil
}

func (p *PebbleClockStore) PutQuorumCertificate(
	qc *protobufs.QuorumCertificate,
	txn store.Transaction,
) error {
	if qc == nil {
		return errors.Wrap(
			errors.New("quorum certificate is required"),
			"put quorum certificate",
		)
	}

	rank := qc.Rank
	filter := qc.Filter
	data, err := qc.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"put quorum certificate",
		)
	}

	key := clockQuorumCertificateKey(rank, filter)
	if err := txn.Set(key, data); err != nil {
		return errors.Wrap(err, "put quorum certificate")
	}

	if err := p.updateEarliestIndex(
		txn,
		clockQuorumCertificateEarliestIndex(filter),
		rank,
	); err != nil {
		return errors.Wrap(err, "put quorum certificate")
	}

	if err := p.updateLatestIndex(
		txn,
		clockQuorumCertificateLatestIndex(filter),
		rank,
	); err != nil {
		return errors.Wrap(err, "put quorum certificate")
	}

	return nil
}

func (p *PebbleClockStore) GetLatestTimeoutCertificate(
	filter []byte,
) (*protobufs.TimeoutCertificate, error) {
	idxValue, closer, err := p.db.Get(
		clockTimeoutCertificateLatestIndex(filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get latest timeout certificate")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get latest timeout certificate",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetTimeoutCertificate(filter, rank)
}

func (p *PebbleClockStore) GetEarliestTimeoutCertificate(
	filter []byte,
) (*protobufs.TimeoutCertificate, error) {
	idxValue, closer, err := p.db.Get(
		clockTimeoutCertificateEarliestIndex(filter),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get earliest timeout certificate")
	}
	defer closer.Close()

	if len(idxValue) != 8 {
		return nil, errors.Wrap(
			store.ErrInvalidData,
			"get earliest timeout certificate",
		)
	}

	rank := binary.BigEndian.Uint64(idxValue)
	return p.GetTimeoutCertificate(filter, rank)
}

func (p *PebbleClockStore) GetTimeoutCertificate(
	filter []byte,
	rank uint64,
) (*protobufs.TimeoutCertificate, error) {
	key := clockTimeoutCertificateKey(rank, filter)
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get timeout certificate")
	}
	defer closer.Close()

	tc := &protobufs.TimeoutCertificate{}
	if err := tc.FromCanonicalBytes(slices.Clone(value)); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get timeout certificate",
		)
	}

	return tc, nil
}

func (p *PebbleClockStore) RangeTimeoutCertificates(
	filter []byte,
	startRank uint64,
	endRank uint64,
) (store.TypedIterator[*protobufs.TimeoutCertificate], error) {
	if startRank > endRank {
		startRank, endRank = endRank, startRank
	}

	return &PebbleTimeoutCertificateIterator{
		filter: filter,
		start:  startRank,
		end:    endRank + 1,
		cur:    startRank,
		db:     p,
	}, nil
}

func (p *PebbleClockStore) PutTimeoutCertificate(
	tc *protobufs.TimeoutCertificate,
	txn store.Transaction,
) error {
	if tc == nil {
		return errors.Wrap(
			errors.New("timeout certificate is required"),
			"put timeout certificate",
		)
	}

	rank := tc.Rank
	filter := tc.Filter

	data, err := tc.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"put timeout certificate",
		)
	}

	key := clockTimeoutCertificateKey(rank, filter)
	if err := txn.Set(key, data); err != nil {
		return errors.Wrap(err, "put timeout certificate")
	}

	if err := p.updateEarliestIndex(
		txn,
		clockTimeoutCertificateEarliestIndex(filter),
		rank,
	); err != nil {
		return errors.Wrap(err, "put timeout certificate")
	}

	if err := p.updateLatestIndex(
		txn,
		clockTimeoutCertificateLatestIndex(filter),
		rank,
	); err != nil {
		return errors.Wrap(err, "put timeout certificate")
	}

	return nil
}

func (p *PebbleClockStore) PutProposalVote(
	txn store.Transaction,
	vote *protobufs.ProposalVote,
) error {
	if vote == nil {
		return errors.Wrap(
			errors.New("proposal vote is required"),
			"put proposal vote",
		)
	}

	rank := vote.Rank
	filter := vote.Filter
	identity := vote.Identity()

	data, err := vote.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"put proposal vote",
		)
	}

	key := clockProposalVoteKey(rank, filter, []byte(identity))
	err = txn.Set(key, data)
	return errors.Wrap(err, "put proposal vote")
}

func (p *PebbleClockStore) GetProposalVote(
	filter []byte,
	rank uint64,
	identity []byte,
) (
	*protobufs.ProposalVote,
	error,
) {
	key := clockProposalVoteKey(rank, filter, []byte(identity))
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get proposal vote")
	}
	defer closer.Close()

	vote := &protobufs.ProposalVote{}
	if err := vote.FromCanonicalBytes(slices.Clone(value)); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get proposal vote",
		)
	}

	return vote, nil
}

func (p *PebbleClockStore) GetProposalVotes(filter []byte, rank uint64) (
	[]*protobufs.ProposalVote,
	error,
) {
	results := []*protobufs.ProposalVote{}
	startKey := clockProposalVoteKey(rank, filter, nil)
	endKey := clockProposalVoteKey(rank+1, filter, nil)
	iterator, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "get proposal votes")
	}
	defer iterator.Close()

	for iterator.First(); iterator.Valid(); iterator.Next() {
		key := iterator.Key()
		if len(key) != len(startKey)+32 {
			continue
		}

		value := iterator.Value()
		vote := &protobufs.ProposalVote{}
		if err := vote.FromCanonicalBytes(slices.Clone(value)); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, store.ErrInvalidData.Error()),
				"get proposal votes",
			)
		}
		results = append(results, vote)
	}

	return results, nil
}

func (p *PebbleClockStore) PutTimeoutVote(
	txn store.Transaction,
	vote *protobufs.TimeoutState,
) error {
	if vote == nil {
		return errors.Wrap(
			errors.New("timeout vote is required"),
			"put timeout vote",
		)
	}

	rank := vote.Vote.Rank
	filter := vote.Vote.Filter
	identity := vote.Vote.Identity()

	data, err := vote.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"put timeout vote",
		)
	}

	key := clockTimeoutVoteKey(rank, filter, []byte(identity))
	err = txn.Set(key, data)
	return errors.Wrap(err, "put timeout vote")
}

func (p *PebbleClockStore) GetTimeoutVote(
	filter []byte,
	rank uint64,
	identity []byte,
) (
	*protobufs.TimeoutState,
	error,
) {
	key := clockTimeoutVoteKey(rank, filter, []byte(identity))
	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get proposal vote")
	}
	defer closer.Close()

	vote := &protobufs.TimeoutState{}
	if err := vote.FromCanonicalBytes(slices.Clone(value)); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get proposal vote",
		)
	}

	return vote, nil
}

func (p *PebbleClockStore) GetTimeoutVotes(filter []byte, rank uint64) (
	[]*protobufs.TimeoutState,
	error,
) {
	results := []*protobufs.TimeoutState{}
	startKey := clockTimeoutVoteKey(rank, filter, nil)
	endKey := clockTimeoutVoteKey(rank+1, filter, nil)
	iterator, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "get timeout votes")
	}
	defer iterator.Close()

	for iterator.First(); iterator.Valid(); iterator.Next() {
		key := iterator.Key()
		if len(key) != len(startKey)+32 {
			continue
		}

		value := iterator.Value()
		vote := &protobufs.TimeoutState{}
		if err := vote.FromCanonicalBytes(slices.Clone(value)); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, store.ErrInvalidData.Error()),
				"get timeout votes",
			)
		}
		results = append(results, vote)
	}

	return results, nil
}
