package store

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var ErrNotFound = errors.New("worker not found")

var _ store.WorkerStore = (*PebbleWorkerStore)(nil)

type PebbleWorkerStore struct {
	db     store.KVDB
	logger *zap.Logger
}

func NewPebbleWorkerStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleWorkerStore {
	return &PebbleWorkerStore{
		db,
		logger,
	}
}

func workerKey(coreId uint) []byte {
	key := []byte{WORKER, WORKER_BY_CORE}
	coreIdBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(coreIdBytes, uint64(coreId))
	key = append(key, coreIdBytes...)
	return key
}

func workerByFilterKey(filter []byte) []byte {
	key := []byte{WORKER, WORKER_BY_FILTER}
	key = append(key, filter...)
	return key
}

func (p *PebbleWorkerStore) NewTransaction(indexed bool) (
	store.Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleWorkerStore) GetWorker(coreId uint) (*store.WorkerInfo, error) {
	data, closer, err := p.db.Get(workerKey(coreId))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrap(err, "get worker")
	}

	copied := slices.Clone(data)
	closer.Close()

	return decodeWorkerInfo(copied)
}

func (p *PebbleWorkerStore) GetWorkerByFilter(filter []byte) (
	*store.WorkerInfo,
	error,
) {
	if len(filter) == 0 {
		return nil, errors.Wrap(
			errors.New("filter cannot be empty"),
			"get worker by filter",
		)
	}

	data, closer, err := p.db.Get(workerByFilterKey(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrap(err, "get worker by filter")
	}
	copied := slices.Clone(data)
	closer.Close()

	if len(copied) < 8 {
		return nil, errors.Wrap(
			fmt.Errorf("index payload too short: %d", len(copied)),
			"get worker by filter",
		)
	}
	coreId := binary.BigEndian.Uint64(copied[:8])
	return p.GetWorker(uint(coreId))
}

func (p *PebbleWorkerStore) PutWorker(
	txn store.Transaction,
	worker *store.WorkerInfo,
) error {
	// Check if worker already exists to clean up old filter index if needed
	existingWorker, err := p.GetWorker(worker.CoreId)
	if err == nil && existingWorker != nil {
		// Delete old filter index if it exists and is different
		if len(existingWorker.Filter) > 0 &&
			string(existingWorker.Filter) != string(worker.Filter) {
			if err := txn.Delete(
				workerByFilterKey(existingWorker.Filter),
			); err != nil {
				return errors.Wrap(err, "put worker")
			}
		}
	}

	data, err := encodeWorkerInfo(worker)
	if err != nil {
		return errors.Wrap(err, "put worker")
	}

	if err := txn.Set(workerKey(worker.CoreId), data); err != nil {
		return errors.Wrap(err, "put worker")
	}

	// Only set filter index if filter is not empty
	if len(worker.Filter) > 0 {
		coreIdBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(coreIdBytes, uint64(worker.CoreId))
		if err := txn.Set(
			workerByFilterKey(worker.Filter),
			coreIdBytes,
		); err != nil {
			return errors.Wrap(err, "put worker")
		}
	}

	return nil
}

func (p *PebbleWorkerStore) DeleteWorker(
	txn store.Transaction,
	coreId uint,
) error {
	worker, err := p.GetWorker(coreId)
	if err != nil {
		return errors.Wrap(err, "delete worker")
	}

	if err := txn.Delete(workerKey(coreId)); err != nil {
		return errors.Wrap(err, "delete worker")
	}

	// Only delete filter index if filter is not empty
	if len(worker.Filter) > 0 {
		if err := txn.Delete(workerByFilterKey(worker.Filter)); err != nil {
			return errors.Wrap(err, "delete worker")
		}
	}

	return nil
}

func (p *PebbleWorkerStore) RangeWorkers() ([]*store.WorkerInfo, error) {
	iter, err := p.db.NewIter(
		[]byte{WORKER, WORKER_BY_CORE, 0x00},
		[]byte{WORKER, WORKER_BY_CORE, 0xFF},
	)
	if err != nil {
		return nil, errors.Wrap(err, "range workers")
	}
	defer iter.Close()

	var workers []*store.WorkerInfo
	for iter.First(); iter.Valid(); iter.Next() {
		val := slices.Clone(iter.Value())
		worker, err := decodeWorkerInfo(val)
		if err != nil {
			return nil, errors.Wrap(err, "range workers")
		}
		workers = append(workers, worker)
	}

	return workers, nil
}

func encodeWorkerInfo(worker *store.WorkerInfo) ([]byte, error) {
	listenMultiaddrLen := uint16(len(worker.ListenMultiaddr))
	streamListenMultiaddrLen := uint16(len(worker.StreamListenMultiaddr))
	filterLen := uint16(len(worker.Filter))

	// totalLen = coreId(8) + totalStorage(8) + automatic(1) + allocated(1)
	//   + 2 + listen + 2 + stream + 2 + filter
	totalLen := 8 + 8 + 1 + 1 + 2 + int(listenMultiaddrLen) + 2 +
		int(streamListenMultiaddrLen) + 2 + int(filterLen)
	data := make([]byte, totalLen)

	offset := 0
	binary.BigEndian.PutUint64(data[offset:], uint64(worker.CoreId))
	offset += 8

	binary.BigEndian.PutUint64(data[offset:], uint64(worker.TotalStorage))
	offset += 8

	if worker.Automatic {
		data[offset] = 1
	} else {
		data[offset] = 0
	}
	offset += 1

	if worker.Allocated {
		data[offset] = 1
	} else {
		data[offset] = 0
	}
	offset += 1

	binary.BigEndian.PutUint16(data[offset:], listenMultiaddrLen)
	offset += 2
	copy(data[offset:], worker.ListenMultiaddr)
	offset += int(listenMultiaddrLen)

	binary.BigEndian.PutUint16(data[offset:], streamListenMultiaddrLen)
	offset += 2
	copy(data[offset:], worker.StreamListenMultiaddr)
	offset += int(streamListenMultiaddrLen)

	binary.BigEndian.PutUint16(data[offset:], filterLen)
	offset += 2
	copy(data[offset:], worker.Filter)

	return data, nil
}

func decodeWorkerInfo(data []byte) (*store.WorkerInfo, error) {
	if len(data) < 24 {
		return nil, errors.New("invalid worker info data: too short")
	}

	offset := 0
	if offset+8 > len(data) {
		return nil, errors.New("truncated coreId")
	}
	coreId := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	if offset+8 > len(data) {
		return nil, errors.New("truncated totalStorage")
	}
	totalStorage := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	if offset+1 > len(data) {
		return nil, errors.New("truncated automatic flag")
	}
	automatic := data[offset] == 1
	offset += 1

	if offset+1 > len(data) {
		return nil, errors.New("truncated allocated flag")
	}
	allocated := data[offset] == 1
	offset += 1

	if offset+2 > len(data) {
		return nil, errors.New("truncated listenMultiaddr length")
	}

	listenMultiaddrLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if listenMultiaddrLen < 0 || offset+listenMultiaddrLen > len(data) {
		return nil, errors.New("invalid listen multiaddr length")
	}

	listenMultiaddr := string(data[offset : offset+listenMultiaddrLen])
	offset += listenMultiaddrLen

	if offset+2 > len(data) {
		return nil, errors.New("truncated streamListenMultiaddr length")
	}

	streamListenMultiaddrLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if streamListenMultiaddrLen < 0 ||
		offset+streamListenMultiaddrLen > len(data) {
		return nil, errors.New("invalid stream listen multiaddr length")
	}

	streamListenMultiaddr := string(
		data[offset : offset+streamListenMultiaddrLen],
	)
	offset += streamListenMultiaddrLen

	if offset+2 > len(data) {
		return nil, errors.New("truncated filter length")
	}

	filterLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if filterLen < 0 || offset+filterLen > len(data) {
		return nil, errors.New("invalid filter length")
	}

	filter := make([]byte, filterLen)
	copy(filter, data[offset:offset+filterLen])

	return &store.WorkerInfo{
		CoreId:                uint(coreId),
		ListenMultiaddr:       listenMultiaddr,
		StreamListenMultiaddr: streamListenMultiaddr,
		Filter:                filter,
		TotalStorage:          uint(totalStorage),
		Automatic:             automatic,
		Allocated:             allocated,
	}, nil
}
