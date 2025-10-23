package store

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var _ store.ShardsStore = (*PebbleShardsStore)(nil)

type PebbleShardsStore struct {
	db     store.KVDB
	logger *zap.Logger
}

func NewPebbleShardsStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleShardsStore {
	return &PebbleShardsStore{
		db,
		logger,
	}
}

func appShardKey(shardKey []byte, prefix []uint32) []byte {
	key := []byte{SHARD, APP_SHARD_DATA}
	key = append(key, shardKey...)
	for _, p := range prefix {
		key = binary.BigEndian.AppendUint32(key, p)
	}

	return key
}

func (p *PebbleShardsStore) RangeAppShards() ([]store.ShardInfo, error) {
	shards := []store.ShardInfo{}

	iter, err := p.db.NewIter(
		appShardKey(bytes.Repeat([]byte{0}, 35), []uint32{}),
		appShardKey(bytes.Repeat([]byte{0xff}, 35), []uint32{0xffff}),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get app shards")
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		offset := 0
		if len(value)%4 != 0 {
			offset += len(value) % 4
		}
		out := make([]uint32, len(value)/4)
		buf := bytes.NewBuffer(value[offset:])
		err = binary.Read(buf, binary.BigEndian, &out)
		if err != nil {
			return nil, errors.Wrap(err, "get app shards")
		}
		key := slices.Clone(iter.Key())
		shards = append(shards, store.ShardInfo{
			L1:   key[2:5],
			L2:   key[5:37],
			Path: out,
		})
	}

	return shards, nil
}

func (p *PebbleShardsStore) GetAppShards(
	shardKey []byte,
	prefix []uint32,
) ([]store.ShardInfo, error) {
	endPrefix := slices.Clone(prefix)
	endPrefix = append(endPrefix, 0xffff)
	shards := []store.ShardInfo{}

	iter, err := p.db.NewIter(
		appShardKey(shardKey, prefix),
		appShardKey(shardKey, endPrefix),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get app shards")
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		offset := 0
		if len(value)%4 != 0 {
			offset += len(value) % 4
		}
		out := make([]uint32, len(value)/4)
		buf := bytes.NewBuffer(value[offset:])
		err = binary.Read(buf, binary.BigEndian, &out)
		if err != nil {
			return nil, errors.Wrap(err, "get app shards")
		}
		shards = append(shards, store.ShardInfo{
			L1:   shardKey[:3],
			L2:   shardKey[3:],
			Path: out,
		})
	}

	return shards, nil
}

func (p *PebbleShardsStore) PutAppShard(
	txn store.Transaction,
	shard store.ShardInfo,
) error {
	key := appShardKey(slices.Concat(shard.L1, shard.L2), shard.Path)
	return errors.Wrap(txn.Set(key, key[37:]), "put app shard")
}

func (p *PebbleShardsStore) DeleteAppShard(
	txn store.Transaction,
	shardKey []byte,
	prefix []uint32,
) error {
	key := appShardKey(shardKey, prefix)
	return errors.Wrap(txn.Delete(key), "put app shard")
}
