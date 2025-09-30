package mocks

import (
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var _ store.ShardsStore = (*MockShardsStore)(nil)

type MockShardsStore struct {
	mock.Mock
}

// DeleteAppShard implements store.ShardsStore.
func (m *MockShardsStore) DeleteAppShard(
	txn store.Transaction,
	shardKey []byte,
	prefix []uint32,
) error {
	args := m.Called(txn, shardKey, prefix)
	return args.Error(0)
}

// GetAppShards implements store.ShardsStore.
func (m *MockShardsStore) GetAppShards(
	shardKey []byte,
	prefix []uint32,
) ([]store.ShardInfo, error) {
	args := m.Called(shardKey, prefix)
	return args.Get(0).([]store.ShardInfo), args.Error(1)
}

// PutAppShard implements store.ShardsStore.
func (m *MockShardsStore) PutAppShard(
	txn store.Transaction,
	shard store.ShardInfo,
) error {
	args := m.Called(txn, shard)
	return args.Error(0)
}
