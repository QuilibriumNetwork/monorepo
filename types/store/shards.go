package store

type ShardInfo struct {
	L1   []byte
	L2   []byte
	Path []uint32
}

type ShardsStore interface {
	GetAppShards(
		shardKey []byte,
		prefix []uint32,
	) ([]ShardInfo, error)
	PutAppShard(txn Transaction, shard ShardInfo) error
	DeleteAppShard(txn Transaction, shardKey []byte, prefix []uint32) error
}
