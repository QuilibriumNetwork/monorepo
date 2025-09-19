package store

type CoinStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	// GetCoinsForOwner(owner []byte) ([]uint64, [][]byte, []*protobufs.Coin, error)
	// GetCoinByAddress(txn Transaction, address []byte) (
	// 	uint64,
	// 	*protobufs.Coin,
	// 	error,
	// )
	// RangeCoins(start []byte, end []byte) (Iterator, error)
	// PutCoin(
	// 	txn Transaction,
	// 	frameNumber uint64,
	// 	address []byte,
	// 	coin *protobufs.Coin,
	// ) error
	// DeleteCoin(
	// 	txn Transaction,
	// 	address []byte,
	// 	coin *protobufs.Coin,
	// ) error
	// GetLatestFrameProcessed() (uint64, error)
	// SetLatestFrameProcessed(txn Transaction, frameNumber uint64) error
}
