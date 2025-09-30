package store

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

// CoinIterator is a typed iterator for Coin
type CoinIterator interface {
	First() bool
	Next() bool
	Valid() bool
	Value() (uint64, *protobufs.Coin, error)
	Close() error
}

// TransactionIterator is a typed iterator for MaterializedTransaction
type TransactionIterator interface {
	First() bool
	Next() bool
	Valid() bool
	Value() (*protobufs.MaterializedTransaction, error)
	Close() error
}

// PendingTransactionIterator is a typed iterator for
// MaterializedPendingTransaction
type PendingTransactionIterator interface {
	First() bool
	Next() bool
	Valid() bool
	Value() (*protobufs.MaterializedPendingTransaction, error)
	Close() error
}

type TokenStore interface {
	NewTransaction(indexed bool) (Transaction, error)

	// Legacy methods
	GetCoinsForOwner(owner []byte) ([]uint64, [][]byte, []*protobufs.Coin, error)
	GetCoinByAddress(address []byte) (
		uint64,
		*protobufs.Coin,
		error,
	)
	RangeCoins(start []byte, end []byte) (CoinIterator, error)
	PutCoin(
		txn Transaction,
		frameNumber uint64,
		address []byte,
		coin *protobufs.Coin,
	) error
	DeleteCoin(
		txn Transaction,
		address []byte,
		coin *protobufs.Coin,
	) error

	// Materialized state methods
	GetTransactionsForOwner(domain []byte, owner []byte) (
		[]*protobufs.MaterializedTransaction,
		error,
	)
	GetTransactionByAddress(domain []byte, address []byte) (
		*protobufs.MaterializedTransaction,
		error,
	)
	RangeTransactions(
		domain []byte,
		owner []byte,
		start []byte,
		end []byte,
	) (TransactionIterator, error)
	PutTransaction(
		txn Transaction,
		domain []byte,
		owner []byte,
		transaction *protobufs.MaterializedTransaction,
	) error
	DeleteTransaction(
		txn Transaction,
		domain []byte,
		address []byte,
		owner []byte,
	) error
	GetPendingTransactionsForOwner(domain []byte, owner []byte) (
		[]*protobufs.MaterializedPendingTransaction,
		error,
	)
	GetPendingTransactionByAddress(domain []byte, address []byte) (
		*protobufs.MaterializedPendingTransaction,
		error,
	)
	RangePendingTransactions(
		domain []byte,
		owner []byte,
		start []byte,
		end []byte,
	) (PendingTransactionIterator, error)
	PutPendingTransaction(
		txn Transaction,
		domain []byte,
		owner []byte,
		pendingTransaction *protobufs.MaterializedPendingTransaction,
	) error
	DeletePendingTransaction(
		txn Transaction,
		domain []byte,
		owner []byte,
		pendingTransaction *protobufs.MaterializedPendingTransaction,
	) error
}
