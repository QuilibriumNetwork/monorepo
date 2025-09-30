package store

import (
	"bytes"
	"encoding/binary"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var _ store.TokenStore = (*PebbleTokenStore)(nil)

type PebbleTokenStore struct {
	db     store.KVDB
	logger *zap.Logger
}

// Typed iterator for Coin
type PebbleCoinIterator struct {
	i  store.Iterator
	db *PebbleTokenStore
}

var _ store.CoinIterator = (*PebbleCoinIterator)(nil)

// Typed iterator for MaterializedTransaction
type PebbleTransactionIterator struct {
	i  store.Iterator
	db *PebbleTokenStore
}

var _ store.TransactionIterator = (*PebbleTransactionIterator)(nil)

// Typed iterator for MaterializedPendingTransaction
type PebblePendingTransactionIterator struct {
	i  store.Iterator
	db *PebbleTokenStore
}

var _ store.PendingTransactionIterator = (*PebblePendingTransactionIterator)(nil)

func NewPebbleTokenStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleTokenStore {
	return &PebbleTokenStore{
		db,
		logger,
	}
}

func coinKey(address []byte) []byte {
	key := []byte{COIN, COIN_BY_ADDRESS}
	key = append(key, address...)
	return key
}

func coinByOwnerKey(owner []byte, address []byte) []byte {
	key := []byte{COIN, COIN_BY_OWNER}
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func transactionKey(domain []byte, address []byte) []byte {
	key := []byte{COIN, TRANSACTION_BY_ADDRESS}
	key = append(key, domain...)
	key = append(key, address...)
	return key
}

func transactionByOwnerKey(domain []byte, owner []byte, address []byte) []byte {
	key := []byte{COIN, TRANSACTION_BY_OWNER}
	key = append(key, domain...)
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func pendingTransactionKey(domain []byte, address []byte) []byte {
	key := []byte{COIN, PENDING_TRANSACTION_BY_ADDRESS}
	key = append(key, domain...)
	key = append(key, address...)
	return key
}

func pendingTransactionByOwnerKey(
	domain []byte,
	owner []byte,
	address []byte,
) []byte {
	key := []byte{COIN, PENDING_TRANSACTION_BY_OWNER}
	key = append(key, domain...)
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func (p *PebbleTokenStore) NewTransaction(indexed bool) (
	store.Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleTokenStore) GetCoinsForOwner(
	owner []byte,
) ([]uint64, [][]byte, []*protobufs.Coin, error) {
	iter, err := p.db.NewIter(
		coinByOwnerKey(owner, bytes.Repeat([]byte{0x00}, 32)),
		coinByOwnerKey(owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, nil, nil, err
		}
		err = errors.Wrap(err, "get coins for owner")
		return nil, nil, nil, err
	}
	defer iter.Close()

	frameNumbers := []uint64{}
	addresses := [][]byte{}
	coins := []*protobufs.Coin{}
	for iter.First(); iter.Valid(); iter.Next() {
		coinBytes := iter.Value()
		frameNumber := binary.BigEndian.Uint64(coinBytes[:8])
		coin := &protobufs.Coin{}
		err := proto.Unmarshal(coinBytes[8:], coin)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "get coins for owner")
		}
		frameNumbers = append(frameNumbers, frameNumber)
		addr := make([]byte, 32)
		copy(addr[:], iter.Key()[34:])
		addresses = append(addresses, addr)
		coins = append(coins, coin)
	}

	return frameNumbers, addresses, coins, nil
}

func (p *PebbleTokenStore) GetCoinByAddress(
	address []byte,
) (
	uint64,
	*protobufs.Coin,
	error,
) {
	coinBytes, closer, err := p.db.Get(coinKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return 0, nil, err
		}
		err = errors.Wrap(err, "get coin by address")
		return 0, nil, err
	}
	defer closer.Close()

	coin := &protobufs.Coin{}
	err = proto.Unmarshal(coinBytes[8:], coin)
	if err != nil {
		return 0, nil, errors.Wrap(err, "get coin by address")
	}

	frameNumber := binary.BigEndian.Uint64(coinBytes[:8])

	return frameNumber, coin, nil
}

func (p *PebbleTokenStore) RangeCoins(
	start []byte,
	end []byte,
) (store.CoinIterator, error) {
	iter, err := p.db.NewIter(
		coinKey(start),
		coinKey(end),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range pre coin proofs")
	}

	return &PebbleCoinIterator{i: iter, db: p}, nil
}

func (p *PebbleTokenStore) PutCoin(
	txn store.Transaction,
	frameNumber uint64,
	address []byte,
	coin *protobufs.Coin,
) error {
	coinBytes, err := proto.Marshal(coin)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	data := []byte{}
	data = binary.BigEndian.AppendUint64(data, frameNumber)
	data = append(data, coinBytes...)
	err = txn.Set(
		coinByOwnerKey(coin.Owner.GetImplicitAccount().Address, address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	err = txn.Set(
		coinKey(address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	return nil
}

func (p *PebbleTokenStore) DeleteCoin(
	txn store.Transaction,
	address []byte,
	coin *protobufs.Coin,
) error {
	err := txn.Delete(coinKey(address))
	if err != nil {
		return errors.Wrap(err, "delete coin")
	}

	err = txn.Delete(
		coinByOwnerKey(coin.Owner.GetImplicitAccount().GetAddress(), address),
	)
	if err != nil {
		return errors.Wrap(err, "delete coin")
	}

	return nil
}

// DeletePendingTransaction implements store.CoinStore.
func (p *PebbleTokenStore) DeletePendingTransaction(
	txn store.Transaction,
	domain []byte,
	owner []byte,
	pendingTransaction *protobufs.MaterializedPendingTransaction,
) error {
	err := txn.Delete(pendingTransactionKey(domain, pendingTransaction.Address))
	if err != nil {
		return errors.Wrap(err, "delete pending transaction")
	}

	err = txn.Delete(
		pendingTransactionByOwnerKey(domain, owner, pendingTransaction.Address),
	)
	if err != nil {
		return errors.Wrap(err, "delete pending transaction")
	}

	return nil
}

// DeleteTransaction implements store.CoinStore.
func (p *PebbleTokenStore) DeleteTransaction(
	txn store.Transaction,
	domain []byte,
	address []byte,
	owner []byte,
) error {
	err := txn.Delete(transactionKey(domain, address))
	if err != nil {
		return errors.Wrap(err, "delete transaction")
	}

	err = txn.Delete(
		transactionByOwnerKey(domain, owner, address),
	)
	if err != nil {
		return errors.Wrap(err, "delete transaction")
	}

	return nil
}

// GetPendingTransactionByAddress implements store.CoinStore.
func (p *PebbleTokenStore) GetPendingTransactionByAddress(
	domain []byte,
	address []byte,
) (*protobufs.MaterializedPendingTransaction, error) {
	pendingTxnBytes, closer, err := p.db.Get(
		pendingTransactionKey(domain, address),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get pending transaction by address")
		return nil, err
	}
	defer closer.Close()

	pendingTxn := &protobufs.MaterializedPendingTransaction{}
	err = proto.Unmarshal(pendingTxnBytes, pendingTxn)
	if err != nil {
		return nil, errors.Wrap(err, "get pending transaction by address")
	}

	return pendingTxn, nil
}

// GetPendingTransactionsForOwner implements store.CoinStore.
func (p *PebbleTokenStore) GetPendingTransactionsForOwner(
	domain []byte,
	owner []byte,
) ([]*protobufs.MaterializedPendingTransaction, error) {
	iter, err := p.db.NewIter(
		pendingTransactionByOwnerKey(domain, owner, bytes.Repeat([]byte{0x00}, 32)),
		pendingTransactionByOwnerKey(domain, owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get pending transactions for owner")
		return nil, err
	}
	defer iter.Close()

	pendingTransactions := []*protobufs.MaterializedPendingTransaction{}
	for iter.First(); iter.Valid(); iter.Next() {
		pendingTxnBytes := iter.Value()
		pendingTxn := &protobufs.MaterializedPendingTransaction{}
		err := proto.Unmarshal(pendingTxnBytes, pendingTxn)
		if err != nil {
			return nil, errors.Wrap(err, "get pending transactions for owner")
		}
		pendingTransactions = append(pendingTransactions, pendingTxn)
	}

	return pendingTransactions, nil
}

// GetTransactionByAddress implements store.CoinStore.
func (p *PebbleTokenStore) GetTransactionByAddress(
	domain []byte,
	address []byte,
) (*protobufs.MaterializedTransaction, error) {
	txnBytes, closer, err := p.db.Get(transactionKey(domain, address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get transaction by address")
		return nil, err
	}
	defer closer.Close()

	txn := &protobufs.MaterializedTransaction{}
	err = proto.Unmarshal(txnBytes, txn)
	if err != nil {
		return nil, errors.Wrap(err, "get transaction by address")
	}

	return txn, nil
}

// GetTransactionsForOwner implements store.CoinStore.
func (p *PebbleTokenStore) GetTransactionsForOwner(
	domain []byte,
	owner []byte,
) ([]*protobufs.MaterializedTransaction, error) {
	iter, err := p.db.NewIter(
		transactionByOwnerKey(domain, owner, bytes.Repeat([]byte{0x00}, 32)),
		transactionByOwnerKey(domain, owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get transactions for owner")
		return nil, err
	}
	defer iter.Close()

	transactions := []*protobufs.MaterializedTransaction{}
	for iter.First(); iter.Valid(); iter.Next() {
		txnBytes := iter.Value()
		txn := &protobufs.MaterializedTransaction{}
		err := proto.Unmarshal(txnBytes, txn)
		if err != nil {
			return nil, errors.Wrap(err, "get transactions for owner")
		}
		transactions = append(transactions, txn)
	}

	return transactions, nil
}

// PutPendingTransaction implements store.CoinStore.
func (p *PebbleTokenStore) PutPendingTransaction(
	txn store.Transaction,
	domain []byte,
	owner []byte,
	pendingTransaction *protobufs.MaterializedPendingTransaction,
) error {
	pendingTxnBytes, err := proto.Marshal(pendingTransaction)
	if err != nil {
		return errors.Wrap(err, "put pending transaction")
	}

	err = txn.Set(
		pendingTransactionByOwnerKey(domain, owner, pendingTransaction.Address),
		pendingTxnBytes,
	)
	if err != nil {
		return errors.Wrap(err, "put pending transaction")
	}

	err = txn.Set(
		pendingTransactionKey(domain, pendingTransaction.Address),
		pendingTxnBytes,
	)
	if err != nil {
		return errors.Wrap(err, "put pending transaction")
	}

	return nil
}

// PutTransaction implements store.CoinStore.
func (p *PebbleTokenStore) PutTransaction(
	txn store.Transaction,
	domain []byte,
	owner []byte,
	transaction *protobufs.MaterializedTransaction,
) error {
	txnBytes, err := proto.Marshal(transaction)
	if err != nil {
		return errors.Wrap(err, "put transaction")
	}

	err = txn.Set(
		transactionByOwnerKey(domain, owner, transaction.Address),
		txnBytes,
	)
	if err != nil {
		return errors.Wrap(err, "put transaction")
	}

	err = txn.Set(
		transactionKey(domain, transaction.Address),
		txnBytes,
	)
	if err != nil {
		return errors.Wrap(err, "put transaction")
	}

	return nil
}

// RangePendingTransactions implements store.CoinStore.
func (p *PebbleTokenStore) RangePendingTransactions(
	domain []byte,
	owner []byte,
	start []byte,
	end []byte,
) (store.PendingTransactionIterator, error) {
	iter, err := p.db.NewIter(
		pendingTransactionByOwnerKey(domain, owner, start),
		pendingTransactionByOwnerKey(domain, owner, end),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range pending transactions")
	}

	return &PebblePendingTransactionIterator{i: iter, db: p}, nil
}

// RangeTransactions implements store.CoinStore.
func (p *PebbleTokenStore) RangeTransactions(
	domain []byte,
	owner []byte,
	start []byte,
	end []byte,
) (store.TransactionIterator, error) {
	iter, err := p.db.NewIter(
		transactionByOwnerKey(domain, owner, start),
		transactionByOwnerKey(domain, owner, end),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range transactions")
	}

	return &PebbleTransactionIterator{i: iter, db: p}, nil
}

// CoinIterator implementation
func (p *PebbleCoinIterator) First() bool {
	return p.i.First()
}

func (p *PebbleCoinIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleCoinIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleCoinIterator) Value() (uint64, *protobufs.Coin, error) {
	if !p.i.Valid() {
		return 0, nil, store.ErrNotFound
	}

	value := p.i.Value()
	frameNumber := binary.BigEndian.Uint64(value[:8])
	coin := &protobufs.Coin{}
	err := proto.Unmarshal(value[8:], coin)
	if err != nil {
		return 0, nil, errors.Wrap(err, "coin iterator value")
	}

	return frameNumber, coin, nil
}

func (p *PebbleCoinIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing coin iterator")
}

// TransactionIterator implementation
func (p *PebbleTransactionIterator) First() bool {
	return p.i.First()
}

func (p *PebbleTransactionIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleTransactionIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleTransactionIterator) Value() (
	*protobufs.MaterializedTransaction,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	txn := &protobufs.MaterializedTransaction{}
	err := proto.Unmarshal(value, txn)
	if err != nil {
		return nil, errors.Wrap(err, "transaction iterator value")
	}

	return txn, nil
}

func (p *PebbleTransactionIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing transaction iterator")
}

// PendingTransactionIterator implementation
func (p *PebblePendingTransactionIterator) First() bool {
	return p.i.First()
}

func (p *PebblePendingTransactionIterator) Next() bool {
	return p.i.Next()
}

func (p *PebblePendingTransactionIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebblePendingTransactionIterator) Value() (
	*protobufs.MaterializedPendingTransaction,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	pendingTxn := &protobufs.MaterializedPendingTransaction{}
	err := proto.Unmarshal(value, pendingTxn)
	if err != nil {
		return nil, errors.Wrap(err, "pending transaction iterator value")
	}

	return pendingTxn, nil
}

func (p *PebblePendingTransactionIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing pending transaction iterator")
}
