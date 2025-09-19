package store

import (
	"io"
)

type KVDB interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key, value []byte) error
	Delete(key []byte) error
	NewBatch(indexed bool) Transaction
	NewIter(lowerBound []byte, upperBound []byte) (Iterator, error)
	Compact(start, end []byte, parallelize bool) error
	CompactAll() error
	Close() error
	DeleteRange(start, end []byte) error
}

type Transaction interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key []byte, value []byte) error
	Commit() error
	Delete(key []byte) error
	Abort() error
	NewIter(lowerBound []byte, upperBound []byte) (Iterator, error)
	DeleteRange(lowerBound []byte, upperBound []byte) error
}
