package store

import (
	ds "github.com/ipfs/go-datastore"
)

type Peerstore interface {
	ds.TxnDatastore
	ds.PersistentDatastore
	ds.Batching
}
