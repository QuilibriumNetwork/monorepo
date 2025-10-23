package store

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var _ store.DataProofStore = (*PebbleDataProofStore)(nil)

type PebbleDataProofStore struct {
	db     store.KVDB
	logger *zap.Logger
}

func NewPebbleDataProofStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleDataProofStore {
	return &PebbleDataProofStore{
		db,
		logger,
	}
}

// func dataProofMetadataKey(filter []byte, commitment []byte) []byte {
// 	key := []byte{DATA_PROOF, DATA_PROOF_METADATA}
// 	key = append(key, commitment...)
// 	key = append(key, filter...)
// 	return key
// }

// func dataProofInclusionKey(
// 	filter []byte,
// 	commitment []byte,
// 	seqNo uint64,
// ) []byte {
// 	key := []byte{DATA_PROOF, DATA_PROOF_INCLUSION}
// 	key = append(key, commitment...)
// 	key = binary.BigEndian.AppendUint64(key, seqNo)
// 	key = append(key, filter...)
// 	return key
// }

// func dataProofSegmentKey(
// 	filter []byte,
// 	hash []byte,
// ) []byte {
// 	key := []byte{DATA_PROOF, DATA_PROOF_SEGMENT}
// 	key = append(key, hash...)
// 	key = append(key, filter...)
// 	return key
// }

// func dataTimeProofKey(peerId []byte, increment uint32) []byte {
// 	key := []byte{DATA_TIME_PROOF, DATA_TIME_PROOF_DATA}
// 	key = append(key, peerId...)
// 	key = binary.BigEndian.AppendUint32(key, increment)
// 	return key
// }

// func dataTimeProofLatestKey(peerId []byte) []byte {
// 	key := []byte{DATA_TIME_PROOF, DATA_TIME_PROOF_LATEST}
// 	key = append(key, peerId...)
// 	return key
// }

func (p *PebbleDataProofStore) NewTransaction() (store.Transaction, error) {
	return p.db.NewBatch(false), nil
}
