package store

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type CoinStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	GetCoinsForOwner(owner []byte) ([]uint64, [][]byte, []*protobufs.Coin, error)
	GetPreCoinProofsForOwner(owner []byte) (
		[]uint64,
		[]*protobufs.PreCoinProof,
		error,
	)
	GetCoinByAddress(txn Transaction, address []byte) (
		uint64,
		*protobufs.Coin,
		error,
	)
	GetPreCoinProofByAddress(address []byte) (*protobufs.PreCoinProof, error)
	RangeCoins(start []byte, end []byte) (Iterator, error)
	RangePreCoinProofs() (Iterator, error)
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
	PutPreCoinProof(
		txn Transaction,
		frameNumber uint64,
		address []byte,
		preCoinProof *protobufs.PreCoinProof,
	) error
	DeletePreCoinProof(
		txn Transaction,
		address []byte,
		preCoinProof *protobufs.PreCoinProof,
	) error
	GetLatestFrameProcessed() (uint64, error)
	SetLatestFrameProcessed(txn Transaction, frameNumber uint64) error
	SetMigrationVersion(genesisSeedHex string) error
	Migrate(filter []byte, genesisSeedHex string) error
}

var _ CoinStore = (*PebbleCoinStore)(nil)

type PebbleCoinStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleCoinStore(
	db KVDB,
	logger *zap.Logger,
) *PebbleCoinStore {
	return &PebbleCoinStore{
		db,
		logger.With(zap.String("stage", "pebble-coin-store")),
	}
}

const (
	COIN             = 0x07
	PROOF            = 0x08
	COIN_BY_ADDRESS  = 0x00
	COIN_BY_OWNER    = 0x01
	MIGRATION        = 0x02
	GENESIS          = 0xFE
	LATEST_EXECUTION = 0xFF
)

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

func proofKey(address []byte) []byte {
	key := []byte{PROOF, COIN_BY_ADDRESS}
	key = append(key, address...)
	return key
}

func latestExecutionKey() []byte {
	return []byte{COIN, LATEST_EXECUTION}
}

func proofByOwnerKey(owner []byte, address []byte) []byte {
	key := []byte{PROOF, COIN_BY_OWNER}
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func migrationKey() []byte {
	return []byte{COIN, MIGRATION}
}

func genesisSeedKey() []byte {
	return []byte{COIN, GENESIS}
}

func (p *PebbleCoinStore) NewTransaction(indexed bool) (Transaction, error) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleCoinStore) GetCoinsForOwner(
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

func (p *PebbleCoinStore) GetPreCoinProofsForOwner(owner []byte) (
	[]uint64,
	[]*protobufs.PreCoinProof,
	error,
) {
	iter, err := p.db.NewIter(
		proofByOwnerKey(owner, bytes.Repeat([]byte{0x00}, 32)),
		proofByOwnerKey(owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, nil, err
		}
		err = errors.Wrap(err, "get pre coin proofs for owner")
		return nil, nil, err
	}
	defer iter.Close()

	frameNumbers := []uint64{}
	proofs := []*protobufs.PreCoinProof{}
	for iter.First(); iter.Valid(); iter.Next() {
		proofBytes := iter.Value()
		frameNumber := binary.BigEndian.Uint64(proofBytes[:8])
		proof := &protobufs.PreCoinProof{}
		err := proto.Unmarshal(proofBytes[8:], proof)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get pre coin proofs for owner")
		}
		frameNumbers = append(frameNumbers, frameNumber)
		proofs = append(proofs, proof)
	}

	return frameNumbers, proofs, nil
}

func (p *PebbleCoinStore) GetCoinByAddress(txn Transaction, address []byte) (
	uint64,
	*protobufs.Coin,
	error,
) {
	var coinBytes []byte
	var closer io.Closer
	var err error
	if txn == nil {
		coinBytes, closer, err = p.db.Get(coinKey(address))
	} else {
		coinBytes, closer, err = txn.Get(coinKey(address))
	}
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

func (p *PebbleCoinStore) GetPreCoinProofByAddress(address []byte) (
	*protobufs.PreCoinProof,
	error,
) {
	preCoinProofBytes, closer, err := p.db.Get(proofKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get pre coin proof by address")
		return nil, err
	}
	defer closer.Close()

	proof := &protobufs.PreCoinProof{}
	err = proto.Unmarshal(preCoinProofBytes[8:], proof)
	if err != nil {
		return nil, errors.Wrap(err, "get pre coin proof by address")
	}

	return proof, nil
}

func (p *PebbleCoinStore) RangePreCoinProofs() (Iterator, error) {
	iter, err := p.db.NewIter(
		proofKey(bytes.Repeat([]byte{0x00}, 32)),
		proofKey(bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range pre coin proofs")
	}

	return iter, nil
}

func (p *PebbleCoinStore) RangeCoins(
	start []byte,
	end []byte,
) (Iterator, error) {
	iter, err := p.db.NewIter(
		coinKey(start),
		coinKey(end),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range pre coin proofs")
	}

	return iter, nil
}

func (p *PebbleCoinStore) PutCoin(
	txn Transaction,
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

func (p *PebbleCoinStore) DeleteCoin(
	txn Transaction,
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

func (p *PebbleCoinStore) PutPreCoinProof(
	txn Transaction,
	frameNumber uint64,
	address []byte,
	preCoinProof *protobufs.PreCoinProof,
) error {
	proofBytes, err := proto.Marshal(preCoinProof)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	data := []byte{}
	data = binary.BigEndian.AppendUint64(data, frameNumber)
	data = append(data, proofBytes...)
	err = txn.Set(
		proofByOwnerKey(preCoinProof.Owner.GetImplicitAccount().Address, address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	err = txn.Set(
		proofKey(address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	return nil
}

func (p *PebbleCoinStore) DeletePreCoinProof(
	txn Transaction,
	address []byte,
	preCoinProof *protobufs.PreCoinProof,
) error {
	err := txn.Delete(proofKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return ErrNotFound
		}

		return errors.Wrap(err, "delete pre coin proof")
	}

	err = txn.Delete(
		proofByOwnerKey(
			preCoinProof.Owner.GetImplicitAccount().GetAddress(),
			address,
		),
	)
	if err != nil {
		return errors.Wrap(err, "delete pre coin proof")
	}

	return nil
}

func (p *PebbleCoinStore) GetLatestFrameProcessed() (uint64, error) {
	v, closer, err := p.db.Get(latestExecutionKey())
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return 0, nil
		}

		return 0, errors.Wrap(err, "get latest frame processed")
	}
	defer closer.Close()

	frameNumber := binary.BigEndian.Uint64(v)

	return frameNumber, nil
}

func (p *PebbleCoinStore) SetLatestFrameProcessed(
	txn Transaction,
	frameNumber uint64,
) error {
	if err := txn.Set(
		latestExecutionKey(),
		binary.BigEndian.AppendUint64([]byte{}, frameNumber),
	); err != nil {
		return errors.Wrap(err, "set latest frame processed")
	}

	return nil
}

func (p *PebbleCoinStore) SetMigrationVersion(
	genesisSeedHex string,
) error {
	seed, err := hex.DecodeString(genesisSeedHex)
	if err != nil {
		return errors.Wrap(err, "migrate")
	}

	txn, err := p.NewTransaction(false)
	if err != nil {
		return nil
	}

	err = txn.Set(migrationKey(), []byte{0x02, 0x00, 0x01, 0x04})
	if err != nil {
		p.logger.Panic("failed to set migration version", zap.Error(err))
	}

	err = txn.Set(genesisSeedKey(), seed)
	if err != nil {
		p.logger.Panic("failed to set genesis seed", zap.Error(err))
	}

	return txn.Commit()
}

func (p *PebbleCoinStore) internalMigrate(
	filter []byte,
	genesisSeed []byte,
) error {
	p.logger.Warn("incompatible state change detected, performing migration")
	err := p.db.DeleteRange(
		coinByOwnerKey(
			bytes.Repeat([]byte{0x00}, 32),
			bytes.Repeat([]byte{0x00}, 32),
		),
		coinByOwnerKey(
			bytes.Repeat([]byte{0xff}, 32),
			bytes.Repeat([]byte{0xff}, 32),
		),
	)
	if err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}
	err = p.db.DeleteRange(
		coinKey(
			bytes.Repeat([]byte{0x00}, 32),
		),
		coinKey(
			bytes.Repeat([]byte{0xff}, 32),
		),
	)
	if err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}
	err = p.db.DeleteRange(
		proofByOwnerKey(
			bytes.Repeat([]byte{0x00}, 32),
			bytes.Repeat([]byte{0x00}, 32),
		),
		proofByOwnerKey(
			bytes.Repeat([]byte{0xff}, 32),
			bytes.Repeat([]byte{0xff}, 32),
		),
	)
	if err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}
	err = p.db.DeleteRange(
		proofKey(
			bytes.Repeat([]byte{0x00}, 32),
		),
		proofKey(
			bytes.Repeat([]byte{0xff}, 32),
		),
	)
	if err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}
	if err := p.db.Delete(clockDataEarliestIndex(filter)); err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}
	if err := p.db.Delete(clockDataLatestIndex(filter)); err != nil {
		p.logger.Panic("failed to delete range", zap.Error(err))
	}

	txn, err := p.NewTransaction(false)
	if err != nil {
		return nil
	}

	err = txn.Set(migrationKey(), []byte{0x02, 0x00, 0x01, 0x04})
	if err != nil {
		p.logger.Panic("failed to set migration version", zap.Error(err))
	}

	err = txn.Set(genesisSeedKey(), genesisSeed)
	if err != nil {
		p.logger.Panic("failed to set genesis seed", zap.Error(err))
	}

	return txn.Commit()
}

func (p *PebbleCoinStore) Migrate(filter []byte, genesisSeedHex string) error {
	seed, err := hex.DecodeString(genesisSeedHex)
	if err != nil {
		return errors.Wrap(err, "migrate")
	}

	compare, closer, err := p.db.Get(genesisSeedKey())
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "migrate")
		}
		return p.internalMigrate(filter, seed)
	}
	defer closer.Close()

	if !bytes.Equal(compare, seed) {
		return p.internalMigrate(filter, seed)
	}

	status, closer, err := p.db.Get(migrationKey())
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "migrate")
		}

		txn, err := p.NewTransaction(false)
		if err != nil {
			return nil
		}

		err = txn.Set(migrationKey(), []byte{0x02, 0x00, 0x01, 0x04})
		if err != nil {
			p.logger.Panic("failed to set migration version", zap.Error(err))
		}
		return txn.Commit()
	} else {
		defer closer.Close()
		if len(status) == 4 && bytes.Compare(status, []byte{0x02, 0x00, 0x01, 0x04}) > 0 {
			p.logger.Panic("database has been migrated to a newer version, do not rollback")
		} else if len(status) == 3 || bytes.Compare(status, []byte{0x02, 0x00, 0x01, 0x04}) < 0 {
			return p.internalMigrate(filter, seed)
		}
		return nil
	}
}
