package store

import (
	"encoding/binary"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type KeyStore interface {
	NewTransaction() (Transaction, error)
	StageProvingKey(provingKey *protobufs.ProvingKeyAnnouncement) error
	IncludeProvingKey(
		inclusionCommitment *protobufs.InclusionCommitment,
		txn Transaction,
	) error
	GetStagedProvingKey(
		provingKey []byte,
	) (*protobufs.ProvingKeyAnnouncement, error)
	GetProvingKey(provingKey []byte) (*protobufs.InclusionCommitment, error)
	GetKeyBundle(
		provingKey []byte,
		frameNumber uint64,
	) (*protobufs.InclusionCommitment, error)
	GetLatestKeyBundle(provingKey []byte) (*protobufs.InclusionCommitment, error)
	PutKeyBundle(
		provingKey []byte,
		keyBundleCommitment *protobufs.InclusionCommitment,
		txn Transaction,
	) error
	RangeProvingKeys() (*PebbleProvingKeyIterator, error)
	RangeStagedProvingKeys() (*PebbleStagedProvingKeyIterator, error)
	RangeKeyBundleKeys(provingKey []byte) (*PebbleKeyBundleIterator, error)
}

type PebbleKeyStore struct {
	db     KVDB
	logger *zap.Logger
}

type PebbleProvingKeyIterator struct {
	i Iterator
}

type PebbleStagedProvingKeyIterator struct {
	i Iterator
}

type PebbleKeyBundleIterator struct {
	i Iterator
}

var pki = (*PebbleProvingKeyIterator)(nil)
var spki = (*PebbleStagedProvingKeyIterator)(nil)
var kbi = (*PebbleKeyBundleIterator)(nil)
var _ TypedIterator[*protobufs.InclusionCommitment] = pki
var _ TypedIterator[*protobufs.ProvingKeyAnnouncement] = spki
var _ TypedIterator[*protobufs.InclusionCommitment] = kbi
var _ KeyStore = (*PebbleKeyStore)(nil)

func (p *PebbleProvingKeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleProvingKeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleProvingKeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleProvingKeyIterator) Value() (
	*protobufs.InclusionCommitment,
	error,
) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.InclusionCommitment{}
	if err := proto.Unmarshal(value, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get proving key iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleProvingKeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

func (p *PebbleStagedProvingKeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleStagedProvingKeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleStagedProvingKeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleStagedProvingKeyIterator) Value() (
	*protobufs.ProvingKeyAnnouncement,
	error,
) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ProvingKeyAnnouncement{}
	if err := proto.Unmarshal(value, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get staged proving key iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleStagedProvingKeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

func (p *PebbleKeyBundleIterator) First() bool {
	return p.i.First()
}

func (p *PebbleKeyBundleIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleKeyBundleIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleKeyBundleIterator) Value() (
	*protobufs.InclusionCommitment,
	error,
) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.InclusionCommitment{}
	if err := proto.Unmarshal(value, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get key bundle iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleKeyBundleIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

func NewPebbleKeyStore(db KVDB, logger *zap.Logger) *PebbleKeyStore {
	return &PebbleKeyStore{
		db,
		logger,
	}
}

const (
	PROVING_KEY               = 0x01
	PROVING_KEY_STAGED        = 0x02
	KEY_BUNDLE                = 0x03
	KEY_DATA                  = 0x00
	KEY_BUNDLE_INDEX_EARLIEST = 0x10
	KEY_BUNDLE_INDEX_LATEST   = 0x20
)

func provingKeyKey(provingKey []byte) []byte {
	key := []byte{PROVING_KEY, KEY_DATA}
	key = append(key, provingKey...)
	return key
}

func stagedProvingKeyKey(provingKey []byte) []byte {
	key := []byte{PROVING_KEY_STAGED, KEY_DATA}
	key = append(key, provingKey...)
	return key
}

func keyBundleKey(provingKey []byte, frameNumber uint64) []byte {
	key := []byte{KEY_BUNDLE, KEY_DATA}
	key = append(key, provingKey...)
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	return key
}

func keyBundleLatestKey(provingKey []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_BUNDLE_INDEX_LATEST}
	key = append(key, provingKey...)
	return key
}

func keyBundleEarliestKey(provingKey []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_BUNDLE_INDEX_EARLIEST}
	key = append(key, provingKey...)
	return key
}

func (p *PebbleKeyStore) NewTransaction() (Transaction, error) {
	return p.db.NewBatch(false), nil
}

// Stages a proving key for later inclusion on proof of meaningful work.
// Does not verify, upstream callers must verify.
func (p *PebbleKeyStore) StageProvingKey(
	provingKey *protobufs.ProvingKeyAnnouncement,
) error {
	data, err := proto.Marshal(provingKey)
	if err != nil {
		return errors.Wrap(err, "stage proving key")
	}

	err = p.db.Set(
		stagedProvingKeyKey(provingKey.PublicKey()),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "stage proving key")
	}

	return nil
}

// Includes a proving key with an inclusion commitment. If a proving key is
// staged, promotes it by including it in the primary key store and deletes the
// staged key.
func (p *PebbleKeyStore) IncludeProvingKey(
	inclusionCommitment *protobufs.InclusionCommitment,
	txn Transaction,
) error {
	provingKey := &protobufs.ProvingKeyAnnouncement{}
	if err := proto.Unmarshal(inclusionCommitment.Data, provingKey); err != nil {
		return errors.Wrap(err, "include proving key")
	}

	if err := provingKey.Verify(); err != nil {
		return errors.Wrap(err, "include proving key")
	}

	data, err := proto.Marshal(inclusionCommitment)
	if err != nil {
		return errors.Wrap(err, "include proving key")
	}

	txn.Set(
		provingKeyKey(provingKey.PublicKey()),
		data,
	)

	staged, closer, err := p.db.Get(stagedProvingKeyKey(provingKey.PublicKey()))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return errors.Wrap(err, "include proving key")
	} else if err == nil {
		defer closer.Close()
	}

	if staged != nil {
		if err := txn.Delete(
			stagedProvingKeyKey(provingKey.PublicKey()),
		); err != nil {
			return errors.Wrap(err, "include proving key")
		}
	}

	return nil
}

func (p *PebbleKeyStore) GetStagedProvingKey(
	provingKey []byte,
) (*protobufs.ProvingKeyAnnouncement, error) {
	data, closer, err := p.db.Get(stagedProvingKeyKey(provingKey))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get staged proving key")
	}
	defer closer.Close()

	stagedKey := &protobufs.ProvingKeyAnnouncement{}
	if err = proto.Unmarshal(data, stagedKey); err != nil {
		return nil, errors.Wrap(err, "get staged proving key")
	}

	return stagedKey, nil
}

// Returns the latest key bundle for a given proving key.
func (p *PebbleKeyStore) GetLatestKeyBundle(
	provingKey []byte,
) (*protobufs.InclusionCommitment, error) {
	value, closer, err := p.db.Get(keyBundleLatestKey(provingKey))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest key bundle")
	}
	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(value)

	value, closer, err = p.db.Get(keyBundleKey(provingKey, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest key bundle")
	}
	defer closer.Close()

	announcement := &protobufs.InclusionCommitment{}
	if err := proto.Unmarshal(value, announcement); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get latest key bundle",
		)
	}

	return announcement, nil
}

// Retrieves the specific key bundle included at a given frame number.
func (p *PebbleKeyStore) GetKeyBundle(
	provingKey []byte,
	frameNumber uint64,
) (*protobufs.InclusionCommitment, error) {
	value, closer, err := p.db.Get(keyBundleKey(provingKey, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get key bundle")
	}

	defer closer.Close()

	announcement := &protobufs.InclusionCommitment{}
	if err := proto.Unmarshal(value, announcement); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get key bundle",
		)
	}

	return announcement, nil
}

// Retrieves an included proving key, returns ErrNotFound if not present.
func (p *PebbleKeyStore) GetProvingKey(
	provingKey []byte,
) (*protobufs.InclusionCommitment, error) {
	value, closer, err := p.db.Get(provingKeyKey(provingKey))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get proving key")
	}

	defer closer.Close()

	announcement := &protobufs.InclusionCommitment{}
	if err := proto.Unmarshal(value, announcement); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get proving key",
		)
	}

	return announcement, nil
}

// Inserts a key bundle with inclusion commitment. Does not verify, upstream
// callers must perform the verification.
func (p *PebbleKeyStore) PutKeyBundle(
	provingKey []byte,
	keyBundle *protobufs.InclusionCommitment,
	txn Transaction,
) error {
	data, err := proto.Marshal(keyBundle)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"put key bundle",
		)
	}

	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, keyBundle.FrameNumber)

	if err = txn.Set(
		keyBundleKey(provingKey, keyBundle.FrameNumber),
		data,
	); err != nil {
		return errors.Wrap(err, "put key bundle")
	}

	_, closer, err := p.db.Get(keyBundleEarliestKey(provingKey))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "put key bundle")
		}

		if err = txn.Set(
			keyBundleEarliestKey(provingKey),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "put key bundle")
		}
	} else {
		_ = closer.Close()
	}

	if err = txn.Set(
		keyBundleLatestKey(provingKey),
		frameNumberBytes,
	); err != nil {
		return errors.Wrap(err, "put key bundle")
	}

	return nil
}

func (p *PebbleKeyStore) RangeProvingKeys() (*PebbleProvingKeyIterator, error) {
	iter, err := p.db.NewIter(
		provingKeyKey([]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		}),
		provingKeyKey([]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff,
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range proving keys")
	}

	return &PebbleProvingKeyIterator{i: iter}, nil
}

func (p *PebbleKeyStore) RangeStagedProvingKeys() (
	*PebbleStagedProvingKeyIterator,
	error,
) {
	iter, err := p.db.NewIter(
		stagedProvingKeyKey([]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,
		}),
		stagedProvingKeyKey([]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff,
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range staged proving keys")
	}

	return &PebbleStagedProvingKeyIterator{i: iter}, nil
}

func (p *PebbleKeyStore) RangeKeyBundleKeys(provingKey []byte) (
	*PebbleKeyBundleIterator,
	error,
) {
	iter, err := p.db.NewIter(
		keyBundleKey(provingKey, 0),
		keyBundleKey(provingKey, 0xffffffffffffffff),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range key bundle keys")
	}

	return &PebbleKeyBundleIterator{i: iter}, nil
}
