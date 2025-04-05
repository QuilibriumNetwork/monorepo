package store

import (
	"encoding/binary"
	"math/big"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

type DataProofStore interface {
	NewTransaction() (Transaction, error)
	GetAggregateProof(
		filter []byte,
		commitment []byte,
		frameNumber uint64,
	) (
		*protobufs.InclusionAggregateProof,
		error,
	)
	PutAggregateProof(
		txn Transaction,
		aggregateProof *protobufs.InclusionAggregateProof,
		commitment []byte,
	) error
	GetDataTimeProof(
		peerId []byte,
		increment uint32,
	) (difficulty, parallelism uint32, input, output []byte, err error)
	GetTotalReward(
		peerId []byte,
	) (*big.Int, error)
	PutDataTimeProof(
		txn Transaction,
		parallelism uint32,
		peerId []byte,
		increment uint32,
		input []byte,
		output []byte,
	) error
	GetLatestDataTimeProof(peerId []byte) (
		increment uint32,
		parallelism uint32,
		output []byte,
		err error,
	)
	RewindToIncrement(peerId []byte, increment uint32) error
}

var _ DataProofStore = (*PebbleDataProofStore)(nil)

type PebbleDataProofStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleDataProofStore(
	db KVDB,
	logger *zap.Logger,
) *PebbleDataProofStore {
	return &PebbleDataProofStore{
		db,
		logger,
	}
}

const (
	DATA_PROOF             = 0x04
	DATA_PROOF_METADATA    = 0x00
	DATA_PROOF_INCLUSION   = 0x01
	DATA_PROOF_SEGMENT     = 0x02
	DATA_TIME_PROOF        = 0x05
	DATA_TIME_PROOF_DATA   = 0x00
	DATA_TIME_PROOF_LATEST = 0x01
)

func dataProofMetadataKey(filter []byte, commitment []byte) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_METADATA}
	key = append(key, commitment...)
	key = append(key, filter...)
	return key
}

func dataProofInclusionKey(
	filter []byte,
	commitment []byte,
	seqNo uint64,
) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_INCLUSION}
	key = append(key, commitment...)
	key = binary.BigEndian.AppendUint64(key, seqNo)
	key = append(key, filter...)
	return key
}

func dataProofSegmentKey(
	filter []byte,
	hash []byte,
) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_SEGMENT}
	key = append(key, hash...)
	key = append(key, filter...)
	return key
}

func dataTimeProofKey(peerId []byte, increment uint32) []byte {
	key := []byte{DATA_TIME_PROOF, DATA_TIME_PROOF_DATA}
	key = append(key, peerId...)
	key = binary.BigEndian.AppendUint32(key, increment)
	return key
}

func dataTimeProofLatestKey(peerId []byte) []byte {
	key := []byte{DATA_TIME_PROOF, DATA_TIME_PROOF_LATEST}
	key = append(key, peerId...)
	return key
}

func (p *PebbleDataProofStore) NewTransaction() (Transaction, error) {
	return p.db.NewBatch(false), nil
}

func internalGetAggregateProof(
	db KVDB,
	filter []byte,
	commitment []byte,
	frameNumber uint64,
) (*protobufs.InclusionAggregateProof, error) {
	value, closer, err := db.Get(dataProofMetadataKey(filter, commitment))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get aggregate proof")
	}
	defer closer.Close()

	copied := make([]byte, len(value[8:]))
	limit := binary.BigEndian.Uint64(value[0:8])
	copy(copied, value[8:])

	aggregate := &protobufs.InclusionAggregateProof{
		Filter:               filter,
		FrameNumber:          frameNumber,
		InclusionCommitments: []*protobufs.InclusionCommitment{},
		Proof:                copied,
	}

	iter, err := db.NewIter(
		dataProofInclusionKey(filter, commitment, 0),
		dataProofInclusionKey(filter, commitment, limit+1),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get aggregate proof")
	}
	defer iter.Close()

	i := uint32(0)

	for iter.First(); iter.Valid(); iter.Next() {
		incCommit := iter.Value()

		urlLength := binary.BigEndian.Uint16(incCommit[:2])
		commitLength := binary.BigEndian.Uint16(incCommit[2:4])

		url := make([]byte, urlLength)
		copy(url, incCommit[4:urlLength+4])

		commit := make([]byte, commitLength)
		copy(commit, incCommit[urlLength+4:urlLength+4+commitLength])

		remainder := int(urlLength + 4 + commitLength)

		inclusionCommitment := &protobufs.InclusionCommitment{
			Filter:      filter,
			FrameNumber: frameNumber,
			Position:    i,
			TypeUrl:     string(url),
			Commitment:  commit,
		}

		chunks := [][]byte{}
		for j := 0; j < (len(incCommit)-remainder)/32; j++ {
			start := remainder + (j * 32)
			end := remainder + ((j + 1) * 32)
			segValue, dataCloser, err := db.Get(
				dataProofSegmentKey(filter, incCommit[start:end]),
			)
			if err != nil {
				if errors.Is(err, pebble.ErrNotFound) {
					// If we've lost this key it means we're in a corrupted state
					return nil, ErrInvalidData
				}

				return nil, errors.Wrap(err, "get aggregate proof")
			}
			defer dataCloser.Close()

			segCopy := make([]byte, len(segValue))
			copy(segCopy, segValue)
			chunks = append(chunks, segCopy)
		}

		if string(url) == protobufs.IntrinsicExecutionOutputType {
			o := &protobufs.IntrinsicExecutionOutput{}
			copiedLeft := make([]byte, len(chunks[0]))
			copiedRight := make([]byte, len(chunks[1]))
			copy(copiedLeft, chunks[0])
			copy(copiedRight, chunks[1])

			o.Address = copiedLeft[:32]
			o.Output = copiedLeft[32:]
			o.Proof = copiedRight
			inclusionCommitment.Data, err = proto.Marshal(o)
			if err != nil {
				return nil, errors.Wrap(err, "get aggregate proof")
			}
		} else {
			copied := make([]byte, len(chunks[0]))
			copy(copied, chunks[0])
			inclusionCommitment.Data = copied
		}

		aggregate.InclusionCommitments = append(
			aggregate.InclusionCommitments,
			inclusionCommitment,
		)
		i++
	}

	return aggregate, nil
}

func internalListAggregateProofKeys(
	db KVDB,
	filter []byte,
	commitment []byte,
	frameNumber uint64,
) ([][]byte, [][]byte, [][]byte, error) {
	logger := utils.GetLogger()
	proofs := [][]byte{dataProofMetadataKey(filter, commitment)}
	commits := [][]byte{}
	data := [][]byte{}

	value, closer, err := db.Get(dataProofMetadataKey(filter, commitment))
	if err != nil {
		logger.Error("proof lookup failed", zap.Error(err))

		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, nil, ErrNotFound
		}

		return nil, nil, nil, errors.Wrap(err, "list aggregate proof")
	}
	defer closer.Close()

	copied := make([]byte, len(value[8:]))
	limit := binary.BigEndian.Uint64(value[0:8])
	copy(copied, value[8:])

	iter, err := db.NewIter(
		dataProofInclusionKey(filter, commitment, 0),
		dataProofInclusionKey(filter, commitment, limit+1),
	)
	if err != nil {
		logger.Error("inclusion lookup failed", zap.Error(err))

		return nil, nil, nil, errors.Wrap(err, "list aggregate proof")
	}
	defer iter.Close()

	i := uint32(0)
	commits = append(commits, dataProofInclusionKey(filter, commitment, 0))
	for iter.First(); iter.Valid(); iter.Next() {
		incCommit := iter.Value()

		urlLength := binary.BigEndian.Uint16(incCommit[:2])
		commitLength := binary.BigEndian.Uint16(incCommit[2:4])

		url := make([]byte, urlLength)
		copy(url, incCommit[4:urlLength+4])

		commit := make([]byte, commitLength)
		copy(commit, incCommit[urlLength+4:urlLength+4+commitLength])

		remainder := int(urlLength + 4 + commitLength)

		for j := 0; j < (len(incCommit)-remainder)/32; j++ {
			start := remainder + (j * 32)
			end := remainder + ((j + 1) * 32)

			data = append(data, dataProofSegmentKey(filter, incCommit[start:end]))
		}

		i++
	}

	return proofs, commits, data, nil
}

func (p *PebbleDataProofStore) GetAggregateProof(
	filter []byte,
	commitment []byte,
	frameNumber uint64,
) (*protobufs.InclusionAggregateProof, error) {
	return internalGetAggregateProof(
		p.db,
		filter,
		commitment,
		frameNumber,
	)
}

func internalDeleteAggregateProof(
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
) error {
	for i, inc := range aggregateProof.InclusionCommitments {
		var segments [][]byte
		if inc.TypeUrl == protobufs.IntrinsicExecutionOutputType {
			o := &protobufs.IntrinsicExecutionOutput{}
			if err := proto.Unmarshal(inc.Data, o); err != nil {
				return errors.Wrap(err, "delete aggregate proof")
			}
			leftBits := append([]byte{}, o.Address...)
			leftBits = append(leftBits, o.Output...)
			rightBits := o.Proof
			segments = [][]byte{leftBits, rightBits}
		} else {
			segments = [][]byte{inc.Data}
		}

		for _, segment := range segments {
			hash := sha3.Sum256(segment)
			if err := txn.Delete(
				dataProofSegmentKey(aggregateProof.Filter, hash[:]),
			); err != nil {
				return errors.Wrap(err, "delete aggregate proof")
			}
		}

		if err := txn.Delete(
			dataProofInclusionKey(aggregateProof.Filter, commitment, uint64(i)),
		); err != nil {
			return errors.Wrap(err, "delete aggregate proof")
		}
	}

	if err := txn.Delete(
		dataProofMetadataKey(aggregateProof.Filter, commitment),
	); err != nil {
		return errors.Wrap(err, "delete aggregate proof")
	}

	return nil
}

func internalPutAggregateProof(
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
) error {
	buf := binary.BigEndian.AppendUint64(
		nil,
		uint64(len(aggregateProof.InclusionCommitments)),
	)
	buf = append(buf, aggregateProof.Proof...)

	for i, inc := range aggregateProof.InclusionCommitments {
		var segments [][]byte
		if inc.TypeUrl == protobufs.IntrinsicExecutionOutputType {
			o := &protobufs.IntrinsicExecutionOutput{}
			if err := proto.Unmarshal(inc.Data, o); err != nil {
				return errors.Wrap(err, "get aggregate proof")
			}
			leftBits := append([]byte{}, o.Address...)
			leftBits = append(leftBits, o.Output...)
			rightBits := o.Proof
			segments = [][]byte{leftBits, rightBits}
		} else {
			segments = [][]byte{inc.Data}
		}

		urlLength := len(inc.TypeUrl)
		commitLength := len(inc.Commitment)
		encoded := binary.BigEndian.AppendUint16(nil, uint16(urlLength))
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(commitLength))

		encoded = append(encoded, []byte(inc.TypeUrl)...)
		encoded = append(encoded, inc.Commitment...)

		for _, segment := range segments {
			hash := sha3.Sum256(segment)
			if err := txn.Set(
				dataProofSegmentKey(aggregateProof.Filter, hash[:]),
				segment,
			); err != nil {
				return errors.Wrap(err, "put aggregate proof")
			}
			encoded = append(encoded, hash[:]...)
		}

		if err := txn.Set(
			dataProofInclusionKey(aggregateProof.Filter, commitment, uint64(i)),
			encoded,
		); err != nil {
			return errors.Wrap(err, "put aggregate proof")
		}
	}

	if err := txn.Set(
		dataProofMetadataKey(aggregateProof.Filter, commitment),
		buf,
	); err != nil {
		return errors.Wrap(err, "put aggregate proof")
	}

	return nil
}

func (p *PebbleDataProofStore) PutAggregateProof(
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
) error {
	return internalPutAggregateProof(
		txn,
		aggregateProof,
		commitment,
	)
}

func (p *PebbleDataProofStore) GetDataTimeProof(
	peerId []byte,
	increment uint32,
) (difficulty, parallelism uint32, input, output []byte, err error) {
	data, closer, err := p.db.Get(dataTimeProofKey(peerId, increment))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return
		}
		err = errors.Wrap(err, "get data time proof")
		return
	}
	defer closer.Close()

	if len(data) < 24 {
		err = ErrInvalidData
		return
	}

	difficulty = binary.BigEndian.Uint32(data[:4])
	parallelism = binary.BigEndian.Uint32(data[4:8])
	inputLen := binary.BigEndian.Uint64(data[8:16])

	// Verify length of remaining data is at least equal to the input and next
	// length prefix
	if uint64(len(data[16:])) < inputLen+8 {
		err = ErrInvalidData
		return
	}

	input = make([]byte, inputLen)
	copy(input[:], data[16:16+inputLen])

	outputLen := binary.BigEndian.Uint64(data[16+inputLen : 16+inputLen+8])

	// Verify length
	if uint64(len(data[16+inputLen+8:])) < outputLen {
		err = ErrInvalidData
		return
	}

	output = make([]byte, outputLen)
	copy(output[:], data[16+inputLen+8:])
	return difficulty, parallelism, input, output, nil
}

func (p *PebbleDataProofStore) GetTotalReward(
	peerId []byte,
) (*big.Int, error) {
	reward := big.NewInt(0)
	prev, closer, err := p.db.Get(dataTimeProofLatestKey(peerId))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return big.NewInt(0), nil
		}

		return nil, errors.Wrap(err, "get total difficulty sum")
	}
	defer closer.Close()

	if len(prev) != 0 {
		reward.SetBytes(prev[4:])
	}

	return reward, nil
}

func (p *PebbleDataProofStore) PutDataTimeProof(
	txn Transaction,
	parallelism uint32,
	peerId []byte,
	increment uint32,
	input []byte,
	output []byte,
) error {
	// Now, for the assumptions.
	// Rewards are calculated based off of a current average rate of growth such
	// that we continue at the rate we have been, for the course of the next month
	// and carry it to now it such that the greatest advantage gleaned is from
	// upgrading on time, akin to a "difficulty bomb" in reverse, but locally
	// calculated.
	difficulty := 200000 - (increment / 4)
	if difficulty < 25000 || increment > 800000 {
		difficulty = 25000
	}

	// Basis split on the estimated shard level for growth rate (in terms of
	// units): 240 (QUIL) * 8000000000 (conversion factor) / 1600000 (shards)
	//       = 1200000 units per reward interval per core
	pomwBasis := big.NewInt(1200000)
	reward := new(big.Int)
	reward = reward.Mul(pomwBasis, big.NewInt(int64(parallelism)))

	priorSum := big.NewInt(0)
	prev, closer, err := p.db.Get(dataTimeProofLatestKey(peerId))
	if err != nil && (!errors.Is(err, pebble.ErrNotFound) || increment != 0) {
		return errors.Wrap(err, "put data time proof")
	}
	defer closer.Close()

	if len(prev) != 0 {
		priorSum.SetBytes(prev[4:])
		prevIncrement := binary.BigEndian.Uint32(prev[:4])

		if prevIncrement != increment-1 {
			return errors.Wrap(errors.New("invalid increment"), "put data time proof")
		}
	}

	data := []byte{}
	data = binary.BigEndian.AppendUint32(data, difficulty)
	data = binary.BigEndian.AppendUint32(data, parallelism)
	data = binary.BigEndian.AppendUint64(data, uint64(len(input)))
	data = append(data, input...)
	data = binary.BigEndian.AppendUint64(data, uint64(len(output)))
	data = append(data, output...)
	err = txn.Set(dataTimeProofKey(peerId, increment), data)
	if err != nil {
		return errors.Wrap(err, "put data time proof")
	}

	latest := []byte{}
	latest = binary.BigEndian.AppendUint32(latest, increment)

	priorSum.Add(priorSum, reward)
	latest = append(latest, priorSum.FillBytes(make([]byte, 32))...)

	if err = txn.Set(dataTimeProofLatestKey(peerId), latest); err != nil {
		return errors.Wrap(err, "put data time proof")
	}

	return nil
}

func (p *PebbleDataProofStore) GetLatestDataTimeProof(peerId []byte) (
	increment uint32,
	parallelism uint32,
	output []byte,
	err error,
) {
	prev, closer, err := p.db.Get(dataTimeProofLatestKey(peerId))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return 0, 0, nil, ErrNotFound
		}

		return 0, 0, nil, errors.Wrap(err, "get latest data time proof")
	}
	defer closer.Close()

	if len(prev) < 4 {
		return 0, 0, nil, ErrInvalidData
	}

	increment = binary.BigEndian.Uint32(prev[:4])

	_, parallelism, _, output, err = p.GetDataTimeProof(peerId, increment)

	return increment, parallelism, output, err
}

func (p *PebbleDataProofStore) RewindToIncrement(
	peerId []byte,
	increment uint32,
) error {
	reward := new(big.Int)
	for j := uint32(0); j <= increment; j++ {
		_, parallelism, _, _, err := p.GetDataTimeProof(peerId, uint32(j))
		if err != nil {
			p.logger.Panic("Failed to get data time proof", zap.Error(err))
		}

		pomwBasis := big.NewInt(1200000)

		reward = reward.Add(
			reward,
			new(big.Int).Mul(pomwBasis, big.NewInt(int64(parallelism))),
		)
	}

	latest := []byte{}
	latest = binary.BigEndian.AppendUint32(latest, increment)

	latest = append(latest, reward.FillBytes(make([]byte, 32))...)

	if err := p.db.Set(dataTimeProofLatestKey(peerId), latest); err != nil {
		return errors.Wrap(err, "put data time proof")
	}

	return nil
}
