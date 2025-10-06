package vdf

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type WesolowskiFrameProver struct {
	logger *zap.Logger
}

func NewCachedWesolowskiFrameProver(logger *zap.Logger) qcrypto.FrameProver {
	return qcrypto.NewCachedFrameProver(NewWesolowskiFrameProver(logger))
}

func NewWesolowskiFrameProver(logger *zap.Logger) *WesolowskiFrameProver {
	return &WesolowskiFrameProver{
		logger,
	}
}

// SetBitAtIndex sets the bit at the given index in a copy of the mask and
// returns it.
func SetBitAtIndex(mask []byte, index uint8) []byte {
	byteIndex := index / 8
	bitPos := index % 8

	newMask := make([]byte, 32)
	copy(newMask, mask)
	mask = newMask

	mask[byteIndex] |= 1 << bitPos
	return mask
}

// GetSetBitIndices returns a slice of indices where bits are set in the mask.
func GetSetBitIndices(mask []byte) []uint8 {
	var indices []uint8
	for byteIdx, b := range mask {
		for bitPos := 0; bitPos < 8; bitPos++ {
			if b&(1<<bitPos) != 0 {
				indices = append(indices, uint8(byteIdx*8+bitPos))
			}
		}
	}
	return indices
}

func (w *WesolowskiFrameProver) CalculateMultiProof(
	challenge [32]byte,
	difficulty uint32,
	ids [][]byte,
	index uint32,
) [516]byte {
	return WesolowskiSolveMulti(challenge, difficulty, ids, index)
}

func (w *WesolowskiFrameProver) VerifyMultiProof(
	challenge [32]byte,
	difficulty uint32,
	ids [][]byte,
	allegedSolutions [][516]byte,
) (bool, error) {
	if len(ids) != len(allegedSolutions) || len(ids) == 0 {
		return false, errors.New("invalid payload")
	}

	return WesolowskiVerifyMulti(
		challenge,
		difficulty,
		ids,
		allegedSolutions,
	), nil
}

func (w *WesolowskiFrameProver) ProveFrameHeaderGenesis(
	address []byte,
	difficulty uint32,
	input []byte,
	feeMultiplierVote uint64,
) (*protobufs.FrameHeader, error) {
	input = slices.Clone(input)
	input = append(input, address...)
	input = binary.BigEndian.AppendUint64(
		input,
		0,
	)
	input = binary.BigEndian.AppendUint64(input, uint64(0))
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = binary.BigEndian.AppendUint64(input, feeMultiplierVote)
	input = append(input, make([]byte, 32)...)

	b := sha3.Sum256(input)
	o := WesolowskiSolve(b, difficulty)

	stateRoots := make([][]byte, 4)
	for i := range stateRoots {
		stateRoots[i] = make([]byte, 74)
	}

	header := &protobufs.FrameHeader{
		Address:           address,
		FrameNumber:       0,
		Timestamp:         0,
		Difficulty:        difficulty,
		Output:            o[:],
		ParentSelector:    make([]byte, 32),
		FeeMultiplierVote: feeMultiplierVote,
		RequestsRoot:      make([]byte, 74),
		StateRoots:        stateRoots,
	}

	return header, nil
}

func (w *WesolowskiFrameProver) ProveFrameHeader(
	previousFrame *protobufs.FrameHeader,
	address []byte,
	requestsRoot []byte,
	stateRoots [][]byte,
	prover []byte,
	provingKey qcrypto.Signer,
	timestamp int64,
	difficulty uint32,
	feeMultiplierVote uint64,
	proverIndex uint8,
) (*protobufs.FrameHeader, error) {
	if previousFrame == nil {
		return nil, errors.Wrap(
			errors.New("missing header"),
			"prove frame header",
		)
	}

	pubkeyType := provingKey.GetType()

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove frame header")
	}

	input := []byte{}
	input = append(input, address...)
	input = binary.BigEndian.AppendUint64(
		input,
		previousFrame.FrameNumber+1,
	)
	input = binary.BigEndian.AppendUint64(input, uint64(timestamp))
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = binary.BigEndian.AppendUint64(input, feeMultiplierVote)
	input = append(input, parent.FillBytes(make([]byte, 32))...)
	input = append(input, requestsRoot...)

	for _, stateRoot := range stateRoots {
		input = append(input, stateRoot...)
	}

	input = append(input, prover...)

	b := sha3.Sum256(input)
	o := WesolowskiSolve(b, difficulty)

	domain := append([]byte("shard"), address...)
	signature, err := provingKey.SignWithDomain(
		append(append([]byte{}, b[:]...), o[:]...),
		domain,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove frame header",
		)
	}

	header := &protobufs.FrameHeader{
		Address:           address,
		FrameNumber:       previousFrame.FrameNumber + 1,
		Timestamp:         timestamp,
		Difficulty:        difficulty,
		Output:            o[:],
		ParentSelector:    parent.FillBytes(make([]byte, 32)),
		FeeMultiplierVote: feeMultiplierVote,
		RequestsRoot:      requestsRoot,
		StateRoots:        stateRoots,
		Prover:            prover,
	}

	switch pubkeyType {
	case qcrypto.KeyTypeBLS48581G1:
		fallthrough
	case qcrypto.KeyTypeBLS48581G2:
		header.PublicKeySignatureBls48581 = &protobufs.BLS48581AggregateSignature{
			Bitmask:   SetBitAtIndex(make([]byte, 32), proverIndex),
			Signature: signature,
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: provingKey.Public().([]byte),
			},
		}
	default:
		return nil, errors.Wrap(
			errors.New("unsupported proving key"),
			"prove frame header",
		)
	}

	return header, nil
}

// GetFrameSignaturePayload extracts the signature payload from a frame header
func (w *WesolowskiFrameProver) GetFrameSignaturePayload(
	frame *protobufs.FrameHeader,
) ([]byte, error) {
	if len(frame.ParentSelector) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid selector"),
			"get frame signature payload",
		)
	}

	if len(frame.Output) != 516 {
		return nil, errors.Wrap(
			errors.New("invalid output"),
			"get frame signature payload",
		)
	}

	input := []byte{}
	input = append(input, frame.Address...)
	input = binary.BigEndian.AppendUint64(
		input,
		frame.FrameNumber,
	)
	input = binary.BigEndian.AppendUint64(input, uint64(frame.Timestamp))
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = binary.BigEndian.AppendUint64(input, frame.FeeMultiplierVote)
	input = append(input, frame.ParentSelector...)
	input = append(input, frame.RequestsRoot...)

	for _, stateRoot := range frame.StateRoots {
		input = append(input, stateRoot...)
	}

	input = append(input, frame.Prover...)

	b := sha3.Sum256(input)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	return append(append([]byte{}, b[:]...), proof[:]...), nil
}

func (w *WesolowskiFrameProver) VerifyFrameHeader(
	frame *protobufs.FrameHeader,
	bls qcrypto.BlsConstructor,
) ([]uint8, error) {
	if len(frame.Address) == 0 {
		return nil, errors.Wrap(
			errors.New("invalid address"),
			"verify frame header",
		)
	}

	if len(frame.RequestsRoot) != 74 && len(frame.RequestsRoot) != 64 {
		return nil, errors.Wrap(
			errors.New("invalid requests root length"),
			"verify frame header",
		)
	}

	if len(frame.StateRoots) != 4 {
		return nil, errors.Wrap(
			errors.New("invalid state roots count"),
			"verify frame header",
		)
	}

	for _, stateRoot := range frame.StateRoots {
		if len(stateRoot) != 74 && len(stateRoot) != 64 {
			return nil, errors.Wrap(
				errors.New("invalid state root length"),
				"verify frame header",
			)
		}
	}

	if len(frame.Prover) == 0 {
		return nil, errors.Wrap(
			errors.New("invalid prover"),
			"verify frame header",
		)
	}

	if frame.FrameNumber == 0 {
		return bytes.Repeat([]uint8{0xff}, 32), nil
	}

	// Get the signature payload
	signaturePayload, err := w.GetFrameSignaturePayload(frame)
	if err != nil {
		return nil, errors.Wrap(err, "verify frame header")
	}

	// Extract the hash and proof from the signature payload
	b := [32]byte{}
	copy(b[:], signaturePayload[:32])
	proof := [516]byte{}
	copy(proof[:], signaturePayload[32:])

	if !WesolowskiVerify(b, frame.Difficulty, proof) {
		return nil, errors.Wrap(
			errors.New("invalid proof"),
			"verify frame header",
		)
	}

	if frame.PublicKeySignatureBls48581 == nil {
		return nil, nil
	}

	valid, err := w.VerifyFrameHeaderSignature(frame, bls)
	if err != nil {
		return nil, errors.Wrap(err, "verify frame header")
	}

	if !valid {
		return nil, errors.Wrap(
			errors.New("invalid signature"),
			"verify frame header",
		)
	}

	return GetSetBitIndices(frame.PublicKeySignatureBls48581.Bitmask), nil
}

func (w *WesolowskiFrameProver) VerifyFrameHeaderSignature(
	frame *protobufs.FrameHeader,
	bls qcrypto.BlsConstructor,
) (bool, error) {
	// Get the signature payload
	signaturePayload, err := w.GetFrameSignaturePayload(frame)
	if err != nil {
		return false, errors.Wrap(err, "verify frame header signature")
	}

	domain := append([]byte("shard"), frame.Address...)
	if !bls.VerifySignatureRaw(
		frame.PublicKeySignatureBls48581.PublicKey.KeyValue,
		frame.PublicKeySignatureBls48581.Signature,
		signaturePayload,
		domain,
	) {
		return false, errors.Wrap(
			errors.New("invalid signature"),
			"verify frame header signature",
		)
	}

	return true, nil
}

func (w *WesolowskiFrameProver) ProveGlobalFrameHeader(
	previousFrame *protobufs.GlobalFrameHeader,
	commitments [][]byte,
	proverRoot []byte,
	provingKey qcrypto.Signer,
	timestamp int64,
	difficulty uint32,
	proverIndex uint8,
) (*protobufs.GlobalFrameHeader, error) {
	if previousFrame == nil {
		return nil, errors.Wrap(
			errors.New("missing header"),
			"prove global frame header",
		)
	}

	pubkeyType := provingKey.GetType()

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove global frame header")
	}

	input := []byte{}
	input = binary.BigEndian.AppendUint64(
		input,
		previousFrame.FrameNumber+1,
	)
	input = binary.BigEndian.AppendUint64(input, uint64(timestamp))
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, parent.FillBytes(make([]byte, 32))...)

	for _, commitment := range commitments {
		input = append(input, commitment...)
	}

	input = append(input, proverRoot...)

	b := sha3.Sum256(input)
	o := WesolowskiSolve(b, difficulty)

	signature, err := provingKey.SignWithDomain(
		append(append([]byte{}, b[:]...), o[:]...),
		[]byte("global"),
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove global frame header",
		)
	}

	header := &protobufs.GlobalFrameHeader{
		FrameNumber:          previousFrame.FrameNumber + 1,
		Timestamp:            timestamp,
		Difficulty:           difficulty,
		Output:               o[:],
		ParentSelector:       parent.FillBytes(make([]byte, 32)),
		GlobalCommitments:    commitments,
		ProverTreeCommitment: proverRoot,
	}

	switch pubkeyType {
	case qcrypto.KeyTypeBLS48581G1:
		fallthrough
	case qcrypto.KeyTypeBLS48581G2:
		header.PublicKeySignatureBls48581 = &protobufs.BLS48581AggregateSignature{
			Bitmask:   SetBitAtIndex(make([]byte, 32), proverIndex),
			Signature: signature,
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: provingKey.Public().([]byte),
			},
		}
	default:
		return nil, errors.Wrap(
			errors.New("unsupported proving key"),
			"prove global frame header",
		)
	}

	return header, nil
}

// GetGlobalFrameSignaturePayload extracts the signature payload from a global
// frame header
func (w *WesolowskiFrameProver) GetGlobalFrameSignaturePayload(
	frame *protobufs.GlobalFrameHeader,
) ([]byte, error) {
	if len(frame.ParentSelector) != 32 {
		return nil, errors.Wrap(
			errors.New("invalid selector"),
			"get global frame signature payload",
		)
	}

	if len(frame.Output) != 516 {
		return nil, errors.Wrap(
			errors.New("invalid output"),
			"get global frame signature payload",
		)
	}

	input := []byte{}
	input = binary.BigEndian.AppendUint64(
		input,
		frame.FrameNumber,
	)
	input = binary.BigEndian.AppendUint64(input, uint64(frame.Timestamp))
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, frame.ParentSelector...)

	for _, commitment := range frame.GlobalCommitments {
		input = append(input, commitment...)
	}

	input = append(input, frame.ProverTreeCommitment...)

	b := sha3.Sum256(input)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	return append(append([]byte{}, b[:]...), proof[:]...), nil
}

func (w *WesolowskiFrameProver) VerifyGlobalFrameHeader(
	frame *protobufs.GlobalFrameHeader,
	bls qcrypto.BlsConstructor,
) ([]uint8, error) {
	if frame.PublicKeySignatureBls48581 == nil ||
		frame.PublicKeySignatureBls48581.PublicKey == nil ||
		len(frame.PublicKeySignatureBls48581.PublicKey.KeyValue) != 585 ||
		len(frame.PublicKeySignatureBls48581.Signature) != 74 {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"verify global frame header",
		)
	}

	if len(frame.GlobalCommitments) != 256 {
		return nil, errors.Wrap(
			errors.New("invalid global commitment length"),
			"verify global frame header",
		)
	} else {
		for _, c := range frame.GlobalCommitments {
			if len(c) != 74 && len(c) != 64 {
				return nil, errors.Wrap(
					errors.Errorf("invalid global commitment length: %d", len(c)),
					"verify global frame header",
				)
			}
		}
	}

	// Validate commitment lengths
	for _, commitment := range frame.GlobalCommitments {
		if len(commitment) != 74 && len(commitment) != 64 {
			return nil, errors.Wrap(
				errors.New("invalid global commitment length"),
				"verify global frame header",
			)
		}
	}

	if len(frame.ProverTreeCommitment) != 74 &&
		len(frame.ProverTreeCommitment) != 64 {
		return nil, errors.Wrap(
			errors.New("invalid prover commitment length"),
			"verify global frame header",
		)
	}

	// Get the signature payload
	signaturePayload, err := w.GetGlobalFrameSignaturePayload(frame)
	if err != nil {
		return nil, errors.Wrap(err, "verify global frame header")
	}

	// Extract the hash and proof from the signature payload
	b := [32]byte{}
	copy(b[:], signaturePayload[:32])
	proof := [516]byte{}
	copy(proof[:], signaturePayload[32:])

	if !WesolowskiVerify(b, frame.Difficulty, proof) {
		return nil, errors.Wrap(
			errors.New("invalid proof"),
			"verify global frame header",
		)
	}

	return GetSetBitIndices(frame.PublicKeySignatureBls48581.Bitmask), nil
}

func (w *WesolowskiFrameProver) VerifyGlobalHeaderSignature(
	frame *protobufs.GlobalFrameHeader,
	bls qcrypto.BlsConstructor,
) (bool, error) {
	// Get the signature payload
	signaturePayload, err := w.GetGlobalFrameSignaturePayload(frame)
	if err != nil {
		return false, errors.Wrap(err, "verify global frame header")
	}

	if !bls.VerifySignatureRaw(
		frame.PublicKeySignatureBls48581.PublicKey.KeyValue,
		frame.PublicKeySignatureBls48581.Signature,
		signaturePayload,
		[]byte("global"),
	) {
		return false, errors.Wrap(
			errors.New("invalid signature"),
			"verify global frame header",
		)
	}

	return true, nil
}

var _ qcrypto.FrameProver = (*WesolowskiFrameProver)(nil)
