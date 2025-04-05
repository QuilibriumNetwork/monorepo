package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
)

type WesolowskiFrameProver struct {
	logger *zap.Logger
}

func NewWesolowskiFrameProver(logger *zap.Logger) *WesolowskiFrameProver {
	return &WesolowskiFrameProver{
		logger,
	}
}

func (w *WesolowskiFrameProver) ProveMasterClockFrame(
	previousFrame *protobufs.ClockFrame,
	timestamp int64,
	difficulty uint32,
	aggregateProofs []*protobufs.InclusionAggregateProof,
) (*protobufs.ClockFrame, error) {
	input := []byte{}
	input = append(input, previousFrame.Filter...)
	input = binary.BigEndian.AppendUint64(input, previousFrame.FrameNumber+1)
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, previousFrame.Output[:]...)

	b := sha3.Sum256(input)
	o := vdf.WesolowskiSolve(b, difficulty)

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove clock frame")
	}

	frame := &protobufs.ClockFrame{
		Filter:          previousFrame.Filter,
		FrameNumber:     previousFrame.FrameNumber + 1,
		Timestamp:       timestamp,
		Difficulty:      difficulty,
		ParentSelector:  parent.FillBytes(make([]byte, 32)),
		Input:           previousFrame.Output,
		AggregateProofs: aggregateProofs,
		Output:          o[:],
	}

	return frame, nil
}

func (w *WesolowskiFrameProver) VerifyMasterClockFrame(
	frame *protobufs.ClockFrame,
) error {
	input := []byte{}
	input = append(input, frame.Filter...)
	input = binary.BigEndian.AppendUint64(input, frame.FrameNumber)
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, frame.Input...)

	if len(frame.Input) < 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if frame.PublicKeySignature != nil {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if len(frame.Input) != 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if len(frame.Output) != 516 {
		return errors.Wrap(
			errors.New("invalid output"),
			"verify clock frame",
		)
	}

	b := sha3.Sum256(input)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	if !vdf.WesolowskiVerify(b, frame.Difficulty, proof) {
		w.logger.Error("invalid proof",
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.Uint32("difficulty", frame.Difficulty),
			zap.Binary("frame_input", frame.Input),
			zap.Binary("frame_output", frame.Output),
		)
		return errors.Wrap(
			errors.New("invalid proof"),
			"verify clock frame",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return errors.Wrap(err, "verify clock frame")
	}

	selector := new(big.Int).SetBytes(frame.ParentSelector)
	if parent.Cmp(selector) != 0 {
		return errors.Wrap(
			errors.New("selector did not match input"),
			"verify clock frame",
		)
	}

	return nil
}

func (w *WesolowskiFrameProver) CreateMasterGenesisFrame(
	filter []byte,
	seed []byte,
	difficulty uint32,
) (
	*protobufs.ClockFrame,
	error,
) {
	b := sha3.Sum256(seed)
	o := vdf.WesolowskiSolve(b, difficulty)
	inputMessage := o[:]

	w.logger.Debug("proving genesis frame")
	input := []byte{}
	input = append(input, filter...)
	input = binary.BigEndian.AppendUint64(input, 0)
	input = binary.BigEndian.AppendUint32(input, difficulty)
	if bytes.Equal(seed, []byte{0x00}) {
		value := [516]byte{}
		input = append(input, value[:]...)
	} else {
		input = append(input, seed...)
	}

	b = sha3.Sum256(input)
	o = vdf.WesolowskiSolve(b, difficulty)

	frame := &protobufs.ClockFrame{
		Filter:      filter,
		FrameNumber: 0,
		Timestamp:   0,
		Difficulty:  difficulty,
		Input:       inputMessage,
		Output:      o[:],
		ParentSelector: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AggregateProofs:    []*protobufs.InclusionAggregateProof{},
		PublicKeySignature: nil,
	}

	return frame, nil
}

func (w *WesolowskiFrameProver) ProveDataClockFrame(
	previousFrame *protobufs.ClockFrame,
	commitments [][]byte,
	aggregateProofs []*protobufs.InclusionAggregateProof,
	provingKey crypto.Signer,
	timestamp int64,
	difficulty uint32,
) (*protobufs.ClockFrame, error) {
	var pubkey []byte
	pubkeyType := keys.KeyTypeEd448
	ed448PublicKey, ok := provingKey.Public().(ed448.PublicKey)
	if ok {
		pubkey = []byte(ed448PublicKey)
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"prove clock frame",
		)
	}

	h, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil, errors.Wrap(
			errors.New("could not hash proving key"),
			"prove clock frame",
		)
	}

	address := h.Bytes()
	input := []byte{}
	input = append(input, previousFrame.Filter...)
	input = binary.BigEndian.AppendUint64(input, previousFrame.FrameNumber+1)
	input = binary.BigEndian.AppendUint64(input, uint64(timestamp))
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, address...)
	input = append(input, previousFrame.Output[:]...)

	commitmentInput := []byte{}
	for _, commitment := range commitments {
		commitmentInput = append(commitmentInput, commitment...)
	}

	input = append(input, commitmentInput...)

	b := sha3.Sum256(input)
	o := vdf.WesolowskiSolve(b, difficulty)

	// TODO: make this configurable for signing algorithms that allow
	// user-supplied hash functions
	signature, err := provingKey.Sign(
		rand.Reader,
		append(append([]byte{}, b[:]...), o[:]...),
		crypto.Hash(0),
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove clock frame")
	}

	frame := &protobufs.ClockFrame{
		Filter:         previousFrame.Filter,
		FrameNumber:    previousFrame.FrameNumber + 1,
		Timestamp:      timestamp,
		Difficulty:     difficulty,
		ParentSelector: parent.FillBytes(make([]byte, 32)),
		Input: append(
			append([]byte{}, previousFrame.Output...),
			commitmentInput...,
		),
		AggregateProofs: aggregateProofs,
		Output:          o[:],
	}

	switch pubkeyType {
	case keys.KeyTypeEd448:
		frame.PublicKeySignature = &protobufs.ClockFrame_PublicKeySignatureEd448{
			PublicKeySignatureEd448: &protobufs.Ed448Signature{
				Signature: signature,
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: pubkey,
				},
			},
		}
	default:
		return nil, errors.Wrap(
			errors.New("unsupported proving key"),
			"prove clock frame",
		)
	}

	return frame, nil
}

func (w *WesolowskiFrameProver) CreateDataGenesisFrame(
	filter []byte,
	origin []byte,
	difficulty uint32,
	inclusionProof *InclusionAggregateProof,
	proverKeys [][]byte,
) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error) {
	frameProverTries := []*tries.RollingFrecencyCritbitTrie{}
	frameProverTrie := &tries.RollingFrecencyCritbitTrie{}
	for i, s := range proverKeys {
		addr, err := poseidon.HashBytes(s)
		if err != nil {
			w.logger.Panic("could not hash proving key", zap.Error(err))
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		frameProverTrie.Add(addrBytes, 0)

		if i%8 == 0 {
			frameProverTries = append(frameProverTries, frameProverTrie)
			frameProverTrie = &tries.RollingFrecencyCritbitTrie{}
		}
	}
	if len(frameProverTrie.FindNearestAndApproximateNeighbors(
		make([]byte, 32),
	)) != 0 {
		frameProverTries = append(frameProverTries, frameProverTrie)
	}

	w.logger.Info("proving genesis frame")
	input := []byte{}
	input = append(input, filter...)
	input = binary.BigEndian.AppendUint64(input, 0)
	input = binary.BigEndian.AppendUint64(input, 0)
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, origin...)
	input = append(input, inclusionProof.AggregateCommitment...)

	b := sha3.Sum256(input)
	o := vdf.WesolowskiSolve(b, difficulty)

	commitments := []*protobufs.InclusionCommitment{}
	for i, commit := range inclusionProof.InclusionCommitments {
		commitments = append(commitments, &protobufs.InclusionCommitment{
			Filter:      filter,
			FrameNumber: 0,
			Position:    uint32(i),
			TypeUrl:     commit.TypeUrl,
			Data:        commit.Data,
			Commitment:  commit.Commitment,
		})
	}

	frame := &protobufs.ClockFrame{
		Filter:      filter,
		FrameNumber: 0,
		Timestamp:   0,
		Difficulty:  difficulty,
		Input: append(
			append([]byte{}, origin...),
			inclusionProof.AggregateCommitment...,
		),
		Output: o[:],
		ParentSelector: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AggregateProofs: []*protobufs.InclusionAggregateProof{
			{
				Filter:               filter,
				FrameNumber:          0,
				InclusionCommitments: commitments,
				Proof:                inclusionProof.Proof,
			},
		},
		PublicKeySignature: nil,
	}

	return frame, frameProverTries, nil
}

func (w *WesolowskiFrameProver) VerifyDataClockFrame(
	frame *protobufs.ClockFrame,
) error {
	var pubkey []byte
	var signature []byte
	pubkeyType := keys.KeyTypeEd448
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
		signature = ed448PublicKey.Signature
	} else {
		return errors.Wrap(
			errors.New("no valid signature provided"),
			"verify clock frame",
		)
	}

	h, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return errors.Wrap(
			errors.New("could not hash proving key"),
			"verify clock frame",
		)
	}

	address := h.Bytes()

	input := []byte{}
	input = append(input, frame.Filter...)
	input = binary.BigEndian.AppendUint64(input, frame.FrameNumber)
	input = binary.BigEndian.AppendUint64(input, uint64(frame.Timestamp))
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, address...)
	input = append(input, frame.Input...)

	if len(frame.Input) < 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if len(frame.Output) != 516 {
		return errors.Wrap(
			errors.New("invalid output"),
			"verify clock frame",
		)
	}

	b := sha3.Sum256(input)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	// TODO: make this configurable for signing algorithms that allow
	// user-supplied hash functions
	switch pubkeyType {
	case keys.KeyTypeEd448:
		if len(pubkey) != 57 || len(signature) != 114 || !ed448.VerifyAny(
			pubkey,
			append(append([]byte{}, b[:]...), frame.Output...),
			signature,
			crypto.Hash(0),
		) {
			return errors.Wrap(
				errors.New("invalid signature for issuer"),
				"verify clock frame",
			)
		}
	}
	if !vdf.WesolowskiVerify(b, frame.Difficulty, proof) {
		return errors.Wrap(
			errors.New("invalid proof"),
			"verify clock frame",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return errors.Wrap(err, "verify clock frame")
	}

	selector := new(big.Int).SetBytes(frame.ParentSelector)
	if parent.Cmp(selector) != 0 {
		return errors.Wrap(
			errors.New("selector did not match input"),
			"verify clock frame",
		)
	}

	return nil
}

func (w *WesolowskiFrameProver) GenerateWeakRecursiveProofIndex(
	frame *protobufs.ClockFrame,
) (uint64, error) {
	hash, err := poseidon.HashBytes(frame.Output)
	if err != nil {
		return 0, errors.Wrap(err, "generate weak recursive proof")
	}

	return hash.Mod(
		hash,
		new(big.Int).SetUint64(frame.FrameNumber),
	).Uint64(), nil
}

func (w *WesolowskiFrameProver) FetchRecursiveProof(
	frame *protobufs.ClockFrame,
) []byte {
	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil
	}

	h, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil
	}

	address := h.Bytes()
	input := []byte{}
	input = append(input, frame.Filter...)
	input = binary.BigEndian.AppendUint64(input, frame.FrameNumber)
	input = binary.BigEndian.AppendUint64(input, uint64(frame.Timestamp))
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, address...)
	input = append(input, frame.Input...)
	input = append(input, frame.Output...)

	return input
}

func (w *WesolowskiFrameProver) VerifyWeakRecursiveProof(
	frame *protobufs.ClockFrame,
	proof []byte,
	deepVerifier *protobufs.ClockFrame,
) bool {
	hash, err := poseidon.HashBytes(frame.Output)
	if err != nil {
		w.logger.Debug("could not hash output")
		return false
	}

	frameNumber := hash.Mod(
		hash,
		new(big.Int).SetUint64(frame.FrameNumber),
	).Uint64()

	if len(proof) < 1084 {
		w.logger.Debug("invalid proof size")
		return false
	}

	filter := proof[:len(frame.Filter)]
	check := binary.BigEndian.Uint64(
		proof[len(frame.Filter) : len(frame.Filter)+8],
	)
	timestamp := binary.BigEndian.Uint64(
		proof[len(frame.Filter)+8 : len(frame.Filter)+16],
	)
	difficulty := binary.BigEndian.Uint32(
		proof[len(frame.Filter)+16 : len(frame.Filter)+20],
	)
	input := proof[len(frame.Filter)+52:]

	if check != frameNumber ||
		!bytes.Equal(filter, frame.Filter) ||
		int64(timestamp) >= frame.Timestamp ||
		difficulty > frame.Difficulty ||
		len(input) < 1032 {
		w.logger.Debug(
			"check failed",
			zap.Bool("failed_frame_number", check != frameNumber),
			zap.Bool("failed_filter", !bytes.Equal(filter, frame.Filter)),
			zap.Bool("failed_timestamp", int64(timestamp) >= frame.Timestamp),
			zap.Bool("failed_difficulty", difficulty > frame.Difficulty),
			zap.Bool("failed_input_size", len(input) < 1032),
		)
		return false
	}

	if deepVerifier != nil && (check != deepVerifier.FrameNumber ||
		!bytes.Equal(filter, deepVerifier.Filter) ||
		int64(timestamp) != deepVerifier.Timestamp ||
		difficulty != deepVerifier.Difficulty ||
		!bytes.Equal(input[:len(input)-516], deepVerifier.Input)) {
		return false
	}

	b := sha3.Sum256(input[:len(input)-516])
	output := [516]byte{}
	copy(output[:], input[len(input)-516:])

	if vdf.WesolowskiVerify(b, difficulty, output) {
		w.logger.Debug("verification succeeded")
		return true
	} else {
		w.logger.Debug("verification failed")
		return false
	}
}

func (w *WesolowskiFrameProver) CalculateChallengeProofDifficulty(
	increment uint32,
) uint32 {
	if increment >= 700000 {
		return 25000
	}

	return 200000 - (increment / 4)
}

func (w *WesolowskiFrameProver) CalculateChallengeProof(
	challenge []byte,
	difficulty uint32,
) ([]byte, error) {
	b := sha3.Sum256(challenge)
	o := vdf.WesolowskiSolve(b, uint32(difficulty))

	output := make([]byte, 516)
	copy(output[:], o[:])

	return output, nil
}

func (w *WesolowskiFrameProver) VerifyChallengeProof(
	challenge []byte,
	difficulty uint32,
	proof []byte,
) bool {
	if len(proof) != 516 {
		return false
	}

	b := sha3.Sum256(challenge)

	check := vdf.WesolowskiVerify(b, difficulty, [516]byte(proof))
	return check
}

func (w *WesolowskiFrameProver) VerifyPreDuskChallengeProof(
	challenge []byte,
	increment uint32,
	core uint32,
	proof []byte,
) bool {
	difficulty := w.CalculateChallengeProofDifficulty(increment)

	if len(proof) != 516 {
		return false
	}

	instanceInput := binary.BigEndian.AppendUint32([]byte{}, core)
	instanceInput = append(instanceInput, challenge...)
	b := sha3.Sum256(instanceInput)

	check := vdf.WesolowskiVerify(b, difficulty, [516]byte(proof))
	return check
}
