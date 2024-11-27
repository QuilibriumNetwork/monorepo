package tries

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"github.com/pkg/errors"
	mt "github.com/txaty/go-merkletree"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type ProofLeaf struct {
	output []byte
}

var _ mt.DataBlock = (*ProofLeaf)(nil)

func NewProofLeaf(output []byte) *ProofLeaf {
	return &ProofLeaf{output}
}

func (p *ProofLeaf) Serialize() ([]byte, error) {
	return p.output, nil
}

func PackOutputIntoPayloadAndProof(
	outputs []mt.DataBlock,
	modulo int,
	frame *protobufs.ClockFrame,
	previousTree *mt.MerkleTree,
) (*mt.MerkleTree, [][]byte, error) {
	if modulo != len(outputs) {
		return nil, nil, errors.Wrap(
			errors.New("mismatch of outputs and prover size"),
			"pack output into payload and proof",
		)
	}
	tree, err := mt.New(
		&mt.Config{
			HashFunc: func(data []byte) ([]byte, error) {
				hash := sha3.Sum256(data)
				return hash[:], nil
			},
			Mode:               mt.ModeProofGen,
			DisableLeafHashing: true,
		},
		outputs,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "pack output into payload and proof")
	}

	output := [][]byte{
		tree.Root,
		binary.BigEndian.AppendUint32([]byte{}, uint32(modulo)),
		binary.BigEndian.AppendUint64([]byte{}, frame.FrameNumber),
	}

	if previousTree != nil {
		hash := sha3.Sum256(frame.Output)
		pick := BytesToUnbiasedMod(hash, uint64(modulo))
		if uint64(modulo) < pick {
			return nil, nil, errors.Wrap(
				errors.New("proof size mismatch"),
				"pack output into payload and proof",
			)
		}
		for _, sib := range previousTree.Proofs[int(pick)].Siblings {
			output = append(output, sib)
		}
		output = append(
			output,
			binary.BigEndian.AppendUint32(
				[]byte{},
				previousTree.Proofs[int(pick)].Path,
			),
		)
		output = append(output, previousTree.Leaves[int(pick)])
	}
	return tree, output, nil
}

func UnpackAndVerifyOutput(
	previousRoot []byte,
	output [][]byte,
) (treeRoot []byte, modulo uint32, frameNumber uint64, verified bool, err error) {
	if len(output) < 3 {
		return nil, 0, 0, false, errors.Wrap(
			fmt.Errorf("output too short, expected at least 3 elements"),
			"unpack and verify output",
		)
	}

	treeRoot = output[0]
	modulo = binary.BigEndian.Uint32(output[1])
	frameNumber = binary.BigEndian.Uint64(output[2])

	payload := []byte("mint")
	payload = append(payload, treeRoot...)
	payload = binary.BigEndian.AppendUint32(payload, modulo)
	payload = binary.BigEndian.AppendUint64(payload, frameNumber)

	if len(output) > 3 {
		numSiblings := bits.Len64(uint64(modulo) - 1)
		if len(output) != 5+numSiblings {
			return nil, 0, 0, false, errors.Wrap(
				fmt.Errorf("invalid number of proof elements"),
				"unpack and verify output",
			)
		}

		siblings := output[3 : 3+numSiblings]
		for _, sib := range siblings {
			payload = append(payload, sib...)
		}

		pathBytes := output[3+numSiblings]
		path := binary.BigEndian.Uint32(pathBytes)
		payload = binary.BigEndian.AppendUint32(payload, path)

		leaf := output[len(output)-1]
		payload = append(payload, leaf...)

		verified, err = mt.Verify(
			NewProofLeaf(leaf),
			&mt.Proof{
				Siblings: siblings,
				Path:     path,
			},
			previousRoot,
			&mt.Config{
				HashFunc: func(data []byte) ([]byte, error) {
					hash := sha3.Sum256(data)
					return hash[:], nil
				},
				Mode:               mt.ModeProofGen,
				DisableLeafHashing: true,
			},
		)
		if err != nil {
			return nil, 0, 0, false, errors.Wrap(err, "unpack and verify output")
		}
	} else {
		verified = true
	}

	return treeRoot, modulo, frameNumber, verified, nil
}

func BytesToUnbiasedMod(input [32]byte, modulus uint64) uint64 {
	if modulus <= 1 {
		return 0
	}

	hashValue := binary.BigEndian.Uint64(input[:8])

	maxValid := math.MaxUint64 - (math.MaxUint64 % modulus)

	result := hashValue
	for result > maxValid {
		offset := uint64(8)
		for result > maxValid && offset <= 24 {
			nextBytes := binary.BigEndian.Uint64(input[offset : offset+8])
			result = (result * 31) ^ nextBytes
			offset += 8
		}

		if result > maxValid {
			result = (result * 31) ^ (result >> 32)
		}
	}

	return result % modulus
}
