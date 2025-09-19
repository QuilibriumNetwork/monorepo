package hypergraph

import (
	"encoding/binary"
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// EncryptedToVertexTree converts a slice of encrypted data into a
// VectorCommitmentTree. Each encrypted element is inserted with a sequential
// index as its key.
func EncryptedToVertexTree(
	prover crypto.InclusionProver,
	encrypted []Encrypted,
) *tries.VectorCommitmentTree {
	dataTree := &tries.VectorCommitmentTree{}
	for i, d := range encrypted {
		dataBytes := d.ToBytes()
		id := binary.BigEndian.AppendUint64([]byte{}, uint64(i))
		dataTree.Insert(
			id,
			dataBytes,
			d.GetStatement(),
			big.NewInt(55),
		)
	}
	dataTree.Commit(prover, false)
	return dataTree
}

// VertexTreeToEncrypted extracts encrypted data from a VectorCommitmentTree.
// It reads sequential indices until no more data is found.
func VertexTreeToEncrypted(
	verEnc crypto.VerifiableEncryptor,
	tree *tries.VectorCommitmentTree,
) []Encrypted {
	outs := []Encrypted{}
	index := uint64(0)

	for {
		id := binary.BigEndian.AppendUint64([]byte{}, index)
		dataBytes, err := tree.Get(id)
		if err != nil {
			break
		}

		outs = append(outs, verEnc.FromBytes(dataBytes))
		index++
	}

	return outs
}
