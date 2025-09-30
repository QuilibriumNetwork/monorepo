package token

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

// ToBytes serializes a PendingTransaction to bytes using protobuf
func (tx *PendingTransaction) ToBytes() ([]byte, error) {
	// Convert to protobuf
	pb := tx.ToProtobuf()

	// Serialize using protobuf
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a PendingTransaction from bytes using protobuf
func (tx *PendingTransaction) FromBytes(
	data []byte,
	config *TokenIntrinsicConfiguration,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyRing keys.KeyRing,
	rdfHypergraphSchema string,
	rdfMultiprover *schema.RDFMultiprover,
) error {
	// Deserialize using protobuf
	pb := &protobufs.PendingTransaction{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Convert from protobuf
	converted, err := PendingTransactionFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy converted fields
	*tx = *converted

	tx.rdfHypergraphSchema = rdfHypergraphSchema

	// Convert TraversalProof from protobuf if present
	if pb.TraversalProof != nil {
		tp, err := TraversalProofFromProtobuf(pb.TraversalProof, inclusionProver)
		if err != nil {
			return errors.Wrap(err, "deserializing traversal proof")
		}
		tx.TraversalProof = tp

		if tx.TraversalProof != nil && len(tx.TraversalProof.SubProofs) == 0 {
			return errors.Wrap(errors.New("invalid payload"), "from bytes")
		}
	}

	// Set injected values
	tx.hypergraph = hypergraph
	tx.bulletproofProver = bulletproofProver
	tx.inclusionProver = inclusionProver
	tx.verEnc = verEnc
	tx.decafConstructor = decafConstructor
	tx.keyRing = keyRing
	tx.config = config
	tx.rdfMultiprover = rdfMultiprover

	return nil
}

// ToBytes serializes a Transaction to bytes using protobuf
func (tx *Transaction) ToBytes() ([]byte, error) {
	// Convert to protobuf (ToProtobuf already handles TraversalProof)
	pb := tx.ToProtobuf()

	// Serialize using protobuf
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a Transaction from bytes using protobuf
func (tx *Transaction) FromBytes(
	data []byte,
	config *TokenIntrinsicConfiguration,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyRing keys.KeyRing,
	rdfHypergraphSchema string,
	rdfMultiprover *schema.RDFMultiprover,
) error {
	// Deserialize using protobuf
	pb := &protobufs.Transaction{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Convert from protobuf
	converted, err := TransactionFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy converted fields
	*tx = *converted

	// Load intrinsic for RDF schema
	tx.rdfHypergraphSchema = rdfHypergraphSchema

	// Convert TraversalProof from protobuf if present
	if pb.TraversalProof != nil {
		tp, err := TraversalProofFromProtobuf(pb.TraversalProof, inclusionProver)
		if err != nil {
			return errors.Wrap(err, "deserializing traversal proof")
		}
		tx.TraversalProof = tp
	}

	// Set injected values
	tx.hypergraph = hypergraph
	tx.bulletproofProver = bulletproofProver
	tx.inclusionProver = inclusionProver
	tx.verEnc = verEnc
	tx.decafConstructor = decafConstructor
	tx.keyRing = keyRing
	tx.config = config
	tx.rdfMultiprover = rdfMultiprover

	return nil
}

// ToBytes serializes a MintTransaction to bytes using protobuf
func (tx *MintTransaction) ToBytes() ([]byte, error) {
	// Convert to protobuf
	pb := tx.ToProtobuf()

	// Serialize using protobuf
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a MintTransaction from bytes using protobuf
func (tx *MintTransaction) FromBytes(
	data []byte,
	config *TokenIntrinsicConfiguration,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyRing keys.KeyRing,
	rdfHypergraphSchema string,
	rdfMultiprover *schema.RDFMultiprover,
) error {
	// Deserialize using protobuf
	pb := &protobufs.MintTransaction{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Convert from protobuf
	converted, err := MintTransactionFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy converted fields
	*tx = *converted

	tx.rdfHypergraphSchema = rdfHypergraphSchema

	// Set injected values
	tx.hypergraph = hypergraph
	tx.bulletproofProver = bulletproofProver
	tx.inclusionProver = inclusionProver
	tx.verEnc = verEnc
	tx.decafConstructor = decafConstructor
	tx.keyRing = keyRing
	tx.config = config
	tx.rdfMultiprover = rdfMultiprover

	return nil
}
