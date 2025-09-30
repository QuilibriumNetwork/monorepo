package token

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// ToBytes serializes a RecipientBundle to bytes using protobuf
func (rb *RecipientBundle) ToBytes() ([]byte, error) {
	// No validation here - let protobuf handle it
	pb := rb.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a RecipientBundle from bytes using protobuf
func (rb *RecipientBundle) FromBytes(data []byte) error {
	pb := &protobufs.RecipientBundle{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := RecipientBundleFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*rb = *converted

	return nil
}

// ToBytes serializes a TransactionOutput to bytes using protobuf
func (o *TransactionOutput) ToBytes() ([]byte, error) {
	pb := o.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a TransactionOutput from bytes using protobuf
func (o *TransactionOutput) FromBytes(data []byte) error {
	pb := &protobufs.TransactionOutput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := TransactionOutputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*o = *converted

	return nil
}

// ToBytes serializes a TransactionInput to bytes using protobuf
func (i *TransactionInput) ToBytes() ([]byte, error) {
	pb := i.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a TransactionInput from bytes using protobuf
func (i *TransactionInput) FromBytes(data []byte) error {
	pb := &protobufs.TransactionInput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := TransactionInputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*i = *converted

	return nil
}

// ToBytes serializes a PendingTransactionInput to bytes using protobuf
func (i *PendingTransactionInput) ToBytes() ([]byte, error) {
	pb := i.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a PendingTransactionInput from bytes using protobuf
func (i *PendingTransactionInput) FromBytes(data []byte) error {
	pb := &protobufs.PendingTransactionInput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := PendingTransactionInputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*i = *converted

	return nil
}

// ToBytes serializes a PendingTransactionOutput to bytes using protobuf
func (o *PendingTransactionOutput) ToBytes() ([]byte, error) {
	pb := o.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a PendingTransactionOutput from bytes using protobuf
func (o *PendingTransactionOutput) FromBytes(data []byte) error {
	pb := &protobufs.PendingTransactionOutput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := PendingTransactionOutputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*o = *converted

	return nil
}

// ToBytes serializes a MintTransactionInput to bytes using protobuf
func (i *MintTransactionInput) ToBytes() ([]byte, error) {
	pb := i.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a MintTransactionInput from bytes using protobuf
func (i *MintTransactionInput) FromBytes(data []byte) error {
	pb := &protobufs.MintTransactionInput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := MintTransactionInputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*i = *converted

	return nil
}

// ToBytes serializes a MintTransactionOutput to bytes using protobuf
func (o *MintTransactionOutput) ToBytes() ([]byte, error) {
	pb := o.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a MintTransactionOutput from bytes using protobuf
func (o *MintTransactionOutput) FromBytes(data []byte) error {
	pb := &protobufs.MintTransactionOutput{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := MintTransactionOutputFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*o = *converted

	return nil
}
