package protobufs

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
)

type BlsVerifier interface {
	VerifySignatureRaw(
		publicKeyG2 []byte,
		signatureG1 []byte,
		message []byte,
		context []byte,
	) bool
}

type SchnorrVerifier interface {
	SimpleVerify(
		message []byte,
		signature []byte,
		point []byte,
	) bool
}

func (s *Ed448Signature) Verify(msg, context []byte) error {
	if s.PublicKey == nil {
		return errors.Wrap(errors.New("public key nil"), "verify")
	}

	if s.Signature == nil {
		return errors.Wrap(errors.New("signature nil"), "verify")
	}

	if len(s.PublicKey.KeyValue) != 57 {
		return errors.Wrap(
			errors.New("invalid length for public key"),
			"verify",
		)
	}

	if len(s.Signature) != 114 {
		return errors.Wrap(errors.New("invalid length for signature"), "verify")
	}

	return s.verifyUnsafe(msg, context)
}

// verifyUnsafe is used to verify a signature without checking the length of the
// public key and signature.
func (s *Ed448Signature) verifyUnsafe(msg, context []byte) error {
	if !ed448.Verify(s.PublicKey.KeyValue, msg, s.Signature, string(context)) {
		return errors.Wrap(
			errors.New("invalid signature for public key"),
			"verify",
		)
	}

	return nil
}

// Validation methods for key types

func (s *SignedX448Key) Validate() error {
	if s == nil {
		return errors.New("nil signed x448 key")
	}

	// Check key exists and has valid length
	if s.Key == nil {
		return errors.Wrap(
			errors.New("nil x448 key"),
			"validate",
		)
	}
	if len(s.Key.KeyValue) != 57 {
		return errors.Wrap(
			errors.New("invalid x448 key length"),
			"validate",
		)
	}

	// Parent key address should be 32 bytes
	if len(s.ParentKeyAddress) != 32 {
		return errors.Wrap(
			errors.New("invalid parent key address length"),
			"validate",
		)
	}

	// Must have a signature
	switch sig := s.Signature.(type) {
	case *SignedX448Key_Ed448Signature:
		if sig.Ed448Signature == nil {
			return errors.Wrap(
				errors.New("nil ed448 signature"),
				"validate",
			)
		}
		// Ed448Signature has its own Validate method
		if err := sig.Ed448Signature.Validate(); err != nil {
			return errors.Wrap(
				errors.Wrap(err, "ed448 signature"),
				"validate",
			)
		}
	case *SignedX448Key_BlsSignature:
		if sig.BlsSignature == nil {
			return errors.Wrap(
				errors.New("nil bls signature"),
				"validate",
			)
		}
		// BLS48581Signature validation
		if len(sig.BlsSignature.Signature) != 74 {
			return errors.Wrap(
				errors.New("invalid bls signature length"),
				"validate",
			)
		}
		if sig.BlsSignature.PublicKey != nil &&
			len(sig.BlsSignature.PublicKey.KeyValue) != 585 {
			return errors.Wrap(
				errors.New("invalid bls public key length"),
				"validate",
			)
		}
	case *SignedX448Key_DecafSignature:
		if sig.DecafSignature == nil {
			return errors.Wrap(
				errors.New("nil decaf signature"),
				"validate",
			)
		}
		// Decaf448Signature validation
		if len(sig.DecafSignature.Signature) != 112 {
			return errors.Wrap(
				errors.New("invalid decaf signature length"),
				"validate",
			)
		}
		if sig.DecafSignature.PublicKey != nil &&
			len(sig.DecafSignature.PublicKey.KeyValue) != 56 {
			return errors.Wrap(
				errors.New("invalid decaf public key length"),
				"validate",
			)
		}
	case nil:
		return errors.Wrap(
			errors.New("no signature specified"),
			"validate",
		)
	default:
		return errors.Wrap(
			errors.New("unknown signature type"),
			"validate",
		)
	}

	return nil
}

func (k *KeyCollection) Validate() error {
	if k == nil {
		return errors.Wrap(errors.New("nil key collection"), "validate")
	}

	// KeyPurpose should not be empty
	if k.KeyPurpose == "" {
		return errors.Wrap(errors.New("empty key purpose"), "validate")
	}

	// Validate all keys
	for i, key := range k.Keys {
		if err := key.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "key %d", i), "validate")
		}
	}

	return nil
}

func (k *KeyRegistry) Validate() error {
	if k == nil {
		return errors.Wrap(
			errors.New("nil key registry"),
			"validate",
		)
	}

	// Validate keys by purpose map
	for purpose, collection := range k.KeysByPurpose {
		if err := collection.Validate(); err != nil {
			return errors.Wrap(
				errors.Wrapf(err, "collection %s", purpose),
				"validate",
			)
		}
	}

	return nil
}

func (s *BLS48581AggregateSignature) Identity() string {
	return string(s.GetPublicKey().GetKeyValue())
}

func (s *BLS48581Signature) Verify(
	msg, context []byte,
	blsVerifier BlsVerifier,
) error {
	if s.PublicKey == nil {
		return errors.Wrap(errors.New("public key nil"), "verify")
	}

	if s.Signature == nil {
		return errors.Wrap(errors.New("signature nil"), "verify")
	}

	if len(s.PublicKey.KeyValue) != 585 {
		return errors.Wrap(
			errors.New("invalid length for public key"),
			"verify",
		)
	}

	if len(s.Signature) != 74 {
		return errors.Wrap(errors.New("invalid length for signature"), "verify")
	}

	if !blsVerifier.VerifySignatureRaw(
		s.PublicKey.KeyValue,
		s.Signature,
		msg,
		context,
	) {
		return errors.Wrap(
			errors.New("invalid signature for public key"),
			"verify",
		)
	}

	return nil
}

func (s *Decaf448Signature) Verify(
	msg, context []byte,
	schnorrVerifier SchnorrVerifier,
) error {
	if s.PublicKey == nil {
		return errors.Wrap(errors.New("public key nil"), "verify")
	}

	if s.Signature == nil {
		return errors.Wrap(errors.New("signature nil"), "verify")
	}

	if len(s.PublicKey.KeyValue) != 56 {
		return errors.Wrap(
			errors.New("invalid length for public key"),
			"verify",
		)
	}

	if len(s.Signature) != 112 {
		return errors.Wrap(errors.New("invalid length for signature"), "verify")
	}

	contextWithMessage := slices.Concat(context, msg)

	if !schnorrVerifier.SimpleVerify(
		contextWithMessage,
		s.Signature,
		s.PublicKey.KeyValue,
	) {
		return errors.Wrap(
			errors.New("invalid signature for public key"),
			"verify",
		)
	}

	return nil
}

func (s *SignedX448Key) Verify(
	context []byte,
	blsVerifier BlsVerifier,
	schnorrVerifier SchnorrVerifier,
) error {
	if s == nil {
		return errors.Wrap(errors.New("nil signed x448 key"), "verify")
	}

	if s.Key == nil {
		return errors.Wrap(errors.New("key nil"), "verify")
	}

	if len(s.Key.KeyValue) != 57 {
		return errors.Wrap(errors.New("invalid length for key"), "verify")
	}

	if len(s.ParentKeyAddress) == 0 {
		return errors.Wrap(errors.New("parent key address required"), "verify")
	}

	// Verify signature and check that parent key address matches
	switch sig := s.Signature.(type) {
	case *SignedX448Key_Ed448Signature:
		if sig.Ed448Signature == nil || sig.Ed448Signature.PublicKey == nil {
			return errors.Wrap(
				errors.New("ed448 signature or public key nil"),
				"verify",
			)
		}

		// Verify the signature
		if err := sig.Ed448Signature.Verify(s.Key.KeyValue, context); err != nil {
			return errors.Wrap(err, "verify signature")
		}

		// Check that parent key address matches the public key
		addrBI, err := poseidon.HashBytes(sig.Ed448Signature.PublicKey.KeyValue)
		if err != nil {
			return errors.Wrap(err, "compute address from public key")
		}
		addressToCheck := addrBI.FillBytes(make([]byte, 32))
		if !bytes.Equal(addressToCheck, s.ParentKeyAddress) {
			return errors.Wrap(
				errors.New("parent key address does not match public key"),
				"verify",
			)
		}

	case *SignedX448Key_BlsSignature:
		if sig.BlsSignature == nil || sig.BlsSignature.PublicKey == nil {
			return errors.Wrap(
				errors.New("bls signature or public key nil"),
				"verify",
			)
		}

		// Verify the signature
		if err := sig.BlsSignature.Verify(
			s.Key.KeyValue,
			context,
			blsVerifier,
		); err != nil {
			return errors.Wrap(err, "verify")
		}

		// Check that parent key address matches the public key
		addrBI, err := poseidon.HashBytes(sig.BlsSignature.PublicKey.KeyValue)
		if err != nil {
			return errors.Wrap(err, "verify")
		}
		addressToCheck := addrBI.FillBytes(make([]byte, 32))
		if !bytes.Equal(addressToCheck, s.ParentKeyAddress) {
			return errors.Wrap(
				errors.New("parent key address does not match public key"),
				"verify",
			)
		}

	case *SignedX448Key_DecafSignature:
		if sig.DecafSignature == nil || sig.DecafSignature.PublicKey == nil {
			return errors.Wrap(
				errors.New("decaf signature or public key nil"),
				"verify",
			)
		}

		// Verify the signature
		if err := sig.DecafSignature.Verify(
			s.Key.KeyValue,
			context,
			schnorrVerifier,
		); err != nil {
			return errors.Wrap(err, "verify")
		}

		// Check that parent key address matches the public key
		addrBI, err := poseidon.HashBytes(sig.DecafSignature.PublicKey.KeyValue)
		if err != nil {
			return errors.Wrap(err, "verify")
		}
		addressToCheck := addrBI.FillBytes(make([]byte, 32))
		if !bytes.Equal(addressToCheck, s.ParentKeyAddress) {
			return errors.Wrap(
				errors.New("parent key address does not match public key"),
				"verify",
			)
		}

	case nil:
		return errors.Wrap(errors.New("no signature"), "verify")
	default:
		return errors.Wrap(errors.New("unknown signature type"), "verify")
	}

	return nil
}

// ToCanonicalBytes serializes an Ed448PublicKey to canonical bytes
func (e *Ed448PublicKey) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		Ed448PublicKeyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_value (fixed 57 bytes for Ed448)
	if len(e.KeyValue) != 57 {
		return nil, errors.Wrap(
			errors.New("invalid ed448 public key length"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(e.KeyValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes an Ed448PublicKey from canonical bytes
func (e *Ed448PublicKey) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != Ed448PublicKeyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_value (fixed 57 bytes)
	e.KeyValue = make([]byte, 57)
	if _, err := buf.Read(e.KeyValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes an Ed448Signature to canonical bytes
func (e *Ed448Signature) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		Ed448SignatureType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key
	if e.PublicKey != nil {
		keyBytes, err := e.PublicKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write signature (fixed 114 bytes for Ed448)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes an Ed448Signature from canonical bytes
func (e *Ed448Signature) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != Ed448SignatureType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen > 0 {
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.PublicKey = &Ed448PublicKey{}
		if err := e.PublicKey.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Signature = make([]byte, sigLen)
	if _, err := buf.Read(e.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a BLS48581G2PublicKey to canonical bytes
func (b *BLS48581G2PublicKey) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		BLS48581G2PublicKeyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_value (fixed 585 bytes for BLS48-581 G2)
	if len(b.KeyValue) != 585 {
		return nil, errors.Wrap(
			errors.New("invalid bls48-581 g2 public key length"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(b.KeyValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a BLS48581G2PublicKey from canonical bytes
func (b *BLS48581G2PublicKey) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != BLS48581G2PublicKeyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_value (fixed 585 bytes)
	b.KeyValue = make([]byte, 585)
	if _, err := buf.Read(b.KeyValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a BLS48581Signature to canonical bytes
func (b *BLS48581Signature) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		BLS48581SignatureType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key
	if b.PublicKey != nil {
		keyBytes, err := b.PublicKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write signature (fixed 74 bytes for BLS48-581)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a BLS48581Signature from canonical bytes
func (b *BLS48581Signature) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != BLS48581SignatureType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen > 0 {
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		b.PublicKey = &BLS48581G2PublicKey{}
		if err := b.PublicKey.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Signature = make([]byte, sigLen)
	if _, err := buf.Read(b.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a BLS48581SignatureWithProofOfPossession to
// canonical bytes
func (b *BLS48581SignatureWithProofOfPossession) ToCanonicalBytes() (
	[]byte,
	error,
) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		BLS48581SignatureWithProofOfPossessionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public key
	if b.PublicKey != nil {
		pubKeyBytes, err := b.PublicKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(pubKeyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(pubKeyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write pop_signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.PopSignature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.PopSignature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a BLS48581SignatureWithProofOfPossession from
// canonical bytes
func (b *BLS48581SignatureWithProofOfPossession) FromCanonicalBytes(
	data []byte,
) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != BLS48581SignatureWithProofOfPossessionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Signature = make([]byte, sigLen)
	if _, err := buf.Read(b.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public key
	var pubKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if pubKeyLen > 0 {
		pubKeyBytes := make([]byte, pubKeyLen)
		if _, err := buf.Read(pubKeyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		b.PublicKey = &BLS48581G2PublicKey{}
		if err := b.PublicKey.FromCanonicalBytes(pubKeyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read pop_signature
	var popSigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &popSigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.PopSignature = make([]byte, popSigLen)
	if _, err := buf.Read(b.PopSignature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a BLS48581AddressedSignature to canonical bytes
func (b *BLS48581AddressedSignature) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		BLS48581AddressedSignatureType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a BLS48581AddressedSignature from canonical
// bytes
func (b *BLS48581AddressedSignature) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != BLS48581AddressedSignatureType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Signature = make([]byte, sigLen)
	if _, err := buf.Read(b.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read address
	var addrLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Address = make([]byte, addrLen)
	if _, err := buf.Read(b.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a BLS48581AggregateSignature to canonical bytes
func (b *BLS48581AggregateSignature) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		BLS48581AggregateSignatureType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public key
	if b.PublicKey != nil {
		pubKeyBytes, err := b.PublicKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(pubKeyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(pubKeyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write bitmask
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(b.Bitmask)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(b.Bitmask); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a BLS48581AggregateSignature from canonical
// bytes
func (b *BLS48581AggregateSignature) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != BLS48581AggregateSignatureType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Signature = make([]byte, sigLen)
	if _, err := buf.Read(b.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public key
	var pubKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if pubKeyLen > 0 {
		pubKeyBytes := make([]byte, pubKeyLen)
		if _, err := buf.Read(pubKeyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		b.PublicKey = &BLS48581G2PublicKey{}
		if err := b.PublicKey.FromCanonicalBytes(pubKeyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read bitmask
	var bitmaskLen uint32
	if err := binary.Read(buf, binary.BigEndian, &bitmaskLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	b.Bitmask = make([]byte, bitmaskLen)
	if _, err := buf.Read(b.Bitmask); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a X448PublicKey to canonical bytes
func (d *X448PublicKey) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		X448PublicKeyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_value (fixed 57 bytes for X448)
	if len(d.KeyValue) != 57 {
		return nil, errors.Wrap(
			errors.New("invalid x448 public key length"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(d.KeyValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a X448PublicKey from canonical bytes
func (d *X448PublicKey) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != X448PublicKeyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_value (fixed 57 bytes)
	d.KeyValue = make([]byte, 57)
	if _, err := buf.Read(d.KeyValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a Decaf448PublicKey to canonical bytes
func (d *Decaf448PublicKey) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		Decaf448PublicKeyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_value (fixed 56 bytes for Decaf448)
	if len(d.KeyValue) != 56 {
		return nil, errors.Wrap(
			errors.New("invalid decaf448 public key length"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(d.KeyValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a Decaf448PublicKey from canonical bytes
func (d *Decaf448PublicKey) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != Decaf448PublicKeyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_value (fixed 56 bytes)
	d.KeyValue = make([]byte, 56)
	if _, err := buf.Read(d.KeyValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a Decaf448Signature to canonical bytes
func (d *Decaf448Signature) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		Decaf448SignatureType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key
	if d.PublicKey != nil {
		keyBytes, err := d.PublicKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write signature (fixed 112 bytes for Decaf448 Schnorr)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(d.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(d.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a Decaf448Signature from canonical bytes
func (d *Decaf448Signature) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != Decaf448SignatureType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen > 0 {
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		d.PublicKey = &Decaf448PublicKey{}
		if err := d.PublicKey.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	d.Signature = make([]byte, sigLen)
	if _, err := buf.Read(d.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// ToCanonicalBytes serializes a SignedX448Key to canonical bytes
func (s *SignedX448Key) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		SignedX448KeyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key
	if s.Key != nil {
		keyBytes, err := s.Key.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write parent_key_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ParentKeyAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.ParentKeyAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature type and data
	switch sig := s.Signature.(type) {
	case *SignedX448Key_Ed448Signature:
		// Type 1 for Ed448 signature
		if err := binary.Write(buf, binary.BigEndian, uint8(1)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		sigBytes, err := sig.Ed448Signature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	case *SignedX448Key_BlsSignature:
		// Type 2 for BLS signature
		if err := binary.Write(buf, binary.BigEndian, uint8(2)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		sigBytes, err := sig.BlsSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	case *SignedX448Key_DecafSignature:
		// Type 3 for Decaf signature
		if err := binary.Write(buf, binary.BigEndian, uint8(3)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		sigBytes, err := sig.DecafSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	default:
		// Type 0 for nil
		if err := binary.Write(buf, binary.BigEndian, uint8(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write created_at
	if err := binary.Write(buf, binary.BigEndian, s.CreatedAt); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write expires_at
	if err := binary.Write(buf, binary.BigEndian, s.ExpiresAt); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_purpose
	purposeBytes := []byte(s.KeyPurpose)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(purposeBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(purposeBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a SignedX448Key from canonical bytes
func (s *SignedX448Key) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != SignedX448KeyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if keyLen > 0 {
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		s.Key = &X448PublicKey{}
		if err := s.Key.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read parent_key_address
	var parentKeyAddressLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&parentKeyAddressLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.ParentKeyAddress = make([]byte, parentKeyAddressLen)
	if _, err := buf.Read(s.ParentKeyAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature type
	var sigType uint8
	if err := binary.Read(buf, binary.BigEndian, &sigType); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature data based on type
	if sigType > 0 {
		var sigLen uint32
		if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		switch sigType {
		case 1:
			ed448Sig := &Ed448Signature{}
			if err := ed448Sig.FromCanonicalBytes(sigBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			s.Signature = &SignedX448Key_Ed448Signature{
				Ed448Signature: ed448Sig,
			}
		case 2:
			blsSig := &BLS48581Signature{}
			if err := blsSig.FromCanonicalBytes(sigBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			s.Signature = &SignedX448Key_BlsSignature{BlsSignature: blsSig}
		case 3:
			decafSig := &Decaf448Signature{}
			if err := decafSig.FromCanonicalBytes(sigBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			s.Signature = &SignedX448Key_DecafSignature{DecafSignature: decafSig}
		}
	}

	// Read created_at
	if err := binary.Read(buf, binary.BigEndian, &s.CreatedAt); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read expires_at
	if err := binary.Read(buf, binary.BigEndian, &s.ExpiresAt); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read key_purpose
	var purposeLen uint32
	if err := binary.Read(buf, binary.BigEndian, &purposeLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	purposeBytes := make([]byte, purposeLen)
	if _, err := buf.Read(purposeBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.KeyPurpose = string(purposeBytes)

	return nil
}

// Validate checks that all fields have valid lengths
func (e *Ed448PrivateKey) Validate() error {
	if e == nil {
		return errors.Wrap(errors.New("ed448 private key is nil"), "validate")
	}

	// KeyValue should be 57 bytes
	if len(e.KeyValue) > 0 && len(e.KeyValue) != 57 {
		return errors.Wrap(
			errors.Errorf(
				"ed448 private key must be 57 bytes, got %d",
				len(e.KeyValue),
			),
			"validate",
		)
	}

	// Validate public key if present
	if e.PublicKey != nil {
		if err := e.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (d *Decaf448PublicKey) Validate() error {
	if d == nil {
		return errors.Wrap(errors.New("decaf448 public key is nil"), "validate")
	}

	// KeyValue should be 56 bytes
	if len(d.KeyValue) > 0 && len(d.KeyValue) != 56 {
		return errors.Wrap(
			errors.Errorf(
				"decaf448 public key must be 56 bytes, got %d",
				len(d.KeyValue),
			),
			"validate",
		)
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (d *Decaf448PrivateKey) Validate() error {
	if d == nil {
		return errors.Wrap(errors.New("decaf448 private key is nil"), "validate")
	}

	// KeyValue should be 56 bytes
	if len(d.KeyValue) > 0 && len(d.KeyValue) != 56 {
		return errors.Wrap(
			errors.Errorf(
				"decaf448 private key must be 56 bytes, got %d",
				len(d.KeyValue),
			),
			"validate",
		)
	}

	// Validate public key if present
	if d.PublicKey != nil {
		if err := d.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (d *Decaf448Signature) Validate() error {
	if d == nil {
		return errors.Wrap(errors.New("decaf448 signature is nil"), "validate")
	}

	// Signature should be 112 bytes (56 bytes R + 56 bytes S)
	if len(d.Signature) > 0 && len(d.Signature) != 112 {
		return errors.Wrap(
			errors.Errorf(
				"decaf448 signature must be 112 bytes, got %d",
				len(d.Signature),
			),
			"validate",
		)
	}

	// Validate public key if present
	if d.PublicKey != nil {
		if err := d.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (b *BLS48581G2PublicKey) Validate() error {
	if b == nil {
		return errors.Wrap(errors.New("bls48581 g2 public key is nil"), "validate")
	}

	// KeyValue should be 585 bytes
	if len(b.KeyValue) > 0 && len(b.KeyValue) != 585 {
		return errors.Wrap(
			errors.Errorf(
				"bls48581 g2 public key must be 585 bytes, got %d",
				len(b.KeyValue),
			),
			"validate",
		)
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (b *BLS48581Signature) Validate() error {
	if b == nil {
		return errors.Wrap(errors.New("bls48581 signature is nil"), "validate")
	}

	// Signature should be 74 bytes
	if len(b.Signature) > 0 && len(b.Signature) != 74 {
		return errors.Wrap(
			errors.Errorf(
				"bls48581 signature must be 74 bytes, got %d",
				len(b.Signature),
			),
			"validate",
		)
	}

	// Validate public key if present
	if b.PublicKey != nil {
		if err := b.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (b *BLS48581AggregateSignature) Validate() error {
	if b == nil {
		return errors.Wrap(
			errors.New("bls48581 aggregate signature is nil"),
			"validate",
		)
	}

	// Signature should be 74 bytes
	if len(b.Signature) > 0 && len(b.Signature) != 74 {
		return errors.Wrap(
			errors.Errorf(
				"bls48581 signature must be 74 bytes, got %d",
				len(b.Signature),
			),
			"validate",
		)
	}

	// Validate public key if present
	if b.PublicKey != nil {
		if err := b.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	// Bitmask can be variable length

	return nil
}

// Validate checks that all fields have valid lengths
func (x *X448PublicKey) Validate() error {
	if x == nil {
		return errors.Wrap(errors.New("x448 public key is nil"), "validate")
	}

	// KeyValue should be 57 bytes
	if len(x.KeyValue) > 0 && len(x.KeyValue) != 57 {
		return errors.Wrap(
			errors.Errorf(
				"x448 public key must be 57 bytes, got %d",
				len(x.KeyValue),
			),
			"validate",
		)
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (x *X448PrivateKey) Validate() error {
	if x == nil {
		return errors.Wrap(errors.New("x448 private key is nil"), "validate")
	}

	// KeyValue should be 57 bytes
	if len(x.KeyValue) > 0 && len(x.KeyValue) != 57 {
		return errors.Wrap(
			errors.Errorf(
				"x448 private key must be 57 bytes, got %d",
				len(x.KeyValue),
			),
			"validate",
		)
	}

	// Validate public key if present
	if x.PublicKey != nil {
		if err := x.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (p *PCASPublicKey) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("pcas public key is nil"), "validate")
	}

	// KeyValue should be 256 kilobytes
	if len(p.KeyValue) > 0 && len(p.KeyValue) != 256*1024 {
		return errors.Wrap(
			errors.Errorf(
				"pcas public key must be 256 kilobytes, got %d",
				len(p.KeyValue),
			),
			"validate",
		)
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (p *PCASPrivateKey) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("pcas private key is nil"), "validate")
	}

	// KeyValue should be 256 bytes
	if len(p.KeyValue) > 0 && len(p.KeyValue) != 256 {
		return errors.Wrap(
			errors.Errorf(
				"pcas private key must be 256 bytes, got %d",
				len(p.KeyValue),
			),
			"validate",
		)
	}

	// Validate public key if present
	if p.PublicKey != nil {
		if err := p.PublicKey.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

// ToCanonicalBytes serializes a KeyCollection to canonical bytes
func (k *KeyCollection) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		KeyCollectionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_purpose
	purposeBytes := []byte(k.KeyPurpose)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(purposeBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(purposeBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write keys count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(k.Keys)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each key
	for _, key := range k.Keys {
		keyBytes, err := key.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a KeyCollection from canonical bytes
func (k *KeyCollection) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != KeyCollectionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_purpose
	var purposeLen uint32
	if err := binary.Read(buf, binary.BigEndian, &purposeLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	purposeBytes := make([]byte, purposeLen)
	if _, err := buf.Read(purposeBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	k.KeyPurpose = string(purposeBytes)

	// Read keys count
	var keysCount uint32
	if err := binary.Read(buf, binary.BigEndian, &keysCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read each key
	k.Keys = make([]*SignedX448Key, keysCount)
	for i := uint32(0); i < keysCount; i++ {
		var keyLen uint32
		if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.Keys[i] = &SignedX448Key{}
		if err := k.Keys[i].FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// ToCanonicalBytes serializes a KeyRegistry to canonical bytes
func (k *KeyRegistry) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		KeyRegistryType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write identity_key
	if k.IdentityKey != nil {
		keyBytes, err := k.IdentityKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover_key
	if k.ProverKey != nil {
		keyBytes, err := k.ProverKey.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(keyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(keyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write identity_to_prover
	if k.IdentityToProver != nil {
		sigBytes, err := k.IdentityToProver.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover_to_identity
	if k.ProverToIdentity != nil {
		sigBytes, err := k.ProverToIdentity.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write keys_by_purpose count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(k.KeysByPurpose)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each key collection in the map
	for purpose, collection := range k.KeysByPurpose {
		// Write purpose string
		purposeBytes := []byte(purpose)
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(purposeBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(purposeBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}

		// Write collection
		collectionBytes, err := collection.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(collectionBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(collectionBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write last_updated
	if err := binary.Write(buf, binary.BigEndian, k.LastUpdated); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a KeyRegistry from canonical bytes
func (k *KeyRegistry) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != KeyRegistryType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read identity_key
	var identityKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &identityKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if identityKeyLen > 0 {
		keyBytes := make([]byte, identityKeyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.IdentityKey = &Ed448PublicKey{}
		if err := k.IdentityKey.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover_key
	var proverKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proverKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proverKeyLen > 0 {
		keyBytes := make([]byte, proverKeyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.ProverKey = &BLS48581G2PublicKey{}
		if err := k.ProverKey.FromCanonicalBytes(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read identity_to_prover
	var identityToProverLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&identityToProverLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if identityToProverLen > 0 {
		sigBytes := make([]byte, identityToProverLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.IdentityToProver = &Ed448Signature{}
		if err := k.IdentityToProver.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover_to_identity
	var proverToIdentityLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&proverToIdentityLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if proverToIdentityLen > 0 {
		sigBytes := make([]byte, proverToIdentityLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.ProverToIdentity = &BLS48581Signature{}
		if err := k.ProverToIdentity.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read keys_by_purpose count
	var mapCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mapCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read each key collection in the map
	k.KeysByPurpose = make(map[string]*KeyCollection)
	for i := uint32(0); i < mapCount; i++ {
		// Read purpose string
		var purposeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &purposeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		purposeBytes := make([]byte, purposeLen)
		if _, err := buf.Read(purposeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		purpose := string(purposeBytes)

		// Read collection
		var collectionLen uint32
		if err := binary.Read(buf, binary.BigEndian, &collectionLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		collectionBytes := make([]byte, collectionLen)
		if _, err := buf.Read(collectionBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		collection := &KeyCollection{}
		if err := collection.FromCanonicalBytes(collectionBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		k.KeysByPurpose[purpose] = collection
	}

	// Read last_updated
	if err := binary.Read(buf, binary.BigEndian, &k.LastUpdated); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

var _ ValidatableMessage = (*Ed448PublicKey)(nil)

// Validate checks the Ed448 public key.
func (e *Ed448PublicKey) Validate() error {
	if e == nil {
		return errors.New("nil ed448 public key")
	}
	if len(e.KeyValue) != 57 {
		return errors.New("invalid ed448 public key")
	}
	return nil
}

var _ ValidatableMessage = (*Ed448Signature)(nil)

// Validate checks the Ed448 signature.
func (e *Ed448Signature) Validate() error {
	if e == nil {
		return errors.New("nil ed448 signature")
	}
	if err := e.PublicKey.Validate(); err != nil {
		return errors.Wrap(err, "public key")
	}
	if len(e.Signature) != 114 {
		return errors.New("invalid ed448 signature")
	}
	return nil
}

var _ ValidatableMessage = (*BLS48581AddressedSignature)(nil)

// Validate checks the BLS48581Addressed signature.
func (e *BLS48581AddressedSignature) Validate() error {
	if e == nil {
		return errors.Wrap(errors.New("nil bls48581 signature"), "validate")
	}
	if len(e.Address) != 32 {
		return errors.Wrap(errors.New("invalid address"), "validate")
	}
	if len(e.Signature) != 74 {
		return errors.Wrap(errors.New("invalid bls48581 signature"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*BLS48581SignatureWithProofOfPossession)(nil)

// Validate checks the BLS48581Addressed signature.
func (e *BLS48581SignatureWithProofOfPossession) Validate() error {
	if e == nil {
		return errors.Wrap(errors.New("nil bls48581 signature"), "validate")
	}
	if e.PublicKey == nil || len(e.PublicKey.KeyValue) != 585 {
		return errors.Wrap(errors.New("invalid bls48581 public key"), "validate")
	}
	if len(e.PopSignature) != 74 {
		return errors.Wrap(errors.New("invalid popk signature"), "validate")
	}
	if len(e.Signature) != 74 {
		return errors.Wrap(errors.New("invalid bls48581 signature"), "validate")
	}
	return nil
}
