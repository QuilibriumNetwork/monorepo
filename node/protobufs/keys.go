package protobufs

import (
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/zkp/schnorr"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
)

func (p *ProvingKeyAnnouncement) Verify() error {
	if p.ProvingKeySignature == nil {
		return errors.Wrap(errors.New("proving key signature nil"), "verify")
	}
	msg := append(
		append([]byte{}, p.IdentityCommitment...),
		p.PrekeyCommitment...,
	)

	switch k := p.ProvingKeySignature.(type) {
	case *ProvingKeyAnnouncement_ProvingKeySignatureEd448:
		return k.ProvingKeySignatureEd448.Verify(msg)
	default:
		return errors.Wrap(errors.New("unsupported signature type"), "verify")
	}
}

func (p *ProvingKeyAnnouncement) PublicKey() []byte {
	switch k := p.ProvingKeySignature.(type) {
	case *ProvingKeyAnnouncement_ProvingKeySignatureEd448:
		return k.ProvingKeySignatureEd448.PublicKey.KeyValue
	default:
		return nil
	}
}

func (k *KeyBundleAnnouncement) Verify(
	provingKey *ProvingKeyAnnouncement,
) error {
	var curve *curves.Curve
	if k.IdentityKey == nil {
		return errors.Wrap(errors.New("identity key is nil"), "verify")
	}

	if k.IdentityKey.IdentityKeySignature == nil {
		return errors.Wrap(errors.New("identity key signature is nil"), "verify")
	}

	if k.SignedPreKey == nil {
		return errors.Wrap(errors.New("signed pre key is nil"), "verify")
	}

	if k.SignedPreKey.SignedPreKeySignature == nil {
		return errors.Wrap(errors.New("signed pre key signature is nil"), "verify")
	}

	switch s := k.IdentityKey.IdentityKeySignature.(type) {
	case *IdentityKey_PublicKeySignatureEd448:
		err := s.PublicKeySignatureEd448.VerifyCrossSigned(
			k.ProvingKeyBytes,
		)
		if err != nil {
			return err
		}

		v := k.SignedPreKey.SignedPreKeySignature
		spk := v.(*SignedPreKey_PublicKeySignatureEd448)
		if spk == nil {
			return errors.Wrap(errors.New("curve mismatch"), "verify")
		}

		err = spk.PublicKeySignatureEd448.VerifyCrossSigned(
			k.ProvingKeyBytes,
		)
		if err != nil {
			return err
		}

		curve = curves.ED448()
	}

	idkc, err := curve.NewScalar().SetBytes(k.IdentityKey.Challenge)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "challenge invalid"),
			"verify",
		)
	}

	idks, err := curve.NewScalar().SetBytes(k.IdentityKey.Response)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "response invalid"),
			"verify",
		)
	}

	idkStatement, err := curve.NewGeneratorPoint().FromAffineCompressed(
		k.IdentityKey.Statement,
	)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "statement invalid"),
			"verify",
		)
	}

	spkc, err := curve.NewScalar().SetBytes(k.SignedPreKey.Challenge)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "challenge invalid"),
			"verify",
		)
	}

	spks, err := curve.NewScalar().SetBytes(k.SignedPreKey.Response)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "response invalid"),
			"verify",
		)
	}

	spkStatement, err := curve.NewGeneratorPoint().FromAffineCompressed(
		k.SignedPreKey.Statement,
	)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, "statement invalid"),
			"verify",
		)
	}

	if err := schnorr.DecommitVerify(
		&schnorr.Proof{
			Statement: idkStatement,
			C:         idkc,
			S:         idks,
		},
		provingKey.IdentityCommitment,
		curve,
		sha3.New256(),
		curve.NewGeneratorPoint(),
		[]byte{},
	); err != nil {
		return errors.Wrap(err, "verify")
	}

	if err := schnorr.DecommitVerify(
		&schnorr.Proof{
			Statement: spkStatement,
			C:         spkc,
			S:         spks,
		},
		provingKey.PrekeyCommitment,
		curve,
		sha3.New256(),
		curve.NewGeneratorPoint(),
		[]byte{},
	); err != nil {
		return errors.Wrap(err, "verify")
	}

	return nil
}

func (s *Ed448Signature) Verify(msg []byte) error {
	if s.PublicKey == nil {
		return errors.Wrap(errors.New("public key nil"), "verify")
	}

	if s.Signature == nil {
		return errors.Wrap(errors.New("signature nil"), "verify")
	}

	if len(s.PublicKey.KeyValue) != 57 {
		return errors.Wrap(errors.New("invalid length for public key"), "verify")
	}

	if len(s.Signature) != 114 {
		return errors.Wrap(errors.New("invalid length for signature"), "verify")
	}

	return s.verifyUnsafe(msg)
}

// verifyUnsafe is used to verify a signature without checking the length of the public key and signature.
func (s *Ed448Signature) verifyUnsafe(msg []byte) error {
	if !ed448.Verify(s.PublicKey.KeyValue, msg, s.Signature, "") {
		return errors.Wrap(errors.New("invalid signature for public key"), "verify")
	}

	return nil
}

func (s *Ed448Signature) VerifyCrossSigned(
	publicKey []byte,
) error {
	if s.PublicKey == nil {
		return errors.Wrap(errors.New("public key nil"), "verify")
	}

	if s.Signature == nil {
		return errors.Wrap(errors.New("signature nil"), "verify")
	}

	if len(s.PublicKey.KeyValue) != 57 {
		return errors.Wrap(errors.New("invalid length for public key"), "verify")
	}

	if len(s.Signature) != 114 {
		return errors.Wrap(errors.New("invalid length for signature"), "verify")
	}

	if !ed448.Verify(publicKey, s.PublicKey.KeyValue, s.Signature, "") {
		return errors.Wrap(errors.New("invalid signature for public key"), "verify")
	}

	return nil
}
