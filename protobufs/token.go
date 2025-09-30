package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func (a *Authority) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		AuthorityType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_type
	if err := binary.Write(buf, binary.BigEndian, a.KeyType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.PublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.PublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write can_burn
	canBurn := byte(0)
	if a.CanBurn {
		canBurn = 1
	}
	if err := buf.WriteByte(canBurn); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (a *Authority) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != AuthorityType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read key_type
	if err := binary.Read(buf, binary.BigEndian, &a.KeyType); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	a.PublicKey = make([]byte, keyLen)
	if _, err := buf.Read(a.PublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read can_burn
	canBurn, err := buf.ReadByte()
	if err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	a.CanBurn = canBurn != 0

	return nil
}

func (f *FeeBasis) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		FeeBasisStructType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write type
	if err := binary.Write(buf, binary.BigEndian, uint32(f.Type)); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write baseline
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Baseline)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Baseline); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (f *FeeBasis) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != FeeBasisStructType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read type
	var feeType uint32
	if err := binary.Read(buf, binary.BigEndian, &feeType); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Type = FeeBasisType(feeType)

	// Read baseline
	var baselineLen uint32
	if err := binary.Read(buf, binary.BigEndian, &baselineLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Baseline = make([]byte, baselineLen)
	if _, err := buf.Read(f.Baseline); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (t *TokenMintStrategy) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TokenMintStrategyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write mint_behavior
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(t.MintBehavior),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof_basis
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(t.ProofBasis),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write verkle_root
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.VerkleRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.VerkleRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write authority
	if t.Authority != nil {
		authBytes, err := t.Authority.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(authBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(authBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write payment_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.PaymentAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.PaymentAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write fee_basis
	if t.FeeBasis != nil {
		feeBytes, err := t.FeeBasis.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(feeBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(feeBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TokenMintStrategy) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TokenMintStrategyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read mint_behavior
	var mintBehavior uint32
	if err := binary.Read(buf, binary.BigEndian, &mintBehavior); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.MintBehavior = TokenMintBehavior(mintBehavior)

	// Read proof_basis
	var proofBasis uint32
	if err := binary.Read(buf, binary.BigEndian, &proofBasis); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.ProofBasis = ProofBasisType(proofBasis)

	// Read verkle_root
	var verkleLen uint32
	if err := binary.Read(buf, binary.BigEndian, &verkleLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if verkleLen > 0 {
		t.VerkleRoot = make([]byte, verkleLen)
		if _, err := buf.Read(t.VerkleRoot); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read authority
	var authLen uint32
	if err := binary.Read(buf, binary.BigEndian, &authLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if authLen > 0 {
		authBytes := make([]byte, authLen)
		if _, err := buf.Read(authBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Authority = &Authority{}
		if err := t.Authority.FromCanonicalBytes(authBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read payment_address
	var paymentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &paymentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if paymentLen > 0 {
		t.PaymentAddress = make([]byte, paymentLen)
		if _, err := buf.Read(t.PaymentAddress); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read fee_basis
	var feeLen uint32
	if err := binary.Read(buf, binary.BigEndian, &feeLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if feeLen > 0 {
		feeBytes := make([]byte, feeLen)
		if _, err := buf.Read(feeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.FeeBasis = &FeeBasis{}
		if err := t.FeeBasis.FromCanonicalBytes(feeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TokenConfiguration) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TokenConfigurationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write behavior
	if err := binary.Write(buf, binary.BigEndian, t.Behavior); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write mint_strategy
	if t.MintStrategy != nil {
		strategyBytes, err := t.MintStrategy.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(strategyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(strategyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write units
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Units)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Units); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write supply
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Supply)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Supply); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write name
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Name)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.WriteString(t.Name); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write symbol
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Symbol)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.WriteString(t.Symbol); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write additional_reference
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.AdditionalReference)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, ref := range t.AdditionalReference {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(ref)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(ref); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write owner_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.OwnerPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.OwnerPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (t *TokenConfiguration) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TokenConfigurationType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read behavior
	if err := binary.Read(buf, binary.BigEndian, &t.Behavior); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read mint_strategy
	var strategyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &strategyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if strategyLen > 0 {
		strategyBytes := make([]byte, strategyLen)
		if _, err := buf.Read(strategyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.MintStrategy = &TokenMintStrategy{}
		if err := t.MintStrategy.FromCanonicalBytes(strategyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read units
	var unitsLen uint32
	if err := binary.Read(buf, binary.BigEndian, &unitsLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if unitsLen > 0 {
		t.Units = make([]byte, unitsLen)
		if _, err := buf.Read(t.Units); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read supply
	var supplyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &supplyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if supplyLen > 0 {
		t.Supply = make([]byte, supplyLen)
		if _, err := buf.Read(t.Supply); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read name
	var nameLen uint32
	if err := binary.Read(buf, binary.BigEndian, &nameLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if nameLen > 0 {
		nameBytes := make([]byte, nameLen)
		if _, err := buf.Read(nameBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Name = string(nameBytes)
	}

	// Read symbol
	var symbolLen uint32
	if err := binary.Read(buf, binary.BigEndian, &symbolLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if symbolLen > 0 {
		symbolBytes := make([]byte, symbolLen)
		if _, err := buf.Read(symbolBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Symbol = string(symbolBytes)
	}

	// Read additional_reference
	var refCount uint32
	if err := binary.Read(buf, binary.BigEndian, &refCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refCount > 0 {
		t.AdditionalReference = make([][]byte, refCount)
		for i := uint32(0); i < refCount; i++ {
			var refLen uint32
			if err := binary.Read(buf, binary.BigEndian, &refLen); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			t.AdditionalReference[i] = make([]byte, refLen)
			if _, err := buf.Read(t.AdditionalReference[i]); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
		}
	}

	// Read owner_public_key
	var ownerKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ownerKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if ownerKeyLen > 0 {
		t.OwnerPublicKey = make([]byte, ownerKeyLen)
		if _, err := buf.Read(t.OwnerPublicKey); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TokenDeploy) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TokenDeploymentType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write config
	if t.Config != nil {
		configBytes, err := t.Config.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(configBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(configBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write rdf_schema
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if len(t.RdfSchema) > 0 {
		if _, err := buf.Write(t.RdfSchema); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TokenDeploy) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TokenDeploymentType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read config
	var configLen uint32
	if err := binary.Read(buf, binary.BigEndian, &configLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if configLen > 0 {
		configBytes := make([]byte, configLen)
		if _, err := buf.Read(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Config = &TokenConfiguration{}
		if err := t.Config.FromCanonicalBytes(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read rdf_schema
	var rdfSchemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &rdfSchemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if rdfSchemaLen > 0 {
		t.RdfSchema = make([]byte, rdfSchemaLen)
		if _, err := buf.Read(t.RdfSchema); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TokenUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TokenUpdateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write config
	if t.Config != nil {
		configBytes, err := t.Config.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(configBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(configBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write rdf_schema
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.RdfSchema); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if t.PublicKeySignatureBls48581 != nil {
		sigBytes, err := t.PublicKeySignatureBls48581.ToCanonicalBytes()
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

	return buf.Bytes(), nil
}

func (t *TokenUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TokenUpdateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read config
	var configLen uint32
	if err := binary.Read(buf, binary.BigEndian, &configLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if configLen > 0 {
		configBytes := make([]byte, configLen)
		if _, err := buf.Read(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Config = &TokenConfiguration{}
		if err := t.Config.FromCanonicalBytes(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read rdf_schema
	var schemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &schemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if schemaLen > 0 {
		t.RdfSchema = make([]byte, schemaLen)
		if _, err := buf.Read(t.RdfSchema); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := t.PublicKeySignatureBls48581.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (r *RecipientBundle) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		RecipientBundleType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write one_time_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.OneTimeKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.OneTimeKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write verification_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.VerificationKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.VerificationKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write coin_balance
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.CoinBalance)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.CoinBalance); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write mask
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.Mask)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.Mask); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write additional_reference
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.AdditionalReference)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.AdditionalReference); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write additional_reference_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(r.AdditionalReferenceKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(r.AdditionalReferenceKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (r *RecipientBundle) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != RecipientBundleType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read one_time_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	r.OneTimeKey = make([]byte, keyLen)
	if _, err := buf.Read(r.OneTimeKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read verification_key
	var verKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &verKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	r.VerificationKey = make([]byte, verKeyLen)
	if _, err := buf.Read(r.VerificationKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read coin_balance
	var balanceLen uint32
	if err := binary.Read(buf, binary.BigEndian, &balanceLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	r.CoinBalance = make([]byte, balanceLen)
	if _, err := buf.Read(r.CoinBalance); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read mask
	var maskLen uint32
	if err := binary.Read(buf, binary.BigEndian, &maskLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	r.Mask = make([]byte, maskLen)
	if _, err := buf.Read(r.Mask); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read additional_reference
	var refLen uint32
	if err := binary.Read(buf, binary.BigEndian, &refLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refLen > 0 {
		r.AdditionalReference = make([]byte, refLen)
		if _, err := buf.Read(r.AdditionalReference); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read additional_reference_key
	var refKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &refKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refKeyLen > 0 {
		r.AdditionalReferenceKey = make([]byte, refKeyLen)
		if _, err := buf.Read(r.AdditionalReferenceKey); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TransactionInput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TransactionInputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Proofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, proof := range t.Proofs {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(proof)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(proof); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TransactionInput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TransactionInputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(t.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Signature = make([]byte, sigLen)
	if _, err := buf.Read(t.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proofs
	var proofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &proofsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Proofs = make([][]byte, proofsCount)
	for i := uint32(0); i < proofsCount; i++ {
		var proofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Proofs[i] = make([]byte, proofLen)
		if _, err := buf.Read(t.Proofs[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *TransactionOutput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TransactionOutputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.FrameNumber)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write recipient_output
	if t.RecipientOutput != nil {
		recipientBytes, err := t.RecipientOutput.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(recipientBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(recipientBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TransactionOutput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TransactionOutputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	var frameLen uint32
	if err := binary.Read(buf, binary.BigEndian, &frameLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if frameLen > 0 {
		t.FrameNumber = make([]byte, frameLen)
		if _, err := buf.Read(t.FrameNumber); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(t.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read recipient_output
	var recipientLen uint32
	if err := binary.Read(buf, binary.BigEndian, &recipientLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if recipientLen > 0 {
		recipientBytes := make([]byte, recipientLen)
		if _, err := buf.Read(recipientBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.RecipientOutput = &RecipientBundle{}
		if err := t.RecipientOutput.FromCanonicalBytes(
			recipientBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (t *Transaction) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		TransactionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write inputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Inputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, input := range t.Inputs {
		inputBytes, err := input.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(inputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(inputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write outputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Outputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, output := range t.Outputs {
		outputBytes, err := output.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(outputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(outputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write fees count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Fees)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, fee := range t.Fees {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(fee)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(fee); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write range_proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.RangeProof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(t.RangeProof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write traversal_proof
	if t.TraversalProof != nil {
		traversalBytes, err := t.TraversalProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(traversalBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(traversalBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *Transaction) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TransactionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Domain = make([]byte, domainLen)
	if _, err := buf.Read(t.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inputs
	var inputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &inputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Inputs = make([]*TransactionInput, inputsCount)
	for i := uint32(0); i < inputsCount; i++ {
		var inputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &inputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		inputBytes := make([]byte, inputLen)
		if _, err := buf.Read(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Inputs[i] = &TransactionInput{}
		if err := t.Inputs[i].FromCanonicalBytes(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read outputs
	var outputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &outputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Outputs = make([]*TransactionOutput, outputsCount)
	for i := uint32(0); i < outputsCount; i++ {
		var outputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		outputBytes := make([]byte, outputLen)
		if _, err := buf.Read(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Outputs[i] = &TransactionOutput{}
		if err := t.Outputs[i].FromCanonicalBytes(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read fees
	var feesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &feesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Fees = make([][]byte, feesCount)
	for i := uint32(0); i < feesCount; i++ {
		var feeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &feeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Fees[i] = make([]byte, feeLen)
		if _, err := buf.Read(t.Fees[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read range_proof
	var rangeProofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &rangeProofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if rangeProofLen > 0 {
		t.RangeProof = make([]byte, rangeProofLen)
		if _, err := buf.Read(t.RangeProof); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read traversal_proof
	var traversalProofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &traversalProofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if traversalProofLen > 0 {
		traversalBytes := make([]byte, traversalProofLen)
		if _, err := buf.Read(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.TraversalProof = &TraversalProof{}
		if err := t.TraversalProof.FromCanonicalBytes(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *PendingTransactionInput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		PendingTransactionInputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Proofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, proof := range p.Proofs {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(proof)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(proof); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *PendingTransactionInput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PendingTransactionInputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(p.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Signature = make([]byte, sigLen)
	if _, err := buf.Read(p.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proofs
	var proofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &proofsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Proofs = make([][]byte, proofsCount)
	for i := uint32(0); i < proofsCount; i++ {
		var proofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Proofs[i] = make([]byte, proofLen)
		if _, err := buf.Read(p.Proofs[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *PendingTransactionOutput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		PendingTransactionOutputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.FrameNumber)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write to
	if p.To != nil {
		toBytes, err := p.To.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(toBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(toBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write refund
	if p.Refund != nil {
		refundBytes, err := p.Refund.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(refundBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(refundBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write expiration
	if err := binary.Write(buf, binary.BigEndian, p.Expiration); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (p *PendingTransactionOutput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PendingTransactionOutputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	var frameLen uint32
	if err := binary.Read(buf, binary.BigEndian, &frameLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if frameLen > 0 {
		p.FrameNumber = make([]byte, frameLen)
		if _, err := buf.Read(p.FrameNumber); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if commitmentLen > 0 {
		p.Commitment = make([]byte, commitmentLen)
		if _, err := buf.Read(p.Commitment); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read to
	var toLen uint32
	if err := binary.Read(buf, binary.BigEndian, &toLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if toLen > 0 {
		toBytes := make([]byte, toLen)
		if _, err := buf.Read(toBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.To = &RecipientBundle{}
		if err := p.To.FromCanonicalBytes(toBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read refund
	var refundLen uint32
	if err := binary.Read(buf, binary.BigEndian, &refundLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refundLen > 0 {
		refundBytes := make([]byte, refundLen)
		if _, err := buf.Read(refundBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Refund = &RecipientBundle{}
		if err := p.Refund.FromCanonicalBytes(refundBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read expiration
	if err := binary.Read(buf, binary.BigEndian, &p.Expiration); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (p *PendingTransaction) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		PendingTransactionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write inputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Inputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, input := range p.Inputs {
		inputBytes, err := input.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(inputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(inputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write outputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Outputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, output := range p.Outputs {
		outputBytes, err := output.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(outputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(outputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write fees count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Fees)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, fee := range p.Fees {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(fee)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(fee); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write range_proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.RangeProof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.RangeProof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write traversal_proof
	if p.TraversalProof != nil {
		traversalBytes, err := p.TraversalProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(traversalBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(traversalBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *PendingTransaction) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PendingTransactionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Domain = make([]byte, domainLen)
	if _, err := buf.Read(p.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inputs
	var inputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &inputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Inputs = make([]*PendingTransactionInput, inputsCount)
	for i := uint32(0); i < inputsCount; i++ {
		var inputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &inputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		inputBytes := make([]byte, inputLen)
		if _, err := buf.Read(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Inputs[i] = &PendingTransactionInput{}
		if err := p.Inputs[i].FromCanonicalBytes(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read outputs
	var outputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &outputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Outputs = make([]*PendingTransactionOutput, outputsCount)
	for i := uint32(0); i < outputsCount; i++ {
		var outputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		outputBytes := make([]byte, outputLen)
		if _, err := buf.Read(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Outputs[i] = &PendingTransactionOutput{}
		if err := p.Outputs[i].FromCanonicalBytes(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read fees
	var feesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &feesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Fees = make([][]byte, feesCount)
	for i := uint32(0); i < feesCount; i++ {
		var feeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &feeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Fees[i] = make([]byte, feeLen)
		if _, err := buf.Read(p.Fees[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read range_proof
	var rangeProofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &rangeProofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if rangeProofLen > 0 {
		p.RangeProof = make([]byte, rangeProofLen)
		if _, err := buf.Read(p.RangeProof); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read traversal_proof
	var traversalProofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &traversalProofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if traversalProofLen > 0 {
		traversalBytes := make([]byte, traversalProofLen)
		if _, err := buf.Read(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.TraversalProof = &TraversalProof{}
		if err := p.TraversalProof.FromCanonicalBytes(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (m *MintTransactionInput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		MintTransactionInputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write value
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Value)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Value); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Proofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, proof := range m.Proofs {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(proof)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(proof); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write additional_reference
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.AdditionalReference)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.AdditionalReference); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write additional_reference_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.AdditionalReferenceKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.AdditionalReferenceKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MintTransactionInput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MintTransactionInputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read value
	var valueLen uint32
	if err := binary.Read(buf, binary.BigEndian, &valueLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Value = make([]byte, valueLen)
	if _, err := buf.Read(m.Value); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(m.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Signature = make([]byte, sigLen)
	if _, err := buf.Read(m.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proofs
	var proofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &proofsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Proofs = make([][]byte, proofsCount)
	for i := uint32(0); i < proofsCount; i++ {
		var proofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Proofs[i] = make([]byte, proofLen)
		if _, err := buf.Read(m.Proofs[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read additional_reference
	var refKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &refKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refKeyLen > 0 {
		m.AdditionalReference = make([]byte, refKeyLen)
		if _, err := buf.Read(m.AdditionalReference); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read additional_reference_key
	var refKeyKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &refKeyKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if refKeyKeyLen > 0 {
		m.AdditionalReferenceKey = make([]byte, refKeyKeyLen)
		if _, err := buf.Read(
			m.AdditionalReferenceKey,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (m *MintTransactionOutput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		MintTransactionOutputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.FrameNumber)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write recipient_output
	if m.RecipientOutput != nil {
		recipientBytes, err := m.RecipientOutput.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(recipientBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(recipientBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (m *MintTransactionOutput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MintTransactionOutputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	var frameLen uint32
	if err := binary.Read(buf, binary.BigEndian, &frameLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if frameLen > 0 {
		m.FrameNumber = make([]byte, frameLen)
		if _, err := buf.Read(m.FrameNumber); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(m.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read recipient_output
	var recipientLen uint32
	if err := binary.Read(buf, binary.BigEndian, &recipientLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if recipientLen > 0 {
		recipientBytes := make([]byte, recipientLen)
		if _, err := buf.Read(recipientBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.RecipientOutput = &RecipientBundle{}
		if err := m.RecipientOutput.FromCanonicalBytes(
			recipientBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (m *MintTransaction) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		MintTransactionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write inputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Inputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, input := range m.Inputs {
		inputBytes, err := input.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(inputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(inputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write outputs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Outputs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, output := range m.Outputs {
		outputBytes, err := output.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(outputBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(outputBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write fees count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Fees)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, fee := range m.Fees {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(fee)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(fee); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write range_proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.RangeProof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.RangeProof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MintTransaction) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MintTransactionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Domain = make([]byte, domainLen)
	if _, err := buf.Read(m.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inputs
	var inputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &inputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Inputs = make([]*MintTransactionInput, inputsCount)
	for i := uint32(0); i < inputsCount; i++ {
		var inputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &inputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		inputBytes := make([]byte, inputLen)
		if _, err := buf.Read(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Inputs[i] = &MintTransactionInput{}
		if err := m.Inputs[i].FromCanonicalBytes(inputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read outputs
	var outputsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &outputsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Outputs = make([]*MintTransactionOutput, outputsCount)
	for i := uint32(0); i < outputsCount; i++ {
		var outputLen uint32
		if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		outputBytes := make([]byte, outputLen)
		if _, err := buf.Read(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Outputs[i] = &MintTransactionOutput{}
		if err := m.Outputs[i].FromCanonicalBytes(outputBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read fees
	var feesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &feesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Fees = make([][]byte, feesCount)
	for i := uint32(0); i < feesCount; i++ {
		var feeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &feeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Fees[i] = make([]byte, feeLen)
		if _, err := buf.Read(m.Fees[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read range_proof
	var rangeProofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &rangeProofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if rangeProofLen > 0 {
		m.RangeProof = make([]byte, rangeProofLen)
		if _, err := buf.Read(m.RangeProof); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

var _ ValidatableMessage = (*Authority)(nil)

func (a *Authority) Validate() error {
	if a == nil {
		return errors.Wrap(errors.New("nil authority"), "validate")
	}

	// Validate public key based on key type
	switch a.KeyType {
	case 0: // Ed448
		if len(a.PublicKey) != 57 {
			return errors.Wrap(
				errors.New("invalid ed448 public key length"),
				"validate",
			)
		}
	default:
		return errors.Wrap(
			errors.New("unsupported key type"),
			"validate",
		)
	}

	return nil
}

var _ ValidatableMessage = (*FeeBasis)(nil)

func (f *FeeBasis) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil fee basis"), "validate")
	}

	// Validate fee type
	switch f.Type {
	case FeeBasisType_NO_FEE_BASIS:
		// No baseline needed
	case FeeBasisType_PER_UNIT:
		if len(f.Baseline) == 0 {
			return errors.Wrap(
				errors.New("baseline required for per unit fee"),
				"validate",
			)
		}
	default:
		return errors.Wrap(errors.New("invalid fee basis type"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*TokenMintStrategy)(nil)

func (t *TokenMintStrategy) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil token mint strategy"), "validate")
	}

	// Validate mint behavior
	switch t.MintBehavior {
	case TokenMintBehavior_NO_MINT_BEHAVIOR:
		// No additional validation needed
	case TokenMintBehavior_MINT_WITH_PROOF:
		// Verkle root is optional
	case TokenMintBehavior_MINT_WITH_AUTHORITY:
		if t.Authority == nil {
			return errors.Wrap(
				errors.New("authority required for authority mint"),
				"validate",
			)
		}
		if err := t.Authority.Validate(); err != nil {
			return errors.Wrap(err, "authority")
		}
	case TokenMintBehavior_MINT_WITH_SIGNATURE:
		if t.Authority == nil {
			return errors.Wrap(
				errors.New("authority required for signature mint"),
				"validate",
			)
		}
		if err := t.Authority.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	case TokenMintBehavior_MINT_WITH_PAYMENT:
		if len(t.PaymentAddress) == 0 {
			return errors.Wrap(
				errors.New("payment address required for payment mint"),
				"validate",
			)
		}
		if t.FeeBasis == nil {
			return errors.Wrap(
				errors.New("fee basis required for payment mint"),
				"validate",
			)
		}
		if err := t.FeeBasis.Validate(); err != nil {
			return errors.Wrap(err, "fee basis")
		}
	default:
		return errors.Wrap(errors.New("invalid mint behavior"), "validate")
	}

	// Validate proof basis
	switch t.ProofBasis {
	case ProofBasisType_NO_PROOF_BASIS:
		// No additional validation needed
	case ProofBasisType_PROOF_OF_MEANINGFUL_WORK:
		// No additional validation needed
	case ProofBasisType_VERKLE_MULTIPROOF_WITH_SIGNATURE:
		if len(t.VerkleRoot) == 0 {
			return errors.Wrap(
				errors.New("verkle root required for verkle proof basis"),
				"validate",
			)
		}
	default:
		return errors.Wrap(errors.New("invalid proof basis type"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*TokenConfiguration)(nil)

func (t *TokenConfiguration) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil token configuration"), "validate")
	}

	// Check if mintable flag is set
	isMintable := (t.Behavior & uint32(
		TokenIntrinsicBehavior_TOKEN_BEHAVIOR_MINTABLE,
	)) != 0

	if isMintable {
		if t.MintStrategy == nil {
			return errors.Wrap(
				errors.New("mint strategy required for mintable token"),
				"validate",
			)
		}
		if err := t.MintStrategy.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	} else {
		// Non-mintable tokens must have supply
		if len(t.Supply) == 0 {
			return errors.Wrap(
				errors.New("supply required for non-mintable token"),
				"validate",
			)
		}
	}

	// Check if divisible flag is set
	isDivisible := (t.Behavior & uint32(
		TokenIntrinsicBehavior_TOKEN_BEHAVIOR_DIVISIBLE,
	)) != 0

	if isDivisible {
		if len(t.Units) == 0 {
			return errors.Wrap(
				errors.New("units required for divisible token"),
				"validate",
			)
		}
	}

	// Validate metadata
	if len(t.Name) == 0 {
		return errors.Wrap(errors.New("token name required"), "validate")
	}

	if len(t.Symbol) == 0 {
		return errors.Wrap(errors.New("token symbol required"), "validate")
	}

	// Each additional reference should be 64 bytes if provided
	for i, ref := range t.AdditionalReference {
		if len(ref) != 64 {
			return errors.Wrapf(
				errors.New("additional reference must be 64 bytes"),
				"validate: reference %d has %d bytes",
				i, len(ref),
			)
		}
	}

	// Validate owner public key (0 or 585 bytes for BLS48-581)
	if len(t.OwnerPublicKey) != 0 && len(t.OwnerPublicKey) != 585 {
		return errors.Wrap(
			errors.New("owner public key must be 0 or 585 bytes"),
			"validate",
		)
	}

	return nil
}

var _ ValidatableMessage = (*TokenDeploy)(nil)

func (t *TokenDeploy) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil token deploy"), "validate")
	}

	if t.Config == nil {
		return errors.Wrap(errors.New("nil configuration"), "validate")
	}

	return t.Config.Validate()
}

var _ ValidatableMessage = (*TokenUpdate)(nil)

func (t *TokenUpdate) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil token update"), "validate")
	}

	// Config is required for token updates
	if t.Config == nil {
		return errors.Wrap(errors.New("nil configuration"), "validate")
	}

	if err := t.Config.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	if t.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("public key signature is nil"), "validate")
	}

	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*RecipientBundle)(nil)

func (r *RecipientBundle) Validate() error {
	if r == nil {
		return errors.Wrap(errors.New("nil recipient bundle"), "validate")
	}

	// OneTimeKey should not be empty
	if len(r.OneTimeKey) == 0 {
		return errors.Wrap(errors.New("one time key required"), "validate")
	}

	// VerificationKey should not be empty
	if len(r.VerificationKey) == 0 {
		return errors.Wrap(errors.New("verification key required"), "validate")
	}

	// CoinBalance should not be empty
	if len(r.CoinBalance) == 0 {
		return errors.Wrap(errors.New("coin balance required"), "validate")
	}

	// Mask should not be empty
	if len(r.Mask) == 0 {
		return errors.Wrap(errors.New("mask required"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*TransactionInput)(nil)

func (t *TransactionInput) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil transaction input"), "validate")
	}

	if len(t.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment required"), "validate")
	}

	if len(t.Signature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}

	// Proofs can be empty

	return nil
}

var _ ValidatableMessage = (*TransactionOutput)(nil)

func (t *TransactionOutput) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil transaction output"), "validate")
	}

	// FrameNumber can be empty (for pending outputs)

	if len(t.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment required"), "validate")
	}

	if t.RecipientOutput != nil {
		if err := t.RecipientOutput.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

var _ ValidatableMessage = (*Transaction)(nil)

func (t *Transaction) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil transaction"), "validate")
	}

	// Validate domain (32 bytes)
	if len(t.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Must have at least one input
	if len(t.Inputs) == 0 {
		return errors.Wrap(errors.New("no inputs"), "validate")
	}

	// Validate all inputs
	for i, input := range t.Inputs {
		if err := input.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "input %d", i), "validate")
		}
	}

	// Must have at least one output
	if len(t.Outputs) == 0 {
		return errors.Wrap(errors.New("no outputs"), "validate")
	}

	// Validate all outputs
	for i, output := range t.Outputs {
		if err := output.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "output %d", i), "validate")
		}
	}

	// Fees array should match outputs
	if len(t.Fees) != len(t.Outputs) {
		return errors.Wrap(
			errors.New("fees count must match outputs count"),
			"validate",
		)
	}

	// Range proof is required
	if len(t.RangeProof) == 0 {
		return errors.Wrap(errors.New("range proof required"), "validate")
	}

	// TraversalProof is optional

	return nil
}

var _ ValidatableMessage = (*PendingTransactionInput)(nil)

func (p *PendingTransactionInput) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil pending transaction input"), "validate")
	}

	if len(p.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment required"), "validate")
	}

	if len(p.Signature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}

	// Proofs can be empty

	return nil
}

var _ ValidatableMessage = (*PendingTransactionOutput)(nil)

func (p *PendingTransactionOutput) Validate() error {
	if p == nil {
		return errors.Wrap(
			errors.New("nil pending transaction output"),
			"validate",
		)
	}

	// FrameNumber can be empty (for pending outputs)

	if p.To == nil {
		return errors.Wrap(errors.New("to recipient required"), "validate")
	}
	if err := p.To.Validate(); err != nil {
		return errors.Wrap(err, "to recipient")
	}

	if p.Refund == nil {
		return errors.Wrap(errors.New("refund recipient required"), "validate")
	}
	if err := p.Refund.Validate(); err != nil {
		return errors.Wrap(err, "refund recipient")
	}

	// Expiration is checked only if token is expirable

	return nil
}

var _ ValidatableMessage = (*PendingTransaction)(nil)

func (p *PendingTransaction) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil pending transaction"), "validate")
	}

	// Validate domain (32 bytes)
	if len(p.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Must have at least one input
	if len(p.Inputs) == 0 {
		return errors.Wrap(errors.New("no inputs"), "validate")
	}

	// Validate all inputs
	for i, input := range p.Inputs {
		if err := input.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "input %d", i), "validate")
		}
	}

	// Must have at least one output
	if len(p.Outputs) == 0 {
		return errors.Wrap(errors.New("no outputs"), "validate")
	}

	// Validate all outputs
	for i, output := range p.Outputs {
		if err := output.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "output %d", i), "validate")
		}
	}

	// Fees array should match outputs
	if len(p.Fees) != len(p.Outputs) {
		return errors.Wrap(
			errors.New("fees count must match outputs count"),
			"validate",
		)
	}

	// Range proof is required
	if len(p.RangeProof) == 0 {
		return errors.Wrap(errors.New("range proof required"), "validate")
	}

	// TraversalProof is optional

	return nil
}

var _ ValidatableMessage = (*MintTransactionInput)(nil)

func (m *MintTransactionInput) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil mint transaction input"), "validate")
	}

	if len(m.Value) == 0 {
		return errors.Wrap(errors.New("value required"), "validate")
	}

	if len(m.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment required"), "validate")
	}

	if len(m.Signature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}

	// Proofs can be empty
	// Additional reference encryption keys are optional

	return nil
}

var _ ValidatableMessage = (*MintTransactionOutput)(nil)

func (m *MintTransactionOutput) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil mint transaction output"), "validate")
	}

	// FrameNumber can be empty (for pending outputs)

	if len(m.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment required"), "validate")
	}

	if m.RecipientOutput != nil {
		if err := m.RecipientOutput.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

var _ ValidatableMessage = (*MintTransaction)(nil)

func (m *MintTransaction) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil mint transaction"), "validate")
	}

	// Validate domain (32 bytes)
	if len(m.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Must have at least one input
	if len(m.Inputs) == 0 {
		return errors.Wrap(errors.New("no inputs"), "validate")
	}

	// Validate all inputs
	for i, input := range m.Inputs {
		if err := input.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "input %d", i), "validate")
		}
	}

	// Must have at least one output
	if len(m.Outputs) == 0 {
		return errors.Wrap(errors.New("no outputs"), "validate")
	}

	// Validate all outputs
	for i, output := range m.Outputs {
		if err := output.Validate(); err != nil {
			return errors.Wrap(errors.Wrapf(err, "output %d", i), "validate")
		}
	}

	// Fees array should match outputs
	if len(m.Fees) != len(m.Outputs) {
		return errors.Wrap(
			errors.New("fees count must match outputs count"),
			"validate",
		)
	}

	// Range proof is required
	if len(m.RangeProof) == 0 {
		return errors.Wrap(errors.New("range proof required"), "validate")
	}

	return nil
}
