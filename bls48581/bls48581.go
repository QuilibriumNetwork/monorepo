package bls48581

import (
	"bytes"
	gcrypto "crypto"
	"encoding/binary"
	"io"
	"slices"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/bls48581/generated/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

//go:generate ./generate.sh

type BlsAggregateOutput struct {
	AggregatePublicKey []uint8
	AggregateSignature []uint8
}

type BlsKeygenOutput struct {
	SecretKey            []uint8
	PublicKey            []uint8
	ProofOfPossessionSig []uint8
}

type Multiproof struct {
	D     []uint8
	Proof []uint8
}

func (m *Multiproof) FromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read D
	var dLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dLen); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	m.D = make([]byte, dLen)
	if _, err := buf.Read(m.D); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Read Proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	m.Proof = make([]byte, proofLen)
	if _, err := buf.Read(m.Proof); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	return nil
}

func (m *Multiproof) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write D
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.D)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	if _, err := buf.Write(m.D); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	// Write Proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	if _, err := buf.Write(m.Proof); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	return buf.Bytes(), nil
}

func (o *BlsAggregateOutput) GetAggregatePublicKey() []byte {
	out := make([]byte, len(o.AggregatePublicKey))
	copy(out, o.AggregatePublicKey)
	return out
}

func (o *BlsAggregateOutput) GetAggregateSignature() []byte {
	out := make([]byte, len(o.AggregateSignature))
	copy(out, o.AggregateSignature)
	return out
}

func (o *BlsAggregateOutput) Verify(msg []byte, domain []byte) bool {
	return BlsVerify(o.AggregatePublicKey, o.AggregateSignature, msg, domain)
}

func (o *BlsKeygenOutput) GetPublicKey() []byte {
	out := make([]byte, len(o.PublicKey))
	copy(out, o.PublicKey)
	return out
}

func (o *BlsKeygenOutput) GetPrivateKey() []byte {
	out := make([]byte, len(o.SecretKey))
	copy(out, o.SecretKey)
	return out
}

func (o *BlsKeygenOutput) GetProofOfPossession() []byte {
	out := make([]byte, len(o.ProofOfPossessionSig))
	copy(out, o.ProofOfPossessionSig)
	return out
}

func (p *Multiproof) GetMulticommitment() []byte {
	out := make([]byte, len(p.D))
	copy(out, p.D)
	return out
}

func (p *Multiproof) GetProof() []byte {
	out := make([]byte, len(p.Proof))
	copy(out, p.Proof)
	return out
}

func Init() {
	generated.Init()
}

func CommitRaw(data []byte, polySize uint64) []byte {
	return generated.CommitRaw(data, polySize)
}

func ProveRaw(data []byte, index uint64, polySize uint64) []byte {
	return generated.ProveRaw(data, index, polySize)
}

func VerifyRaw(
	data []byte,
	commit []byte,
	index uint64,
	proof []byte,
	polySize uint64,
) bool {
	return generated.VerifyRaw(data, commit, index, proof, polySize)
}

func ProveMultiple(
	commitments [][]byte,
	polys [][]byte,
	indices []uint64,
	polySize uint64,
) crypto.Multiproof {
	mp := generated.ProveMultiple(commitments, polys, indices, polySize)
	d := slices.Clone(mp.D)
	proof := slices.Clone(mp.Proof)
	return &Multiproof{
		D:     d,
		Proof: proof,
	}
}

func VerifyMultiple(
	commitments [][]byte,
	evaluations [][]byte,
	indices []uint64,
	polySize uint64,
	multiCommitment []byte,
	proof []byte,
) bool {
	return generated.VerifyMultiple(
		commitments,
		evaluations,
		indices,
		polySize,
		multiCommitment,
		proof,
	)
}

func BlsAggregate(pks [][]byte, sigs [][]byte) crypto.BlsAggregateOutput {
	ag := generated.BlsAggregate(pks, sigs)
	pk := slices.Clone(ag.AggregatePublicKey)
	sig := slices.Clone(ag.AggregateSignature)
	return &BlsAggregateOutput{
		AggregatePublicKey: pk,
		AggregateSignature: sig,
	}
}

func BlsKeygen() crypto.BlsKeygenOutput {
	kg := generated.BlsKeygen()
	sk := slices.Clone(kg.SecretKey)
	pk := slices.Clone(kg.PublicKey)
	pops := slices.Clone(kg.ProofOfPossessionSig)
	return &BlsKeygenOutput{
		SecretKey:            sk,
		PublicKey:            pk,
		ProofOfPossessionSig: pops,
	}
}

func BlsSign(sk []byte, msg []byte, domain []byte) []byte {
	return generated.BlsSign(sk, msg, domain)
}

func BlsVerify(pk []byte, sig []byte, msg []byte, domain []byte) bool {
	if len(pk) != 585 || len(sig) != 74 {
		return false
	}

	return generated.BlsVerify(pk, sig, msg, domain)
}

type Bls48581KeyConstructor struct{}

// Aggregate implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (crypto.BlsAggregateOutput, error) {
	aggregate := BlsAggregate(publicKeys, signatures)
	if len(aggregate.GetAggregatePublicKey()) == 0 {
		return nil, errors.Wrap(errors.New("invalid aggregation"), "aggregate")
	}

	return aggregate, nil
}

// VerifySignatureRaw implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) VerifySignatureRaw(
	publicKeyG2 []byte,
	signatureG1 []byte,
	message []byte,
	context []byte,
) bool {
	if len(publicKeyG2) != 585 || len(signatureG1) != 74 {
		return false
	}

	return generated.BlsVerify(publicKeyG2, signatureG1, message, context)
}

type Bls48581Key struct {
	privateKey []byte
	publicKey  []byte
}

// GetType implements crypto.Signer.
func (b *Bls48581Key) GetType() crypto.KeyType {
	return crypto.KeyTypeBLS48581G1
}

// Private implements crypto.Signer.
func (b *Bls48581Key) Private() []byte {
	return b.privateKey
}

// Public implements crypto.Signer.
func (b *Bls48581Key) Public() gcrypto.PublicKey {
	return b.publicKey
}

// Sign implements crypto.Signer.
func (b *Bls48581Key) Sign(
	rand io.Reader,
	digest []byte,
	opts gcrypto.SignerOpts,
) (signature []byte, err error) {
	return nil, errors.Wrap(errors.New("sign with domain must be used"), "sign")
}

// SignWithDomain implements crypto.Signer.
func (b *Bls48581Key) SignWithDomain(
	message []byte,
	domain []byte,
) (signature []byte, err error) {
	out := BlsSign(b.privateKey, message, domain)
	if len(out) == 0 {
		return nil, errors.Wrap(errors.New("unknown"), "sign with domain")
	}

	return out, nil
}

// FromBytes implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) FromBytes(
	privateKey []byte,
	publicKey []byte,
) (crypto.Signer, error) {
	return &Bls48581Key{
		privateKey,
		publicKey,
	}, nil
}

// New implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) New() (crypto.Signer, []byte, error) {
	key := BlsKeygen()
	return &Bls48581Key{
		privateKey: key.GetPrivateKey(),
		publicKey:  key.GetPublicKey(),
	}, key.GetProofOfPossession(), nil
}

var _ crypto.BlsConstructor = (*Bls48581KeyConstructor)(nil)
