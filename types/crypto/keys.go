package crypto

import "crypto"

type KeyType int

const (
	KeyTypeEd448 KeyType = iota
	KeyTypeX448
	KeyTypeBLS48581G1
	KeyTypeBLS48581G2
	KeyTypeDecaf448
)

// Not utilized by the key manager, but some other things may depend on this:
const (
	KeyTypeSecp256K1SHA256 KeyType = 1 << 8
	KeyTypeSecp256K1SHA3   KeyType = 2 << 8
	KeyTypeEd25519         KeyType = 3 << 8
)

type BlsConstructor interface {
	New() (Signer, []byte, error)
	FromBytes(privateKey []byte, publicKey []byte) (Signer, error)
	VerifySignatureRaw(
		publicKeyG2 []byte,
		signatureG1 []byte,
		message []byte,
		context []byte,
	) bool
	Aggregate(
		publicKeys [][]byte,
		signatures [][]byte,
	) (BlsAggregateOutput, error)
}

type DecafConstructor interface {
	New() (DecafAgreement, error)
	FromBytes(privateKey []byte, publicKey []byte) (DecafAgreement, error)
	HashToScalar(input []byte) (DecafAgreement, error)
	NewFromScalar(input []byte) (DecafAgreement, error)
	AltGenerator() []byte
}

type Signer interface {
	crypto.Signer
	GetType() KeyType
	Private() []byte
	SignWithDomain(message []byte, domain []byte) (signature []byte, err error)
}

type DecafAgreement interface {
	Private() []byte
	Public() []byte
	AgreeWith(publicKey []byte) (shared []byte, err error)
	AgreeWithAndHashToScalar(publicKey []byte) (shared DecafAgreement, err error)
	InverseScalar() (inv DecafAgreement, err error)
	ScalarMult(scalar []byte) (product DecafAgreement, err error)
	Add(publicKey []byte) (point []byte, err error)
}

type Agreement interface {
	Private() []byte
	Public() []byte
	AgreeWith(publicKey []byte) (shared []byte, err error)
}
