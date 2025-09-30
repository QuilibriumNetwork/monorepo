package keys

import (
	"encoding/hex"

	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type KeyManager interface {
	GetRawKey(id string) (*Key, error)
	GetSigningKey(id string) (crypto.Signer, error)
	GetAgreementKey(id string) (crypto.Agreement, error)
	PutRawKey(key *Key) error
	CreateSigningKey(
		id string,
		keyType crypto.KeyType,
	) (key crypto.Signer, popk []byte, err error)
	CreateAgreementKey(
		id string,
		keyType crypto.KeyType,
	) (crypto.Agreement, error)
	DeleteKey(id string) error
	ListKeys() ([]*Key, error)
	ValidateSignature(
		keyType crypto.KeyType,
		publicKey []byte,
		message []byte,
		signature []byte,
		domain []byte,
	) (bool, error)
	Aggregate(publicKeys [][]byte, signatures [][]byte) (
		crypto.BlsAggregateOutput,
		error,
	)
}

type KeyRing interface {
	GetSigningKey(
		id string,
		keyType crypto.KeyType,
	) (crypto.Signer, error)
	GetAgreementKey(
		reference string,
		address []byte,
		keyType crypto.KeyType,
	) (crypto.Agreement, error)
	ValidateSignature(
		keyType crypto.KeyType,
		publicKey []byte,
		message []byte,
		signature []byte,
		domain []byte,
	) (bool, error)
}

type ByteString []byte

func (b ByteString) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(b)), nil
}

func (b *ByteString) UnmarshalText(text []byte) error {
	value, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}

	*b = value
	return nil
}

type Key struct {
	Id         string         `yaml:"id"`
	Type       crypto.KeyType `yaml:"type"`
	PrivateKey ByteString     `yaml:"privateKey"`
	PublicKey  ByteString     `yaml:"publicKey"`
}
