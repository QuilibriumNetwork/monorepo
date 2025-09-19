package keys

import (
	"crypto/rand"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type X448Key struct {
	privateKey curves.Scalar
}

func NewX448Key() *X448Key {
	privkey := curves.ED448().Scalar.Random(rand.Reader)

	return &X448Key{privateKey: privkey}
}

func X448KeyFromBytes(data []byte) (*X448Key, error) {
	privkey, err := curves.ED448().Scalar.SetBytes(data)
	if err != nil {
		return nil, errors.Wrap(err, "from bytes")
	}

	return &X448Key{privateKey: privkey}, nil
}

// AgreeWith implements Agreement.
func (x *X448Key) AgreeWith(publicKey []byte) (shared []byte, err error) {
	pubkey, err := curves.ED448().NewGeneratorPoint().FromAffineCompressed(
		publicKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "agree with")
	}

	return pubkey.Mul(x.privateKey).ToAffineCompressed(), nil
}

// Private implements Agreement.
func (x *X448Key) Private() []byte {
	return x.privateKey.Bytes()
}

// Public implements Agreement.
func (x *X448Key) Public() []byte {
	pubkey := curves.ED448().NewGeneratorPoint().Mul(x.privateKey)
	return pubkey.ToAffineCompressed()
}

var _ qcrypto.Agreement = (*X448Key)(nil)
