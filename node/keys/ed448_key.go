package keys

import (
	"crypto"
	"crypto/rand"
	"io"
	"slices"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type Ed448Key struct {
	privateKey []byte
	publicKey  []byte
}

func NewEd448Key() (*Ed448Key, error) {
	pubkey, privkey, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "new ed448 key")
	}

	return &Ed448Key{
		privateKey: privkey,
		publicKey:  pubkey,
	}, nil
}

func Ed448KeyFromBytes(privateKey []byte, publicKey []byte) (*Ed448Key, error) {
	return &Ed448Key{
		privateKey,
		publicKey,
	}, nil
}

// Private implements Signer.
func (e *Ed448Key) Private() []byte {
	return e.privateKey
}

func (e *Ed448Key) RawPrivateKey() []byte {
	H := sha3.NewShake256()
	h := make([]byte, 114)
	_, _ = H.Write(e.privateKey)
	_, _ = H.Read(h[:])
	h[0] &= 0xFC    // The two least significant bits of the first octet are cleared,
	h[57-1] = 0x00  // all eight bits the last octet are cleared, and
	h[57-2] |= 0x80 // the highest bit of the second to last octet is set.
	return h[:56]
}

// GetType implements Signer.
func (e *Ed448Key) GetType() qcrypto.KeyType {
	return qcrypto.KeyTypeEd448
}

// Public implements Signer.
func (e *Ed448Key) Public() crypto.PublicKey {
	return e.publicKey
}

// Sign implements Signer.
func (e *Ed448Key) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	return ed448.PrivateKey(e.privateKey).Sign(rand, digest, opts)
}

// SignWithDomain implements Signer.
func (e *Ed448Key) SignWithDomain(
	message []byte,
	domain []byte,
) (signature []byte, err error) {
	return e.Sign(rand.Reader, slices.Concat(domain, message), crypto.Hash(0))
}

var _ qcrypto.Signer = (*Ed448Key)(nil)
