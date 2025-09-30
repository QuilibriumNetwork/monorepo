package keys

import (
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type keyRingShim struct {
	keyManager   keys.KeyManager
	validateOnly bool
}

// GetAgreementKey implements keys.KeyRing.
func (k *keyRingShim) GetAgreementKey(
	reference string,
	address []byte,
	keyType crypto.KeyType,
) (crypto.Agreement, error) {
	if !k.validateOnly {
		return k.keyManager.GetAgreementKey(reference)
	}

	panic("validate only mode")
}

// GetSigningKey implements keys.KeyRing.
func (k *keyRingShim) GetSigningKey(
	id string,
	keyType crypto.KeyType,
) (crypto.Signer, error) {
	if !k.validateOnly {
		return k.keyManager.GetSigningKey(id)
	}

	panic("validate only mode")
}

// ValidateSignature implements keys.KeyRing.
func (k *keyRingShim) ValidateSignature(
	keyType crypto.KeyType,
	publicKey []byte,
	message []byte,
	signature []byte,
	domain []byte,
) (bool, error) {
	return k.keyManager.ValidateSignature(
		keyType,
		publicKey,
		message,
		signature,
		domain,
	)
}

func ToKeyRing(keyManager keys.KeyManager, validateOnly bool) keys.KeyRing {
	return &keyRingShim{
		keyManager,
		validateOnly,
	}
}
