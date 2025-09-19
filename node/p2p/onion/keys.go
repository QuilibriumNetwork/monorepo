package onion

// KeyFn generates an ephemeral keypair used for key agreement.
type KeyFn func() (ephemeralPub []byte, ephemeralPriv []byte, err error)

// SharedSecretFn derives a DH shared secret using our ephemeral secret and the
// peer's long-term onion public key.
type SharedSecretFn func(ephemeralPriv []byte, peerOnionPub []byte) (
	sharedSecret []byte,
	err error,
)
