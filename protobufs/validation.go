package protobufs

// SignedMessage is a message that has a signature.
type SignedMessage interface {
	// ValidateSignature checks the signature of the message.
	// The message contents are expected to be valid - validation
	// of contents must precede validation of the signature.
	ValidateSignature() error
}

// ValidatableMessage is a message that can be validated.
type ValidatableMessage interface {
	// Validate checks the message contents.
	// It does _not_ verify signatures. You will need to do this externally.
	Validate() error
}
