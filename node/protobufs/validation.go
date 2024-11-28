package protobufs

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
)

type signatureMessage interface {
	signatureMessage() []byte
}

var _ signatureMessage = (*ClockFrameFragment_ReedSolomonEncoding)(nil)

func (c *ClockFrameFragment_ReedSolomonEncoding) signatureMessage() []byte {
	payload := []byte("reed-solomon-fragment")
	payload = binary.BigEndian.AppendUint64(payload, c.FrameSize)
	payload = binary.BigEndian.AppendUint64(payload, c.FragmentShard)
	payload = binary.BigEndian.AppendUint64(payload, c.FragmentDataShardCount)
	payload = binary.BigEndian.AppendUint64(payload, c.FragmentParityShardCount)
	h := sha256.Sum256(c.FragmentData)
	payload = append(payload, h[:]...)
	return payload
}

var _ signatureMessage = (*ClockFrameFragment)(nil)

func (c *ClockFrameFragment) signatureMessage() []byte {
	payload := []byte("fragment")
	payload = binary.BigEndian.AppendUint64(payload, c.FrameNumber)
	payload = append(payload, c.Filter...)
	payload = binary.BigEndian.AppendUint64(payload, uint64(c.Timestamp))
	payload = append(payload, c.FrameHash...)
	if reedSolomon := c.GetReedSolomon(); reedSolomon != nil {
		payload = append(payload, reedSolomon.signatureMessage()...)
	}
	return payload
}

var _ signatureMessage = (*TransferCoinRequest)(nil)

func (t *TransferCoinRequest) signatureMessage() []byte {
	payload := []byte("transfer")
	payload = append(payload, t.OfCoin.Address...)
	payload = append(
		payload,
		t.ToAccount.GetImplicitAccount().Address...,
	)
	return payload
}

var _ signatureMessage = (*SplitCoinRequest)(nil)

func (t *SplitCoinRequest) signatureMessage() []byte {
	payload := []byte("split")
	payload = append(payload, t.OfCoin.Address...)
	for _, a := range t.Amounts {
		payload = append(payload, a...)
	}
	return payload
}

var _ signatureMessage = (*MergeCoinRequest)(nil)

func (t *MergeCoinRequest) signatureMessage() []byte {
	payload := []byte("merge")
	for _, c := range t.Coins {
		payload = append(payload, c.Address...)
	}
	return payload
}

var _ signatureMessage = (*MintCoinRequest)(nil)

func (t *MintCoinRequest) signatureMessage() []byte {
	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	return payload
}

// NOTE: AnnounceProverRequest has a non-trivial signature payload.

var _ signatureMessage = (*AnnounceProverJoin)(nil)

func (t *AnnounceProverJoin) signatureMessage() []byte {
	payload := []byte("join")
	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)
	return payload
}

var _ signatureMessage = (*AnnounceProverLeave)(nil)

func (t *AnnounceProverLeave) signatureMessage() []byte {
	payload := []byte("leave")
	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)
	return payload
}

var _ signatureMessage = (*AnnounceProverPause)(nil)

func (t *AnnounceProverPause) signatureMessage() []byte {
	payload := []byte("pause")
	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)
	return payload
}

var _ signatureMessage = (*AnnounceProverResume)(nil)

func (t *AnnounceProverResume) signatureMessage() []byte {
	payload := []byte("resume")
	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)
	return payload
}

// SignedMessage is a message that has a signature.
type SignedMessage interface {
	// ValidateSignature checks the signature of the message.
	// The message contents are expected to be valid - validation
	// of contents must precede validation of the signature.
	ValidateSignature() error
}

var _ SignedMessage = (*ClockFrameFragment)(nil)

// ValidateSignature checks the signature of the clock frame fragment.
func (c *ClockFrameFragment) ValidateSignature() error {
	switch {
	case c.GetPublicKeySignatureEd448() != nil:
		if err := c.GetPublicKeySignatureEd448().verifyUnsafe(c.signatureMessage()); err != nil {
			return errors.Wrap(err, "validate signature")
		}
		return nil
	default:
		return errors.New("invalid signature")
	}
}

var _ SignedMessage = (*TransferCoinRequest)(nil)

// ValidateSignature checks the signature of the transfer coin request.
func (t *TransferCoinRequest) ValidateSignature() error {
	if err := t.Signature.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*SplitCoinRequest)(nil)

// ValidateSignature checks the signature of the split coin request.
func (t *SplitCoinRequest) ValidateSignature() error {
	if err := t.Signature.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*MergeCoinRequest)(nil)

// ValidateSignature checks the signature of the merge coin request.
func (t *MergeCoinRequest) ValidateSignature() error {
	if err := t.Signature.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*MintCoinRequest)(nil)

// ValidateSignature checks the signature of the mint coin request.
func (t *MintCoinRequest) ValidateSignature() error {
	if err := t.Signature.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*AnnounceProverRequest)(nil)

// ValidateSignature checks the signature of the announce prover request.
func (t *AnnounceProverRequest) ValidateSignature() error {
	payload := []byte{}
	primary := t.PublicKeySignaturesEd448[0]
	for _, p := range t.PublicKeySignaturesEd448[1:] {
		payload = append(payload, p.PublicKey.KeyValue...)
		if err := p.verifyUnsafe(primary.PublicKey.KeyValue); err != nil {
			return errors.Wrap(err, "validate signature")
		}
	}
	if err := primary.verifyUnsafe(payload); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*AnnounceProverJoin)(nil)

// ValidateSignature checks the signature of the announce prover join.
func (t *AnnounceProverJoin) ValidateSignature() error {
	if err := t.PublicKeySignatureEd448.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*AnnounceProverLeave)(nil)

// ValidateSignature checks the signature of the announce prover leave.
func (t *AnnounceProverLeave) ValidateSignature() error {
	if err := t.PublicKeySignatureEd448.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*AnnounceProverPause)(nil)

// ValidateSignature checks the signature of the announce prover pause.
func (t *AnnounceProverPause) ValidateSignature() error {
	if err := t.PublicKeySignatureEd448.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ SignedMessage = (*AnnounceProverResume)(nil)

// ValidateSignature checks the signature of the announce prover resume.
func (t *AnnounceProverResume) ValidateSignature() error {
	if err := t.PublicKeySignatureEd448.verifyUnsafe(t.signatureMessage()); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

// ValidatableMessage is a message that can be validated.
type ValidatableMessage interface {
	// Validate checks the message contents.
	// It will also verify signatures if the message is signed.
	Validate() error
}

var _ ValidatableMessage = (*ClockFrameFragment_ReedSolomonEncoding)(nil)

// Validate checks the Reed-Solomon encoding.
func (c *ClockFrameFragment_ReedSolomonEncoding) Validate() error {
	if c == nil {
		return errors.New("nil Reed-Solomon encoding")
	}
	if c.FrameSize == 0 {
		return errors.New("invalid frame size")
	}
	if c.FragmentDataShardCount == 0 {
		return errors.New("invalid fragment data shard count")
	}
	if c.FragmentParityShardCount == 0 {
		return errors.New("invalid fragment parity shard count")
	}
	if c.FragmentShard >= c.FragmentDataShardCount+c.FragmentParityShardCount {
		return errors.New("invalid fragment shard")
	}
	if len(c.FragmentData) == 0 {
		return errors.New("invalid fragment data")
	}
	return nil
}

var _ ValidatableMessage = (*ClockFrameFragment)(nil)

// Validate checks the clock frame fragment.
func (c *ClockFrameFragment) Validate() error {
	if c == nil {
		return errors.New("nil clock frame fragment")
	}
	if len(c.Filter) != 32 {
		return errors.New("invalid filter")
	}
	if c.Timestamp == 0 {
		return errors.New("invalid timestamp")
	}
	if n := len(c.FrameHash); n < 28 || n > 64 {
		return errors.New("invalid frame hash")
	}
	switch {
	case c.GetReedSolomon() != nil:
		if err := c.GetReedSolomon().Validate(); err != nil {
			return errors.Wrap(err, "reed-solomon encoding")
		}
	default:
		return errors.New("missing encoding")
	}
	if err := c.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*Ed448PublicKey)(nil)

// Validate checks the Ed448 public key.
func (e *Ed448PublicKey) Validate() error {
	if e == nil {
		return errors.New("nil Ed448 public key")
	}
	if len(e.KeyValue) != 57 {
		return errors.New("invalid Ed448 public key")
	}
	return nil
}

var _ ValidatableMessage = (*Ed448Signature)(nil)

// Validate checks the Ed448 signature.
func (e *Ed448Signature) Validate() error {
	if e == nil {
		return errors.New("nil Ed448 signature")
	}
	if err := e.PublicKey.Validate(); err != nil {
		return errors.Wrap(err, "public key")
	}
	if len(e.Signature) != 114 {
		return errors.New("invalid Ed448 signature")
	}
	return nil
}

var _ ValidatableMessage = (*ImplicitAccount)(nil)

// Validate checks the implicit account.
func (i *ImplicitAccount) Validate() error {
	if i == nil {
		return errors.New("nil implicit account")
	}
	// TODO: Validate ImplicitType.
	if len(i.Address) != 32 {
		return errors.New("invalid implicit account")
	}
	// TODO: Validate Domain.
	return nil
}

var _ ValidatableMessage = (*OriginatedAccountRef)(nil)

// Validate checks the originated account.
func (o *OriginatedAccountRef) Validate() error {
	if o == nil {
		return errors.New("nil originated account")
	}
	if len(o.Address) != 32 {
		return errors.New("invalid originated account")
	}
	return nil
}

var _ ValidatableMessage = (*AccountRef)(nil)

// Validate checks the account reference.
func (a *AccountRef) Validate() error {
	if a == nil {
		return errors.New("nil account reference")
	}
	switch {
	case a.GetImplicitAccount() != nil:
		if err := a.GetImplicitAccount().Validate(); err != nil {
			return errors.Wrap(err, "implicit account")
		}
	case a.GetOriginatedAccount() != nil:
		if err := a.GetOriginatedAccount().Validate(); err != nil {
			return errors.Wrap(err, "originated account")
		}
	default:
		return errors.New("invalid account reference")
	}
	return nil
}

var _ ValidatableMessage = (*CoinRef)(nil)

// Validate checks the coin reference.
func (c *CoinRef) Validate() error {
	if c == nil {
		return errors.New("nil coin reference")
	}
	if len(c.Address) != 32 {
		return errors.New("invalid coin reference")
	}
	return nil
}

var _ ValidatableMessage = (*AccountAllowanceRef)(nil)

// Validate checks the account allowance reference.
func (a *AccountAllowanceRef) Validate() error {
	if a == nil {
		return errors.New("nil account allowance reference")
	}
	if len(a.Address) != 32 {
		return errors.New("invalid account allowance reference")
	}
	return nil
}

var _ ValidatableMessage = (*CoinAllowanceRef)(nil)

// Validate checks the coin allowance reference.
func (c *CoinAllowanceRef) Validate() error {
	if c == nil {
		return errors.New("nil coin allowance reference")
	}
	if len(c.Address) != 32 {
		return errors.New("invalid coin allowance reference")
	}
	return nil
}

var _ ValidatableMessage = (*TokenRequest)(nil)

// Validate checks the token request.
func (t *TokenRequest) Validate() error {
	if t == nil {
		return errors.New("nil token request")
	}
	switch {
	case t.GetTransfer() != nil:
		return t.GetTransfer().Validate()
	case t.GetSplit() != nil:
		return t.GetSplit().Validate()
	case t.GetMerge() != nil:
		return t.GetMerge().Validate()
	case t.GetMint() != nil:
		return t.GetMint().Validate()
	case t.GetAnnounce() != nil:
		return t.GetAnnounce().Validate()
	case t.GetJoin() != nil:
		return t.GetJoin().Validate()
	case t.GetLeave() != nil:
		return t.GetLeave().Validate()
	case t.GetPause() != nil:
		return t.GetPause().Validate()
	case t.GetResume() != nil:
		return t.GetResume().Validate()
	default:
		return nil
	}
}

var _ ValidatableMessage = (*TransferCoinRequest)(nil)

// Validate checks the transfer coin request.
func (t *TransferCoinRequest) Validate() error {
	if t == nil {
		return errors.New("nil transfer coin request")
	}
	if err := t.ToAccount.Validate(); err != nil {
		return errors.Wrap(err, "to account")
	}
	// TODO: Validate RefundAccount.
	if err := t.OfCoin.Validate(); err != nil {
		return errors.Wrap(err, "of coin")
	}
	// TODO: Validate Expiry.
	// TODO: Validate AccountAllowance.
	// TODO: Validate CoinAllowance.
	if err := t.Signature.Validate(); err != nil {
		return errors.Wrap(err, "signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*SplitCoinRequest)(nil)

// Validate checks the split coin request.
func (t *SplitCoinRequest) Validate() error {
	if t == nil {
		return errors.New("nil split coin request")
	}
	if err := t.OfCoin.Validate(); err != nil {
		return errors.Wrap(err, "of coin")
	}
	if n := len(t.Amounts); n == 0 || n > 100 {
		return errors.New("invalid amounts")
	}
	for _, a := range t.Amounts {
		if n := len(a); n == 0 || n > 32 {
			return errors.New("invalid amount")
		}
	}
	// TODO: Validate AccountAllowance.
	// TODO: Validate CoinAllowance.
	if err := t.Signature.Validate(); err != nil {
		return errors.Wrap(err, "signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*MergeCoinRequest)(nil)

// Validate checks the merge coin request.
func (t *MergeCoinRequest) Validate() error {
	if t == nil {
		return errors.New("nil merge coin request")
	}
	if len(t.Coins) == 0 {
		return errors.New("invalid coins")
	}
	for _, c := range t.Coins {
		if err := c.Validate(); err != nil {
			return errors.Wrap(err, "coin")
		}
	}
	// TODO: Validate AccountAllowance.
	// TODO: Validate CoinAllowance.
	if err := t.Signature.Validate(); err != nil {
		return errors.Wrap(err, "signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*MintCoinRequest)(nil)

// Validate checks the mint coin request.
func (t *MintCoinRequest) Validate() error {
	if t == nil {
		return errors.New("nil mint coin request")
	}
	if len(t.Proofs) == 0 {
		return errors.New("invalid proofs")
	}
	// TODO: Validate AccountAllowance.
	if err := t.Signature.Validate(); err != nil {
		return errors.Wrap(err, "signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*AnnounceProverRequest)(nil)

// Validate checks the announce prover request.
func (t *AnnounceProverRequest) Validate() error {
	if t == nil {
		return errors.New("nil announce prover request")
	}
	if len(t.PublicKeySignaturesEd448) == 0 {
		return errors.New("invalid public key signatures")
	}
	for _, p := range t.PublicKeySignaturesEd448 {
		if err := p.Validate(); err != nil {
			return errors.Wrap(err, "public key signature")
		}
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*AnnounceProverJoin)(nil)

// Validate checks the announce prover join.
func (t *AnnounceProverJoin) Validate() error {
	if t == nil {
		return errors.New("nil announce prover join")
	}
	if len(t.Filter) != 32 {
		return errors.New("invalid filter")
	}
	if announce := t.Announce; announce != nil {
		if err := announce.Validate(); err != nil {
			return errors.Wrap(err, "announce")
		}
	}
	if err := t.PublicKeySignatureEd448.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*AnnounceProverLeave)(nil)

// Validate checks the announce prover leave.
func (t *AnnounceProverLeave) Validate() error {
	if t == nil {
		return errors.New("nil announce prover leave")
	}
	if len(t.Filter) != 32 {
		return errors.New("invalid filter")
	}
	if err := t.PublicKeySignatureEd448.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*AnnounceProverPause)(nil)

// Validate checks the announce prover pause.
func (t *AnnounceProverPause) Validate() error {
	if t == nil {
		return errors.New("nil announce prover pause")
	}
	if len(t.Filter) != 32 {
		return errors.New("invalid filter")
	}
	if err := t.PublicKeySignatureEd448.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

var _ ValidatableMessage = (*AnnounceProverResume)(nil)

// Validate checks the announce prover resume.
func (t *AnnounceProverResume) Validate() error {
	if t == nil {
		return errors.New("nil announce prover resume")
	}
	if len(t.Filter) != 32 {
		return errors.New("invalid filter")
	}
	if err := t.PublicKeySignatureEd448.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "signature")
	}
	return nil
}

// SignableED448Message is a message that can be signed.
type SignableED448Message interface {
	// SignED448 signs the message with the given key, modifying the message.
	// The message contents are expected to be valid - message
	// contents must be validated, or correctly constructed, before signing.
	SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error
}

func newED448Signature(publicKey, signature []byte) *Ed448Signature {
	return &Ed448Signature{
		PublicKey: &Ed448PublicKey{
			KeyValue: publicKey,
		},
		Signature: signature,
	}
}

var _ SignableED448Message = (*ClockFrameFragment)(nil)

// SignED448 signs the clock frame fragment with the given key.
func (c *ClockFrameFragment) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(c.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	c.PublicKeySignature = &ClockFrameFragment_PublicKeySignatureEd448{
		PublicKeySignatureEd448: newED448Signature(publicKey, signature),
	}
	return nil
}

var _ SignableED448Message = (*TransferCoinRequest)(nil)

// SignED448 signs the transfer coin request with the given key.
func (t *TransferCoinRequest) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.Signature = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*SplitCoinRequest)(nil)

// SignED448 signs the split coin request with the given key.
func (t *SplitCoinRequest) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.Signature = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*MergeCoinRequest)(nil)

// SignED448 signs the merge coin request with the given key.
func (t *MergeCoinRequest) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.Signature = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*MintCoinRequest)(nil)

// SignED448 signs the mint coin request with the given key.
func (t *MintCoinRequest) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.Signature = newED448Signature(publicKey, signature)
	return nil
}

type ED448SignHelper struct {
	PublicKey []byte
	Sign      func([]byte) ([]byte, error)
}

// SignED448 signs the announce prover request with the given keys.
func (t *AnnounceProverRequest) SignED448(helpers []ED448SignHelper) error {
	if len(helpers) == 0 {
		return errors.New("no keys")
	}
	payload := []byte{}
	primary := helpers[0]
	signatures := make([]*Ed448Signature, len(helpers))
	for i, k := range helpers[1:] {
		payload = append(payload, k.PublicKey...)
		signature, err := k.Sign(primary.PublicKey)
		if err != nil {
			return errors.Wrap(err, "sign")
		}
		signatures[i+1] = newED448Signature(k.PublicKey, signature)
	}
	signature, err := primary.Sign(payload)
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	signatures[0] = newED448Signature(primary.PublicKey, signature)
	t.PublicKeySignaturesEd448 = signatures
	return nil
}

var _ SignableED448Message = (*AnnounceProverJoin)(nil)

// SignED448 signs the announce prover join with the given key.
func (t *AnnounceProverJoin) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.PublicKeySignatureEd448 = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*AnnounceProverLeave)(nil)

// SignED448 signs the announce prover leave with the given key.
func (t *AnnounceProverLeave) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.PublicKeySignatureEd448 = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*AnnounceProverPause)(nil)

// SignED448 signs the announce prover pause with the given key.
func (t *AnnounceProverPause) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.PublicKeySignatureEd448 = newED448Signature(publicKey, signature)
	return nil
}

var _ SignableED448Message = (*AnnounceProverResume)(nil)

// SignED448 signs the announce prover resume with the given key.
func (t *AnnounceProverResume) SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error {
	signature, err := sign(t.signatureMessage())
	if err != nil {
		return errors.Wrap(err, "sign")
	}
	t.PublicKeySignatureEd448 = newED448Signature(publicKey, signature)
	return nil
}
