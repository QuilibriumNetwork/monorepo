// Package dkls23_ffi provides Go bindings for the DKLs23 threshold ECDSA protocol.
// This wraps the Rust dkls23 crate via uniffi-generated FFI bindings.
package dkls23_ffi

import (
	generated "source.quilibrium.com/quilibrium/monorepo/dkls23_ffi/generated/dkls23_ffi"
)

//go:generate ./generate.sh

// Re-export types from generated bindings
type (
	PartyMessage       = generated.PartyMessage
	DkgInitResult      = generated.DkgInitResult
	DkgRoundResult     = generated.DkgRoundResult
	DkgFinalResult     = generated.DkgFinalResult
	SignInitResult     = generated.SignInitResult
	SignRoundResult    = generated.SignRoundResult
	SignFinalResult    = generated.SignFinalResult
	RefreshInitResult  = generated.RefreshInitResult
	RefreshRoundResult = generated.RefreshRoundResult
	RefreshFinalResult = generated.RefreshFinalResult
	ResizeInitResult   = generated.ResizeInitResult
	ResizeRoundResult  = generated.ResizeRoundResult
	ResizeFinalResult  = generated.ResizeFinalResult
	RekeyResult        = generated.RekeyResult
	DeriveResult       = generated.DeriveResult
	EllipticCurve      = generated.EllipticCurve
)

// Elliptic curve constants
const (
	EllipticCurveSecp256k1 = generated.EllipticCurveSecp256k1
	EllipticCurveP256      = generated.EllipticCurveP256
)

// Init initializes the DKLs23 library. Call once before using other functions.
func Init() {
	generated.Init()
}

// ============================================
// DKG Functions
// ============================================

// DkgInit initializes a new distributed key generation session.
// partyID is the 1-indexed identifier for this party.
// threshold is the minimum number of parties needed to sign (t in t-of-n).
// totalParties is the total number of parties (n in t-of-n).
func DkgInit(partyID, threshold, totalParties uint32, curve EllipticCurve) DkgInitResult {
	return generated.DkgInit(partyID, threshold, totalParties, curve)
}

// DkgInitWithSessionId initializes a new DKG session with a shared session ID.
// All parties MUST use the same 32-byte sessionId for the DKG to succeed.
func DkgInitWithSessionId(partyID, threshold, totalParties uint32, sessionId []byte, curve EllipticCurve) DkgInitResult {
	return generated.DkgInitWithSessionId(partyID, threshold, totalParties, sessionId, curve)
}

// DkgRound1 processes DKG round 1, generating the broadcast commitment message.
func DkgRound1(sessionState []byte) DkgRoundResult {
	return generated.DkgRound1(sessionState)
}

// DkgRound2 processes DKG round 2 with received messages from other parties.
func DkgRound2(sessionState []byte, receivedMessages []PartyMessage) DkgRoundResult {
	return generated.DkgRound2(sessionState, receivedMessages)
}

// DkgRound3 processes DKG round 3 (verification and share computation).
func DkgRound3(sessionState []byte, receivedMessages []PartyMessage) DkgRoundResult {
	return generated.DkgRound3(sessionState, receivedMessages)
}

// DkgFinalize completes DKG and extracts the key share.
func DkgFinalize(sessionState []byte, receivedMessages []PartyMessage) DkgFinalResult {
	return generated.DkgFinalize(sessionState, receivedMessages)
}

// ============================================
// Signing Functions
// ============================================

// SignInit initializes a threshold signing session.
// keyShare is the party's key share from DKG.
// messageHash is the 32-byte hash of the message to sign.
// signerPartyIDs lists the party IDs participating in this signing session.
func SignInit(keyShare, messageHash []byte, signerPartyIDs []uint32) SignInitResult {
	return generated.SignInit(keyShare, messageHash, signerPartyIDs)
}

// SignInitWithSignId initializes a threshold signing session with a shared sign ID.
// All parties must use the same signId for a signing session to work.
func SignInitWithSignId(keyShare, messageHash []byte, signerPartyIDs []uint32, signId []byte) SignInitResult {
	return generated.SignInitWithSignId(keyShare, messageHash, signerPartyIDs, signId)
}

// SignRound1 processes signing round 1, generating nonce commitment.
func SignRound1(sessionState []byte) SignRoundResult {
	return generated.SignRound1(sessionState)
}

// SignRound2 processes signing round 2 with received nonce commitments.
func SignRound2(sessionState []byte, receivedMessages []PartyMessage) SignRoundResult {
	return generated.SignRound2(sessionState, receivedMessages)
}

// SignRound3 processes signing round 3 and produces broadcast messages.
func SignRound3(sessionState []byte, receivedMessages []PartyMessage) SignRoundResult {
	return generated.SignRound3(sessionState, receivedMessages)
}

// SignFinalize collects broadcasts from all parties and produces the final signature.
func SignFinalize(sessionState []byte, receivedMessages []PartyMessage) SignFinalResult {
	return generated.SignFinalize(sessionState, receivedMessages)
}

// ============================================
// Refresh Functions
// ============================================

// RefreshInit initializes a key share refresh session.
// This allows parties to generate new shares for the same key,
// invalidating old shares (proactive security).
func RefreshInit(keyShare []byte, partyID uint32) RefreshInitResult {
	return generated.RefreshInit(keyShare, partyID)
}

// RefreshInitWithRefreshId initializes a refresh session with a shared refresh ID.
// All parties must use the same refreshId for a refresh session to work.
func RefreshInitWithRefreshId(keyShare []byte, partyID uint32, refreshId []byte) RefreshInitResult {
	return generated.RefreshInitWithRefreshId(keyShare, partyID, refreshId)
}

// RefreshRound1 processes refresh round 1 (phase 1: generate polynomial fragments).
func RefreshRound1(sessionState []byte) RefreshRoundResult {
	return generated.RefreshRound1(sessionState)
}

// RefreshRound2 processes refresh round 2 (phase 2: process fragments, generate proofs).
func RefreshRound2(sessionState []byte, receivedMessages []PartyMessage) RefreshRoundResult {
	return generated.RefreshRound2(sessionState, receivedMessages)
}

// RefreshRound3 processes refresh round 3 (phase 3: process transmits).
func RefreshRound3(sessionState []byte, receivedMessages []PartyMessage) RefreshRoundResult {
	return generated.RefreshRound3(sessionState, receivedMessages)
}

// RefreshFinalize verifies proofs and produces the new key share.
func RefreshFinalize(sessionState []byte, receivedMessages []PartyMessage) RefreshFinalResult {
	return generated.RefreshFinalize(sessionState, receivedMessages)
}

// ============================================
// Resize Functions
// ============================================

// ResizeInit initializes a threshold resize session.
// This allows changing the threshold (t) and/or total parties (n).
func ResizeInit(keyShare []byte, partyID, newThreshold, newTotalParties uint32, newPartyIDs []uint32, curve EllipticCurve) ResizeInitResult {
	return generated.ResizeInit(keyShare, partyID, newThreshold, newTotalParties, newPartyIDs, curve)
}

// ResizeRound1 processes resize round 1.
func ResizeRound1(sessionState []byte) ResizeRoundResult {
	return generated.ResizeRound1(sessionState)
}

// ResizeRound2 processes resize round 2 and produces the new key share.
func ResizeRound2(sessionState []byte, receivedMessages []PartyMessage) ResizeFinalResult {
	return generated.ResizeRound2(sessionState, receivedMessages)
}

// ============================================
// Utility Functions
// ============================================

// RekeyFromSecret converts a full secret key into threshold shares.
// This is useful for migrating existing keys to threshold custody.
func RekeyFromSecret(secretKey []byte, threshold, totalParties uint32, curve EllipticCurve) RekeyResult {
	return generated.RekeyFromSecret(secretKey, threshold, totalParties, curve)
}

// DeriveChildShare derives a child key share using a BIP-32 derivation path.
func DeriveChildShare(keyShare []byte, derivationPath []uint32) DeriveResult {
	return generated.DeriveChildShare(keyShare, derivationPath)
}

// GetPublicKey extracts the public key from a key share.
func GetPublicKey(keyShare []byte) []byte {
	return generated.GetPublicKey(keyShare)
}

// ValidateKeyShare validates a key share's structure and parameters.
func ValidateKeyShare(keyShare []byte) bool {
	return generated.ValidateKeyShare(keyShare)
}

// ============================================
// Helper functions for error checking
// ============================================

// GetErrorMessage returns the error message from an optional string pointer.
// Returns empty string if the pointer is nil.
func GetErrorMessage(errMsg *string) string {
	if errMsg != nil {
		return *errMsg
	}
	return ""
}
