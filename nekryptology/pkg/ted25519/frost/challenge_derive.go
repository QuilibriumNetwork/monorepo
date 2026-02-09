//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"crypto/sha512"
	"math/big"

	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type ChallengeDerive interface {
	DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error)
}

type Ed25519ChallengeDeriver struct{}

func (ed Ed25519ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	h := sha512.New()
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)
	return new(curves.ScalarEd25519).SetBytesWide(h.Sum(nil))
}

// Ed448ChallengeDeriver implements ChallengeDerive for Ed448 curves
// Ed448 uses SHAKE256 for hashing per RFC 8032
type Ed448ChallengeDeriver struct{}

func (ed Ed448ChallengeDeriver) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	// Ed448 challenge derivation per RFC 8032:
	// SHAKE256(dom4(0, "") || R || A || M, 114) reduced mod L
	//
	// dom4(phflag, context) = "SigEd448" || octet(phflag) || octet(len(context)) || context
	// For pure Ed448 (no prehash, empty context): dom4(0, "") = "SigEd448" || 0x00 || 0x00

	h := sha3.NewShake256()

	// Write dom4 prefix for Ed448
	_, _ = h.Write([]byte("SigEd448"))
	_, _ = h.Write([]byte{0x00}) // phflag = 0 (not prehashed)
	_, _ = h.Write([]byte{0x00}) // context length = 0

	// Write R || A || M
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)

	// Read 114 bytes (2 * 57 = 114, matching circl's hashSize)
	raw := [114]byte{}
	_, _ = h.Read(raw[:])

	// Convert little-endian bytes to big.Int for proper modular reduction
	// The hash output is in little-endian format
	reversed := make([]byte, 114)
	for i := 0; i < 114; i++ {
		reversed[113-i] = raw[i]
	}
	hashInt := new(big.Int).SetBytes(reversed)

	// SetBigInt performs proper modular reduction by the group order
	return new(curves.ScalarEd448).SetBigInt(hashInt)
}
