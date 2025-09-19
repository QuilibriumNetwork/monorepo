package time

import (
	"bytes"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func computeAppPoseidonHash(data []byte) []byte {
	// Compute Poseidon hash of the data
	h, _ := poseidon.HashBytes(data)
	return h.FillBytes(make([]byte, 32))
}

func isEqualAppFrame(a, b *protobufs.AppShardFrame) bool {
	// Compare all fields except signatures
	return bytes.Equal(a.Header.Address, b.Header.Address) &&
		a.Header.FrameNumber == b.Header.FrameNumber &&
		a.Header.Timestamp == b.Header.Timestamp &&
		a.Header.Difficulty == b.Header.Difficulty &&
		bytes.Equal(a.Header.Output, b.Header.Output) &&
		bytes.Equal(a.Header.ParentSelector, b.Header.ParentSelector) &&
		bytes.Equal(a.Header.Prover, b.Header.Prover)
}

// hasOverlappingAppBits checks if two frames have overlapping bits in their BLS
// signature bitmasks. This indicates equivocation - same signers signing
// different frames at the same height.
func hasOverlappingAppBits(a, b *protobufs.AppShardFrame) bool {
	if a.Header.PublicKeySignatureBls48581 == nil ||
		b.Header.PublicKeySignatureBls48581 == nil {
		return false
	}

	aBitmask := a.Header.PublicKeySignatureBls48581.Bitmask
	bBitmask := b.Header.PublicKeySignatureBls48581.Bitmask

	// Ensure bitmasks are the same length
	maxLen := len(aBitmask)
	if len(bBitmask) > maxLen {
		maxLen = len(bBitmask)
	}

	// Check for any overlapping bits
	for i := 0; i < maxLen; i++ {
		var aByte, bByte byte
		if i < len(aBitmask) {
			aByte = aBitmask[i]
		}
		if i < len(bBitmask) {
			bByte = bBitmask[i]
		}

		// If any bit position is set in both bitmasks, we have overlap
		if aByte&bByte != 0 {
			return true
		}
	}

	return false
}

func isEqualGlobalFrame(a, b *protobufs.GlobalFrame) bool {
	// Compare all fields except signatures
	return a.Header.FrameNumber == b.Header.FrameNumber &&
		a.Header.Timestamp == b.Header.Timestamp &&
		a.Header.Difficulty == b.Header.Difficulty &&
		bytes.Equal(a.Header.Output, b.Header.Output) &&
		bytes.Equal(a.Header.ParentSelector, b.Header.ParentSelector)
}

func computeGlobalPoseidonHash(data []byte) []byte {
	h, _ := poseidon.HashBytes(data)
	return h.FillBytes(make([]byte, 32))
}

// hasOverlappingBits checks if two frames have overlapping bits in their BLS
// signature bitmasks. This indicates equivocation - same signers signing
// different frames at the same height.
func hasOverlappingBits(a, b *protobufs.GlobalFrame) bool {
	if a.Header.PublicKeySignatureBls48581 == nil ||
		b.Header.PublicKeySignatureBls48581 == nil {
		return false
	}

	aBitmask := a.Header.PublicKeySignatureBls48581.Bitmask
	bBitmask := b.Header.PublicKeySignatureBls48581.Bitmask

	// Ensure bitmasks are the same length
	maxLen := len(aBitmask)
	if len(bBitmask) > maxLen {
		maxLen = len(bBitmask)
	}

	// Check for any overlapping bits
	for i := 0; i < maxLen; i++ {
		var aByte, bByte byte
		if i < len(aBitmask) {
			aByte = aBitmask[i]
		}
		if i < len(bBitmask) {
			bByte = bBitmask[i]
		}

		// If any bit position is set in both bitmasks, we have overlap
		if aByte&bByte != 0 {
			return true
		}
	}

	return false
}

// countBits counts the number of set bits in a BLS signature
func countBits(sig *protobufs.BLS48581AggregateSignature) int {
	if sig == nil {
		return 0
	}

	count := 0
	for _, b := range sig.Bitmask {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				count++
			}
		}
	}
	return count
}
