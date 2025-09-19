package difficulty

import (
	"math"
)

// AsertDifficultyAdjuster implements DifficultyAdjuster using the ASERTi3-2d
// algorithm, modified to target the VDF difficulty as the variable instead of
// difficulty bits. ASERTi3-2d is sourced from BCH:
//
//	https://reference.cash/protocol/forks/2020-11-15-asert
//
// Choice of the algorithm is motivated by similar intentions as BCH's proposal:
//   - reduce oscillation of difficulty rate
//   - reduce reward differential between dedicated nodes and sporadic nodes for
//     active timeframes
//   - increase precision of target frame times
//
// This algorithm intentionally approximates the cubic polynomial with integer
// arithmetic because the accuracy loss is negligible and ensures different
// architectures will not have subtle issues due to floating point arithmetic.
type AsertDifficultyAdjuster struct {
	anchorFrameNumber uint64
	anchorParentTime  int64
	anchorDifficulty  uint32
}

const (
	IDEAL_FRAME_TIME = 10000   // 10s in millis
	HALF_LIFE        = 7200000 // 2h in millis
)

func NewAsertDifficultyAdjuster(
	anchorFrameNumber uint64,
	anchorParentTime int64,
	anchorDifficulty uint32,
) *AsertDifficultyAdjuster {
	return &AsertDifficultyAdjuster{
		anchorFrameNumber,
		anchorParentTime,
		anchorDifficulty,
	}
}

func (a *AsertDifficultyAdjuster) GetNextDifficulty(
	currentFrameNumber uint64,
	currentTime int64,
) uint64 {
	const radix = 1 << 16 // Q16 fixed point

	// Ensure valid difficulty
	if a.anchorDifficulty == 0 {
		return 50000
	}

	// Compute height and time difference
	frameNumberDelta := int64(currentFrameNumber - a.anchorFrameNumber)
	timeDelta := currentTime - a.anchorParentTime

	// Calculate exponent as fixed-point Q16
	exponent := -((timeDelta - IDEAL_FRAME_TIME*(frameNumberDelta+1)) * radix) /
		HALF_LIFE

	// Decompose into integer and fractional parts
	shifts := exponent >> 16
	frac := uint16(exponent & 0xFFFF)

	// Compute exponential adjustment factor:
	// factor = 2^(frac/65536.0) approximated by polynomial
	factor := uint64(65536) + ((195766423245049*uint64(frac) +
		971821376*uint64(frac)*uint64(frac) +
		5127*uint64(frac)*uint64(frac)*uint64(frac) +
		(1 << 47)) >> 48)

	// Apply factor
	scaled := uint64(a.anchorDifficulty) * factor

	// Apply shift by 2^shifts and divide by 65536
	if shifts < 0 {
		scaled >>= uint(-shifts)
	} else {
		if shifts > 48 && a.anchorDifficulty > 0 {
			// Prevent overflow (note: Go's uint64 * uint64 overflow wraps silently)
			return math.MaxUint64
		}
		scaled <<= uint(shifts)
	}

	// Final right shift (division by 65536)
	scaled >>= 16

	// Clamp to uint64 max - the minimum check is mandatory but the maximum check
	// will obviously never fire, it exists only as a reference comment on how we
	// should handle future scaling when we start to get into subsequent
	// generations, the above will need to turn into big.Int.
	if scaled < 50000 {
		return 50000
	}

	// if scaled > math.MaxUint64 {
	// 	return math.MaxUint64
	// }

	return scaled
}
