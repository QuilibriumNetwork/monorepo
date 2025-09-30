package schema

import (
	"fmt"

	"github.com/pkg/errors"
)

const (
	// Maximum order values for different encoding sizes
	MaxOrderSingleByte = 63
	MaxOrderTwoByte    = 4093
	MaxOrderThreeByte  = 262142
)

// OrderToKey converts an order value to a key suitable for tree storage.
// The key is encoded as follows:
// - Order 0-63: Single byte, shifted left by 2
// - Order 64-4093: Two bytes, shifted left by 4
// - Order 4094-262142: Three bytes, shifted left by 6
// - Order > 262142: Error
func OrderToKey(order int, maxOrder int) ([]byte, error) {
	if order < 0 {
		return nil, errors.New("order must be non-negative")
	}

	if maxOrder <= MaxOrderSingleByte {
		// Single byte encoding: order << 2
		return []byte{byte(order << 2)}, nil
	}

	if maxOrder <= MaxOrderTwoByte {
		// Two byte encoding: order << 4
		shifted := order << 4
		return []byte{
			byte(shifted >> 8),
			byte(shifted & 0xFF),
		}, nil
	}

	if maxOrder <= MaxOrderThreeByte {
		// Three byte encoding: order << 6
		shifted := order << 6
		return []byte{
			byte(shifted >> 16),
			byte((shifted >> 8) & 0xFF),
			byte(shifted & 0xFF),
		}, nil
	}

	return nil, errors.Wrap(
		fmt.Errorf(
			"order value %d exceeds maximum allowed value of %d",
			maxOrder,
			MaxOrderThreeByte,
		),
		"order to key",
	)
}

// KeyToOrder converts a key back to an order value.
// This is the reverse of OrderToKey.
func KeyToOrder(key []byte) (int, error) {
	if len(key) == 0 {
		return 0, errors.New("empty key")
	}

	switch len(key) {
	case 1:
		// Single byte encoding: order = key >> 2
		return int(key[0]) >> 2, nil

	case 2:
		// Two byte encoding: order = key >> 4
		value := (int(key[0]) << 8) | int(key[1])
		return value >> 4, nil

	case 3:
		// Three byte encoding: order = key >> 6
		value := (int(key[0]) << 16) | (int(key[1]) << 8) | int(key[2])
		return value >> 6, nil

	default:
		return 0, errors.Wrap(
			fmt.Errorf("invalid key length: %d", len(key)),
			"key to order",
		)
	}
}

// GetMaxOrderForDocument determines the maximum order value in a document's
// schema
func GetMaxOrderForDocument(tagsByClass map[string]map[string]*RDFTag) int {
	maxOrder := -1
	for _, classTags := range tagsByClass {
		for _, tag := range classTags {
			if tag.Order > maxOrder {
				maxOrder = tag.Order
			}
		}
	}
	return maxOrder
}

// GetPolySizeForMaxOrder returns the appropriate polynomial size for a given
// max order
func GetPolySizeForMaxOrder(maxOrder int) uint64 {
	if maxOrder <= MaxOrderSingleByte {
		return 64 // Current behavior
	}
	if maxOrder <= MaxOrderTwoByte {
		return 4096
	}
	if maxOrder <= MaxOrderThreeByte {
		return 262144
	}
	// Should not reach here due to validation
	return 262144
}
