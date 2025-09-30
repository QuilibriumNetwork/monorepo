package schema

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrderToKey(t *testing.T) {
	tests := []struct {
		name        string
		order       int
		expectedKey []byte
		expectError bool
	}{
		// Single byte encoding tests (0-63)
		{
			name:        "order 0",
			order:       0,
			expectedKey: []byte{0x00},
		},
		{
			name:        "order 1",
			order:       1,
			expectedKey: []byte{0x04}, // 1 << 2 = 4
		},
		{
			name:        "order 63",
			order:       63,
			expectedKey: []byte{0xFC}, // 63 << 2 = 252
		},
		// Two byte encoding tests (64-4093)
		{
			name:        "order 64",
			order:       64,
			expectedKey: []byte{0x04, 0x00}, // 64 << 4 = 1024 = 0x0400
		},
		{
			name:        "order 100",
			order:       100,
			expectedKey: []byte{0x06, 0x40}, // 100 << 4 = 1600 = 0x0640
		},
		{
			name:        "order 4093",
			order:       4093,
			expectedKey: []byte{0xFF, 0xD0}, // 4093 << 4 = 65488 = 0xFFD0
		},
		// Three byte encoding tests (4094-262142)
		{
			name:        "order 4094",
			order:       4094,
			expectedKey: []byte{0x03, 0xFF, 0x80}, // 4094 << 6 = 262016 = 0x03FF80
		},
		{
			name:        "order 10000",
			order:       10000,
			expectedKey: []byte{0x09, 0xC4, 0x00}, // 10000 << 6 = 640000 = 0x09C400
		},
		{
			name:        "order 262142",
			order:       262142,
			expectedKey: []byte{0xFF, 0xFF, 0x80}, // 262142 << 6 = 16777088 = 0xFFFF80
		},
		// Error cases
		{
			name:        "negative order",
			order:       -1,
			expectError: true,
		},
		{
			name:        "order exceeds maximum",
			order:       262143,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := OrderToKey(1, tt.order)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKey, key)
			}
		})
	}
}

func TestKeyToOrder(t *testing.T) {
	tests := []struct {
		name          string
		key           []byte
		expectedOrder int
		expectError   bool
	}{
		// Single byte decoding
		{
			name:          "single byte - order 0",
			key:           []byte{0x00},
			expectedOrder: 0,
		},
		{
			name:          "single byte - order 1",
			key:           []byte{0x04},
			expectedOrder: 1,
		},
		{
			name:          "single byte - order 63",
			key:           []byte{0xFC},
			expectedOrder: 63,
		},
		// Two byte decoding
		{
			name:          "two bytes - order 64",
			key:           []byte{0x04, 0x00},
			expectedOrder: 64,
		},
		{
			name:          "two bytes - order 100",
			key:           []byte{0x06, 0x40},
			expectedOrder: 100,
		},
		{
			name:          "two bytes - order 4093",
			key:           []byte{0xFF, 0xD0},
			expectedOrder: 4093,
		},
		// Three byte decoding
		{
			name:          "three bytes - order 4094",
			key:           []byte{0x03, 0xFF, 0x80},
			expectedOrder: 4094,
		},
		{
			name:          "three bytes - order 10000",
			key:           []byte{0x09, 0xC4, 0x00},
			expectedOrder: 10000,
		},
		{
			name:          "three bytes - order 262142",
			key:           []byte{0xFF, 0xFF, 0x80},
			expectedOrder: 262142,
		},
		// Error cases
		{
			name:        "empty key",
			key:         []byte{},
			expectError: true,
		},
		{
			name:        "invalid key length",
			key:         []byte{0x01, 0x02, 0x03, 0x04},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order, err := KeyToOrder(tt.key)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedOrder, order)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	// Test round-trip conversion for various order values
	testOrders := []int{
		0, 1, 10, 63, // Single byte range
		64, 100, 1000, 4093, // Two byte range
		4094, 10000, 100000, 262142, // Three byte range
	}

	for _, order := range testOrders {
		t.Run(fmt.Sprintf("order_%d", order), func(t *testing.T) {
			key, err := OrderToKey(1, order)
			require.NoError(t, err)

			decodedOrder, err := KeyToOrder(key)
			require.NoError(t, err)

			assert.Equal(t, order, decodedOrder)
		})
	}
}

func TestGetMaxOrderForDocument(t *testing.T) {
	tagsByClass := map[string]map[string]*RDFTag{
		"Class1": {
			"field1": &RDFTag{Order: 5},
			"field2": &RDFTag{Order: 10},
		},
		"Class2": {
			"field1": &RDFTag{Order: 100},
			"field2": &RDFTag{Order: 50},
		},
		"Class3": {
			"field1": &RDFTag{Order: 262142},
		},
	}

	maxOrder := GetMaxOrderForDocument(tagsByClass)
	assert.Equal(t, 262142, maxOrder)
}

func TestGetPolySizeForMaxOrder(t *testing.T) {
	tests := []struct {
		maxOrder     int
		expectedSize uint64
	}{
		{0, 64},
		{63, 64},
		{64, 4096},
		{4093, 4096},
		{4094, 262144},
		{262142, 262144},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("maxOrder_%d", tt.maxOrder), func(t *testing.T) {
			size := GetPolySizeForMaxOrder(tt.maxOrder)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}
