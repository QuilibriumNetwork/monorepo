package token_test

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/shopspring/decimal"
	"source.quilibrium.com/quilibrium/monorepo/client/cmd/token"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		totalAmount string
		amounts     [][]byte
		payload     []byte
		expectError bool
	}{
		{
			name:        "Valid split - specified amounts",
			args:        []string{"0x1234", "0.5", "0.25", "0.25"},
			totalAmount: "1.0",
			amounts: [][]byte{
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 238, 107, 40, 0},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 53, 148, 0},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 53, 148, 0},
			},
			payload: []byte{
				115, 112, 108, 105, 116,
				18, 52,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 238, 107, 40, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 53, 148, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 53, 148, 0,
			},
			expectError: false,
		},
		{
			name:        "Invalid split - amounts do not sum to the total amount of the coin",
			args:        []string{"0x1234", "0.5", "0.25"},
			totalAmount: "1.0",
			amounts:     [][]byte{},
			payload:     []byte{},
			expectError: true,
		},
		{
			name:        "Invalid split - amounts exceed total amount of the coin",
			args:        []string{"0x1234", "0.5", "1"},
			totalAmount: "1.0",
			amounts:     [][]byte{},
			payload:     []byte{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("split")
			coinaddrHex, _ := strings.CutPrefix(tc.args[0], "0x")
			coinaddr, err := hex.DecodeString(coinaddrHex)
			if err != nil {
				panic(err)
			}
			payload = append(payload, coinaddr...)

			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			totalAmount, _ := decimal.NewFromString(tc.totalAmount)
			totalAmount = totalAmount.Mul(decimal.NewFromBigInt(conversionFactor, 0))

			amounts := [][]byte{}

			if tc.expectError {
				_, _, err = token.Split(tc.args[1:], amounts, payload, totalAmount.BigInt())
				if err == nil {
					t.Errorf("want error for invalid split, got nil")
				}
			} else {
				amounts, payload, err = token.Split(tc.args[1:], amounts, payload, totalAmount.BigInt())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(tc.amounts, amounts) {
					t.Errorf("expected amounts: %v, got: %v", tc.amounts, amounts)
				}
				if !reflect.DeepEqual(tc.payload, payload) {
					t.Errorf("expected payloads: %v, got: %v", tc.payload, payload)
				}
			}
		})
	}
}

func TestSplitParts(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		parts       int
		totalAmount string
		amounts     [][]byte
		payload     []byte
	}{
		{
			name:        "Valid split - into parts",
			args:        []string{"0x1234"},
			parts:       3,
			totalAmount: "1.0",
			amounts: [][]byte{
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			},
			payload: []byte{
				115, 112, 108, 105, 116,
				18, 52,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 158, 242, 26, 170,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("split")
			coinaddrHex, _ := strings.CutPrefix(tc.args[0], "0x")
			coinaddr, err := hex.DecodeString(coinaddrHex)
			if err != nil {
				panic(err)
			}
			payload = append(payload, coinaddr...)

			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			totalAmount, _ := decimal.NewFromString(tc.totalAmount)
			totalAmount = totalAmount.Mul(decimal.NewFromBigInt(conversionFactor, 0))

			amounts := [][]byte{}

			amounts, payload = token.SplitIntoParts(amounts, payload, totalAmount.BigInt(), tc.parts)
			if !reflect.DeepEqual(tc.amounts, amounts) {
				t.Errorf("expected amounts: %v, got: %v", tc.amounts, amounts)
			}
			if !reflect.DeepEqual(tc.payload, payload) {
				t.Errorf("expected payloads: %v, got: %v", tc.payload, payload)
			}
		})
	}
}

func TestSplitIntoPartsAmount(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		parts       int
		partAmount  string
		totalAmount string
		amounts     [][]byte
		payload     []byte
		expectError bool
	}{
		{
			name:        "Valid split - into parts of specified amount",
			args:        []string{"0x1234"},
			parts:       2,
			partAmount:  "0.35",
			totalAmount: "1.0",
			amounts: [][]byte{
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 228, 156, 0},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 228, 156, 0},
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 143, 13, 24, 0},
			},
			payload: []byte{
				115, 112, 108, 105, 116,
				18, 52,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 228, 156, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 228, 156, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 143, 13, 24, 0,
			},
			expectError: false,
		},
		{
			name:        "Invalid split - amounts exceed total amount of the coin",
			args:        []string{"0x1234"},
			parts:       3,
			partAmount:  "0.5",
			totalAmount: "1.0",
			amounts:     [][]byte{},
			payload:     []byte{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("split")
			coinaddrHex, _ := strings.CutPrefix(tc.args[0], "0x")
			coinaddr, err := hex.DecodeString(coinaddrHex)
			if err != nil {
				panic(err)
			}
			payload = append(payload, coinaddr...)

			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			totalAmount, _ := decimal.NewFromString(tc.totalAmount)
			totalAmount = totalAmount.Mul(decimal.NewFromBigInt(conversionFactor, 0))

			amounts := [][]byte{}

			if tc.expectError {
				_, _, err = token.SplitIntoPartsAmount(amounts, payload, totalAmount.BigInt(), tc.parts, tc.partAmount)
				if err == nil {
					t.Errorf("want error for invalid split, got nil")
				}
			} else {
				amounts, payload, err = token.SplitIntoPartsAmount(amounts, payload, totalAmount.BigInt(), tc.parts, tc.partAmount)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(tc.amounts, amounts) {
					t.Errorf("expected amounts: %v, got: %v", tc.amounts, amounts)
				}
				if !reflect.DeepEqual(tc.payload, payload) {
					t.Errorf("expected payloads: %v, got: %v", tc.payload, payload)
				}
			}
		})
	}
}
