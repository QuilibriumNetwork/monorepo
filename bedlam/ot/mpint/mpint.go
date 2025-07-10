//
// mpint.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package mpint

import (
	"math/big"
)

// FromBytes creates a big.Int from the data.
func FromBytes(data []byte) *big.Int {
	return big.NewInt(0).SetBytes(data)
}

// Add adds two big.Int numbers and returns the result as a new
// big.Int.
func Add(a, b *big.Int) *big.Int {
	return big.NewInt(0).Add(a, b)
}

// Sub subtracts two big.Int numbers and returns the result as a new
// big.Int.
func Sub(a, b *big.Int) *big.Int {
	return big.NewInt(0).Sub(a, b)
}

// Exp computes x^y MOD m and returns the result as a new big.Int.
func Exp(x, y, m *big.Int) *big.Int {
	return big.NewInt(0).Exp(x, y, m)
}

// Mod computes x%y and returns the result as a new big.Int.
func Mod(x, y *big.Int) *big.Int {
	return big.NewInt(0).Mod(x, y)
}
