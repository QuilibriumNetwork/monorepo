//
// Copyright Quilibrium, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/math/fp448"
	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/internal"
)

type ScalarEd448 struct {
	value *goldilocks.Scalar
}

type PointEd448 struct {
	value *goldilocks.Point
}

var gscOne = goldilocks.Scalar{
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

var ed448Order = goldilocks.Scalar{
	0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
	0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
	0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
	0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
}

func (s *ScalarEd448) Random(reader io.Reader) Scalar {
	if reader == nil {
		return nil
	}
	var seed [57]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarEd448) Hash(bytes []byte) Scalar {
	raw := [114]byte{}
	h := sha3.NewShake256()
	_, _ = h.Write(bytes)
	_, _ = h.Read(raw[:])
	value := &goldilocks.Scalar{}
	raw[0] &= 0xFC
	raw[55] |= 0x80
	raw[56] = 0x00
	value.FromBytes(raw[:57])

	return &ScalarEd448{value}
}

func (s *ScalarEd448) Zero() Scalar {
	return &ScalarEd448{
		value: &goldilocks.Scalar{},
	}
}

func (s *ScalarEd448) One() Scalar {
	value := &goldilocks.Scalar{}
	value.FromBytes(gscOne[:])
	return &ScalarEd448{value}
}

func (s *ScalarEd448) IsZero() bool {
	i := byte(0)
	for _, b := range s.value {
		i |= b
	}
	return i == 0
}

func (s *ScalarEd448) IsOne() bool {
	data := s.value
	i := byte(0)
	for j := 1; j < len(data); j++ {
		i |= data[j]
	}
	return i == 0 && data[0] == 1
}

func (s *ScalarEd448) IsOdd() bool {
	return s.value[0]&1 == 1
}

func (s *ScalarEd448) IsEven() bool {
	return s.value[0]&1 == 0
}

func (s *ScalarEd448) New(input int) Scalar {
	var data [56]byte
	i := input
	if input < 0 {
		i = -input
	}

	data[0] = byte(i)
	data[1] = byte(i >> 8)
	data[2] = byte(i >> 16)
	data[3] = byte(i >> 24)
	value := &goldilocks.Scalar{}
	value.FromBytes(data[:])

	if input < 0 {
		value.Neg()
	}

	return &ScalarEd448{
		value,
	}
}

func (s *ScalarEd448) Cmp(rhs Scalar) int {
	r := s.Sub(rhs)
	if r != nil && r.IsZero() {
		return 0
	} else {
		return -2
	}
}

func (s *ScalarEd448) Square() Scalar {
	value := &goldilocks.Scalar{}
	value.Mul(s.value, s.value)
	return &ScalarEd448{value}
}

func (s *ScalarEd448) Double() Scalar {
	value := &goldilocks.Scalar{}
	value.Add(s.value, s.value)
	return &ScalarEd448{value}
}

func (s *ScalarEd448) Invert() (Scalar, error) {
	ret := new(big.Int)
	order := new(big.Int)
	buf := internal.ReverseScalarBytes(s.value[:])
	orderBuf := internal.ReverseScalarBytes(ed448Order[:])
	ret.SetBytes(buf)
	order.SetBytes(orderBuf)
	value := &goldilocks.Scalar{}
	ret = ret.ModInverse(ret, order)
	value.FromBytes(internal.ReverseScalarBytes(ret.Bytes()))
	return &ScalarEd448{value}, nil
}

func (s *ScalarEd448) Sqrt() (Scalar, error) {
	return nil, errors.New("not supported")
}

func (s *ScalarEd448) Cube() Scalar {
	value := &goldilocks.Scalar{}
	value.Mul(s.value, s.value)
	value.Mul(value, s.value)
	return &ScalarEd448{value}
}

func (s *ScalarEd448) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarEd448)
	if ok {
		value := &goldilocks.Scalar{}
		value.Add(s.value, r.value)
		return &ScalarEd448{value}
	} else {
		return nil
	}
}

func (s *ScalarEd448) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarEd448)
	if ok {
		value := &goldilocks.Scalar{}
		value.Sub(s.value, r.value)
		return &ScalarEd448{value}
	} else {
		return nil
	}
}

func (s *ScalarEd448) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarEd448)
	if ok {
		value := &goldilocks.Scalar{}
		value.Mul(s.value, r.value)
		return &ScalarEd448{value}
	} else {
		return nil
	}
}

func (s *ScalarEd448) MulAdd(y, z Scalar) Scalar {
	yy, ok := y.(*ScalarEd448)
	if !ok {
		return nil
	}
	zz, ok := z.(*ScalarEd448)
	if !ok {
		return nil
	}

	value := &goldilocks.Scalar{}
	value.Mul(s.value, yy.value)
	value.Add(value, zz.value)
	return &ScalarEd448{value}
}

func (s *ScalarEd448) Div(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarEd448)
	if ok {
		value, err := r.Invert()
		if err != nil {
			return nil
		}
		i, _ := value.(*ScalarEd448)
		i.value.Mul(i.value, s.value)
		return &ScalarEd448{value: i.value}
	} else {
		return nil
	}
}

func (s *ScalarEd448) Neg() Scalar {
	value := &goldilocks.Scalar{}
	copy(value[:], s.value[:])
	value.Neg()
	return &ScalarEd448{value}
}

func (s *ScalarEd448) SetBigInt(x *big.Int) (Scalar, error) {
	if x == nil {
		return nil, fmt.Errorf("invalid value")
	}

	order := new(big.Int)
	orderBuf := internal.ReverseScalarBytes(ed448Order[:])
	order.SetBytes(orderBuf)
	var v big.Int
	buf := v.Mod(x, order).Bytes()
	var rBuf [56]byte
	copy(rBuf[:], internal.ReverseScalarBytes(buf))
	value := &goldilocks.Scalar{}
	value.FromBytes(rBuf[:])
	return &ScalarEd448{value}, nil
}

func (s *ScalarEd448) BigInt() *big.Int {
	var ret big.Int
	buf := internal.ReverseScalarBytes(s.value[:])
	return ret.SetBytes(buf)
}

func (s *ScalarEd448) Bytes() []byte {
	return s.value[:]
}

// SetBytes takes input a 56-byte long array and returns a Ed448 scalar.
// The input must be 56-byte long and must be a reduced bytes.
func (s *ScalarEd448) SetBytes(input []byte) (Scalar, error) {
	if len(input) != 56 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := &goldilocks.Scalar{}
	value.FromBytes(input[:])

	return &ScalarEd448{value}, nil
}

// SetBytesWide takes input a 112-byte long byte array, reduce it and return an
// Ed448 scalar. If bytes is not of the right length, it returns nil and an
// error
func (s *ScalarEd448) SetBytesWide(bytes []byte) (Scalar, error) {
	if len(bytes) != 56 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	value := &goldilocks.Scalar{}
	value.FromBytes(bytes[:])

	return &ScalarEd448{value}, nil
}

// This function takes an input x and sets s = x, where x is a 56-byte
// little-endian encoding of s, then it returns the corresponding Ed448 scalar.
// If the input is not a canonical encoding of s, it returns nil and an error.
func (s *ScalarEd448) SetBytesCanonical(bytes []byte) (Scalar, error) {
	return s.SetBytes(bytes)
}

func (s *ScalarEd448) Point() Point {
	return new(PointEd448).Identity()
}

func (s *ScalarEd448) Clone() Scalar {
	value := &goldilocks.Scalar{}
	value.FromBytes(s.value[:])
	return &ScalarEd448{value}
}

func (s *ScalarEd448) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarEd448) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarEd448)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarEd448) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarEd448) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarEd448)
	if !ok {
		return fmt.Errorf("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarEd448) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarEd448) UnmarshalJSON(input []byte) error {
	sc, err := scalarUnmarshalJson(input)
	if err != nil {
		return err
	}
	S, ok := sc.(*ScalarEd448)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *PointEd448) Random(reader io.Reader) Point {
	var seed [114]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *PointEd448) Hash(bytes []byte) Point {
	hashBytes := make([]byte, 114)
	h := sha3.NewShake256()
	_, _ = h.Write(bytes)
	_, _ = h.Read(hashBytes[:])
	value := &goldilocks.Scalar{}
	hashBytes[0] &= 0xFC
	hashBytes[55] |= 0x80
	hashBytes[56] = 0x00
	value.FromBytes(hashBytes[:57])
	point := (goldilocks.Curve{}).ScalarBaseMult(value)
	return &PointEd448{value: point}
}

func (p *PointEd448) Identity() Point {
	return &PointEd448{
		value: (goldilocks.Curve{}).Identity(),
	}
}

func (p *PointEd448) Generator() Point {
	return &PointEd448{
		value: (goldilocks.Curve{}).Generator(),
	}
}

func (p *PointEd448) IsIdentity() bool {
	return p.Equal(p.Identity())
}

func (p *PointEd448) IsNegative() bool {
	// Negative points don't really exist in Ed448
	return false
}

func (p *PointEd448) IsOnCurve() bool {
	err := (goldilocks.Curve{}).Identity().UnmarshalBinary(
		p.ToAffineCompressed(),
	)
	return err == nil
}

func (p *PointEd448) Double() Point {
	value, err := p.value.MarshalBinary()
	if err != nil {
		return nil
	}

	clone := &goldilocks.Point{}
	if err := clone.UnmarshalBinary(value); err != nil {
		return nil
	}

	clone.Double()

	return &PointEd448{value: clone}
}

func (p *PointEd448) Scalar() Scalar {
	return new(ScalarEd448).Zero()
}

func (p *PointEd448) Neg() Point {
	value, err := p.value.MarshalBinary()
	if err != nil {
		return nil
	}

	clone := &goldilocks.Point{}
	if err := clone.UnmarshalBinary(value); err != nil {
		return nil
	}

	clone.Neg()

	return &PointEd448{value: clone}
}

func (p *PointEd448) Add(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointEd448)
	if ok {
		value, err := p.value.MarshalBinary()
		if err != nil {
			return nil
		}

		clone := &goldilocks.Point{}
		if err := clone.UnmarshalBinary(value); err != nil {
			return nil
		}

		clone.Add(r.value)

		return &PointEd448{value: clone}
	} else {
		return nil
	}
}

func (p *PointEd448) Sub(rhs Point) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*PointEd448)
	if ok {
		value, err := r.value.MarshalBinary()
		if err != nil {
			return nil
		}

		clone := &goldilocks.Point{}
		if err := clone.UnmarshalBinary(value); err != nil {
			return nil
		}

		clone.Neg()

		clone.Add(p.value)

		return &PointEd448{value: clone}
	} else {
		return nil
	}
}

func (p *PointEd448) Mul(rhs Scalar) Point {
	if rhs == nil {
		return nil
	}
	r, ok := rhs.(*ScalarEd448)
	if ok {
		value, err := p.value.MarshalBinary()
		if err != nil {
			return nil
		}

		clone := &goldilocks.Point{}
		if err := clone.UnmarshalBinary(value); err != nil {
			return nil
		}

		clone = (goldilocks.Curve{}).ScalarMult(r.value, clone)

		return &PointEd448{value: clone}
	} else {
		return nil
	}
}

func (p *PointEd448) Equal(rhs Point) bool {
	r, ok := rhs.(*PointEd448)
	if ok {
		return p.value.IsEqual(r.value)
	} else {
		return false
	}
}

func (p *PointEd448) Set(x, y *big.Int) (Point, error) {
	// check is identity
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	if (xx | yy) == 1 {
		return p.Identity(), nil
	}

	xElem := &fp448.Elt{}
	yElem := &fp448.Elt{}
	copy(xElem[:], internal.ReverseScalarBytes(x.Bytes()))
	copy(yElem[:], internal.ReverseScalarBytes(y.Bytes()))

	point, err := goldilocks.FromAffine(xElem, yElem)
	if err != nil {
		return nil, err
	}
	return &PointEd448{value: point}, nil
}

func (p *PointEd448) ToAffineCompressed() []byte {
	affineCompressed, err := p.value.MarshalBinary()
	if err != nil {
		return nil
	}

	return affineCompressed
}

func (p *PointEd448) ToAffineUncompressed() []byte {
	x, y := p.value.ToAffine()
	var out [112]byte
	copy(out[:56], x[:])
	copy(out[56:], y[:])
	return out[:]
}

func (p *PointEd448) FromAffineCompressed(inBytes []byte) (Point, error) {
	pt := (&goldilocks.Point{})
	err := pt.UnmarshalBinary(inBytes)

	if err != nil {
		return nil, err
	}

	return &PointEd448{value: pt}, nil
}

func (p *PointEd448) FromAffineUncompressed(inBytes []byte) (Point, error) {
	if len(inBytes) != 112 {
		return nil, fmt.Errorf("invalid byte sequence")
	}

	x := &fp448.Elt{}
	copy(x[:], inBytes[:56])
	y := &fp448.Elt{}
	copy(y[:], inBytes[56:])

	value, err := goldilocks.FromAffine(x, y)
	if err != nil {
		return nil, err
	}
	return &PointEd448{value}, nil
}

func (p *PointEd448) CurveName() string {
	return ED448Name
}

func (p *PointEd448) SumOfProducts(points []Point, scalars []Scalar) Point {
	// Unfortunately the primitives don't have have multi-scalar mult
	// implementation so we're left to do it the slow way
	nScalars := make([]*ScalarEd448, len(scalars))
	nPoints := make([]*PointEd448, len(points))
	for i, sc := range scalars {
		s, ok := sc.(*ScalarEd448)
		if !ok {
			return nil
		}
		nScalars[i] = s
	}
	for i, pt := range points {
		pp, ok := pt.(*PointEd448)
		if !ok {
			return nil
		}
		nPoints[i] = pp
	}

	accum := p.Identity().(*PointEd448)
	for i, p := range nPoints {
		s := nScalars[i]
		accum = accum.Add(p.Mul(s)).(*PointEd448)
	}

	return &PointEd448{value: accum.value}
}

func (p *PointEd448) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointEd448) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointEd448)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointEd448) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointEd448) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointEd448)
	if !ok {
		return fmt.Errorf("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointEd448) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointEd448) UnmarshalJSON(input []byte) error {
	pt, err := pointUnmarshalJson(input)
	if err != nil {
		return err
	}
	P, ok := pt.(*PointEd448)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	p.value = P.value
	return nil
}
