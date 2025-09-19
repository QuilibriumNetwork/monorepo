//
// label.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package ot

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Wire implements a wire with 0 and 1 labels.
type Wire struct {
	L0 Label
	L1 Label
}

func (w Wire) String() string {
	return fmt.Sprintf("%s/%s", w.L0, w.L1)
}

// Label implements a 128 bit wire label.
type Label struct {
	D0 uint64
	D1 uint64
}

// LabelData contains lable data as byte array.
type LabelData [16]byte

func (l Label) String() string {
	return fmt.Sprintf("%016x%016x", l.D0, l.D1)
}

// Equal test if the labels are equal.
func (l Label) Equal(o Label) bool {
	return l.D0 == o.D0 && l.D1 == o.D1
}

// NewLabel creates a new random label.
func NewLabel(rand io.Reader) (Label, error) {
	var buf LabelData
	var label Label

	if _, err := rand.Read(buf[:]); err != nil {
		return label, err
	}
	label.SetData(&buf)
	return label, nil
}

// NewTweak creates a new label from the tweak value.
func NewTweak(tweak uint32) Label {
	return Label{
		D1: uint64(tweak),
	}
}

// S tests the label's S bit.
func (l Label) S() bool {
	return (l.D0 & 0x8000000000000000) != 0
}

// SetS sets the label's S bit.
func (l *Label) SetS(set bool) {
	if set {
		l.D0 |= 0x8000000000000000
	} else {
		l.D0 &= 0x7fffffffffffffff
	}
}

// Mul2 multiplies the label by 2.
func (l *Label) Mul2() {
	l.D0 <<= 1
	l.D0 |= (l.D1 >> 63)
	l.D1 <<= 1
}

// Mul4 multiplies the label by 4.
func (l *Label) Mul4() {
	l.D0 <<= 2
	l.D0 |= (l.D1 >> 62)
	l.D1 <<= 2
}

// Xor xors the label with the argument label.
func (l *Label) Xor(o Label) {
	l.D0 ^= o.D0
	l.D1 ^= o.D1
}

// GetData gets the labels as label data.
func (l Label) GetData(buf *LabelData) {
	binary.BigEndian.PutUint64(buf[0:8], l.D0)
	binary.BigEndian.PutUint64(buf[8:16], l.D1)
}

// SetData sets the labels from label data.
func (l *Label) SetData(data *LabelData) {
	l.D0 = binary.BigEndian.Uint64((*data)[0:8])
	l.D1 = binary.BigEndian.Uint64((*data)[8:16])
}

// Bytes returns the label data as bytes.
func (l Label) Bytes(buf *LabelData) []byte {
	l.GetData(buf)
	return buf[:]
}

// SetBytes sets the label data from bytes.
func (l *Label) SetBytes(data []byte) {
	l.D0 = binary.BigEndian.Uint64(data[0:8])
	l.D1 = binary.BigEndian.Uint64(data[8:16])
}
