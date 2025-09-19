//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"testing"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
)

func BenchmarkGarbleXOR(b *testing.B) {
	benchmarkGate(b, newGate(XOR))
}

func BenchmarkGarbleXNOR(b *testing.B) {
	benchmarkGate(b, newGate(XNOR))
}

func BenchmarkGarbleAND(b *testing.B) {
	benchmarkGate(b, newGate(AND))
}

func BenchmarkGarbleOR(b *testing.B) {
	benchmarkGate(b, newGate(OR))
}

func BenchmarkGarbleINV(b *testing.B) {
	benchmarkGate(b, newGate(INV))
}

func newGate(op Operation) *Gate {
	return &Gate{
		Input0: 0,
		Input1: 1,
		Output: 2,
		Op:     op,
	}
}

func benchmarkGate(b *testing.B, g *Gate) {
	var key [16]byte
	inputs := []Wire{0, 1}
	outputs := []Wire{2}

	stream, err := NewStreaming(key[:], inputs, nil)
	if err != nil {
		b.Fatalf("failed to init streaming: %s", err)
	}
	stream.wires = []ot.Wire{{}, {}, {}}
	stream.in = inputs
	stream.out = outputs
	stream.firstTmp = 2
	stream.firstOut = 2

	var id uint32
	var data ot.LabelData
	var table [4]ot.Label

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf [128]byte
		var bufpos int

		err = stream.garbleGate(g, &id, table[:], &data, buf[:], &bufpos)
		if err != nil {
			b.Fatalf("garble failed: %s", err)
		}
	}
}

func BenchmarkEncodeWire32(b *testing.B) {
	var buf [64]byte

	for i := 0; i < b.N; i++ {
		var pos int
		bufpos := &pos

		var aIndex = Wire(i)
		var bIndex = Wire(i * 2)
		var cIndex = Wire(i * 4)
		var op byte

		buf[*bufpos] = op
		*bufpos = *bufpos + 1

		bo.PutUint32(buf[*bufpos+0:], uint32(aIndex))
		bo.PutUint32(buf[*bufpos+4:], uint32(bIndex))
		bo.PutUint32(buf[*bufpos+8:], uint32(cIndex))
		*bufpos = *bufpos + 12
	}
}

func BenchmarkEncodeWire16_32(b *testing.B) {
	var buf [64]byte

	for i := 0; i < b.N; i++ {
		var pos int
		bufpos := &pos

		var aIndex = Wire(i)
		var bIndex = Wire(i * 2)
		var cIndex = Wire(i * 4)
		var op byte

		if aIndex <= 0xffff && bIndex <= 0xffff && cIndex <= 0xffff {
			op |= 0b00010000
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			bo.PutUint16(buf[*bufpos+0:], uint16(aIndex))
			bo.PutUint16(buf[*bufpos+2:], uint16(bIndex))
			bo.PutUint16(buf[*bufpos+4:], uint16(cIndex))
			*bufpos = *bufpos + 6
		} else {
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			bo.PutUint32(buf[*bufpos+0:], uint32(aIndex))
			bo.PutUint32(buf[*bufpos+4:], uint32(bIndex))
			bo.PutUint32(buf[*bufpos+8:], uint32(cIndex))
			*bufpos = *bufpos + 12
		}
	}
}

func BenchmarkEncodeWire8_16_24_32(b *testing.B) {
	var buf [64]byte

	for i := 0; i < b.N; i++ {
		var pos int
		bufpos := &pos

		var aIndex = Wire(i)
		var bIndex = Wire(i * 2)
		var cIndex = Wire(i * 4)
		var op byte

		if aIndex <= 0xff && bIndex <= 0xff && cIndex <= 0xff {
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			buf[*bufpos+0] = byte(aIndex)
			buf[*bufpos+1] = byte(bIndex)
			buf[*bufpos+2] = byte(cIndex)
			*bufpos = *bufpos + 3
		} else if aIndex <= 0xffff && bIndex <= 0xffff && cIndex <= 0xffff {
			op |= 0b00010000
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			bo.PutUint16(buf[*bufpos+0:], uint16(aIndex))
			bo.PutUint16(buf[*bufpos+2:], uint16(bIndex))
			bo.PutUint16(buf[*bufpos+4:], uint16(cIndex))
			*bufpos = *bufpos + 6
		} else if aIndex <= 0xffffff && bIndex <= 0xffffff && cIndex <= 0xffffff {
			op |= 0b00100000
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			PutUint24(buf[*bufpos+0:], uint32(aIndex))
			PutUint24(buf[*bufpos+3:], uint32(bIndex))
			PutUint24(buf[*bufpos+6:], uint32(cIndex))
			*bufpos = *bufpos + 9
		} else {
			op |= 0b00110000
			buf[*bufpos] = op
			*bufpos = *bufpos + 1

			bo.PutUint32(buf[*bufpos+0:], uint32(aIndex))
			bo.PutUint32(buf[*bufpos+4:], uint32(bIndex))
			bo.PutUint32(buf[*bufpos+8:], uint32(cIndex))
			*bufpos = *bufpos + 12
		}
	}
}

func PutUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func BenchmarkEncodeWire7var(b *testing.B) {
	var buf [64]byte

	for i := 0; i < b.N; i++ {
		var pos int
		bufpos := &pos

		var aIndex = Wire(i)
		var bIndex = Wire(i * 2)
		var cIndex = Wire(i * 4)
		var op byte

		buf[*bufpos] = op
		*bufpos = *bufpos + 1

		*bufpos += encode7varRev(buf[*bufpos:], uint32(aIndex))
		*bufpos += encode7varRev(buf[*bufpos:], uint32(bIndex))
		*bufpos += encode7varRev(buf[*bufpos:], uint32(cIndex))
	}
}

func encode7var(b []byte, v uint32) int {
	if v <= 0b01111111 {
		b[0] = byte(v)
		return 1
	} else if v <= 0b01111111_1111111 {
		b[0] = byte(v >> 7)
		b[1] = byte(v)
		return 2
	} else if v <= 0b01111111_1111111_1111111 {
		b[0] = byte(v >> 14)
		b[1] = byte(v >> 7)
		b[2] = byte(v)
		return 3
	} else if v <= 0b01111111_1111111_1111111_1111111 {
		b[0] = byte(v >> 21)
		b[1] = byte(v >> 14)
		b[2] = byte(v >> 7)
		b[3] = byte(v)
		return 4
	} else {
		b[0] = byte(v >> 28)
		b[1] = byte(v >> 21)
		b[2] = byte(v >> 14)
		b[3] = byte(v >> 7)
		b[4] = byte(v)
		return 5
	}
}

func encode7varRev(b []byte, v uint32) int {
	if v > 0b01111111_1111111_1111111_1111111 {
		b[0] = byte(v >> 28)
		b[1] = byte(v >> 21)
		b[2] = byte(v >> 14)
		b[3] = byte(v >> 7)
		b[4] = byte(v)
		return 5
	} else if v > 0b01111111_1111111_1111111 {
		b[0] = byte(v >> 21)
		b[1] = byte(v >> 14)
		b[2] = byte(v >> 7)
		b[3] = byte(v)
		return 4
	} else if v > 0b01111111_1111111 {
		b[0] = byte(v >> 14)
		b[1] = byte(v >> 7)
		b[2] = byte(v)
		return 3
	} else if v > 0b01111111 {
		b[0] = byte(v >> 7)
		b[1] = byte(v)
		return 2
	} else {
		b[0] = byte(v)
		return 1
	}
}

func BenchmarkEncodeWire7varInline(b *testing.B) {
	var buf [64]byte

	for i := 0; i < b.N; i++ {
		var pos int
		bufpos := &pos

		var aIndex = Wire(i)
		var bIndex = Wire(i * 2)
		var cIndex = Wire(i * 4)
		var op byte

		buf[*bufpos] = op
		*bufpos = *bufpos + 1

		if aIndex <= 0b01111111 &&
			bIndex <= 0b01111111 &&
			cIndex <= 0b01111111 {
			encode7var1(buf[*bufpos+0:], uint32(aIndex))
			encode7var1(buf[*bufpos+1:], uint32(bIndex))
			encode7var1(buf[*bufpos+2:], uint32(cIndex))
			*bufpos += 3
		} else if aIndex <= 0b01111111_1111111 &&
			bIndex <= 0b01111111_1111111 &&
			cIndex <= 0b01111111_1111111 {
			encode7var2(buf[*bufpos+0:], uint32(aIndex))
			encode7var2(buf[*bufpos+2:], uint32(bIndex))
			encode7var2(buf[*bufpos+4:], uint32(cIndex))
			*bufpos += 6
		} else if aIndex <= 0b01111111_1111111_1111111 &&
			bIndex <= 0b01111111_1111111_1111111 &&
			cIndex <= 0b01111111_1111111_1111111 {
			encode7var3(buf[*bufpos+0:], uint32(aIndex))
			encode7var3(buf[*bufpos+3:], uint32(bIndex))
			encode7var3(buf[*bufpos+6:], uint32(cIndex))
			*bufpos += 9
		} else if aIndex <= 0b01111111_1111111_1111111_1111111 &&
			bIndex <= 0b01111111_1111111_1111111_1111111 &&
			cIndex <= 0b01111111_1111111_1111111_1111111 {
			encode7var4(buf[*bufpos+0:], uint32(aIndex))
			encode7var4(buf[*bufpos+4:], uint32(bIndex))
			encode7var4(buf[*bufpos+8:], uint32(cIndex))
			*bufpos += 12
		} else {
			encode7var5(buf[*bufpos+0:], uint32(aIndex))
			encode7var5(buf[*bufpos+5:], uint32(bIndex))
			encode7var5(buf[*bufpos+10:], uint32(cIndex))
			*bufpos += 15
		}
	}
}

func encode7var1(b []byte, v uint32) {
	b[0] = byte(v)
}

func encode7var2(b []byte, v uint32) {
	b[0] = byte(v >> 7)
	b[1] = byte(v)
}

func encode7var3(b []byte, v uint32) {
	b[0] = byte(v >> 14)
	b[1] = byte(v >> 7)
	b[2] = byte(v)
}

func encode7var4(b []byte, v uint32) {
	b[0] = byte(v >> 21)
	b[1] = byte(v >> 14)
	b[2] = byte(v >> 7)
	b[3] = byte(v)
}

func encode7var5(b []byte, v uint32) {
	b[0] = byte(v >> 28)
	b[1] = byte(v >> 21)
	b[2] = byte(v >> 14)
	b[3] = byte(v >> 7)
	b[4] = byte(v)
}

func BenchmarkTimeDuration(b *testing.B) {
	var total time.Duration

	for i := 0; i < b.N; i++ {
		start := time.Now()
		total += time.Now().Sub(start)
	}
}
