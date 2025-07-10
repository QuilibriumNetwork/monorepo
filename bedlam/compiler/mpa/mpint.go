//
// Copyright (c) 2023-2024 Markku Rossi
//
// All rights reserved.
//

package mpa

import (
	"fmt"
	"math/big"
	"strconv"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Int implements multi-precision integer arithmetics.
type Int struct {
	bits   types.Size
	i64    int64
	values *big.Int
}

// New creates a new integer with the specified bit size.
func New(bits types.Size) *Int {
	if bits == 0 {
		panic("mpa.New: bits are zero")
	}
	return &Int{
		bits: bits,
	}
}

// NewInt creates a new Int with init value x and optional bit
// size. If the bit size is 0, the size is determined from the
// cardinality of x.
func NewInt(x int64, bits types.Size) *Int {
	if bits == 0 {
		for bits = 1; bits < 64; bits++ {
			if (0xffffffffffffffff<<bits)&uint64(x) == 0 {
				break
			}
		}
		if bits > 32 {
			bits = 64
		} else {
			bits = 32
		}
	}
	return &Int{
		bits: bits,
		i64:  x,
	}
}

func (z *Int) isSmall() bool {
	return z.bits <= 64
}

func (z *Int) small() int64 {
	if z.values != nil {
		return z.values.Int64()
	}
	return z.i64
}

func (z *Int) big() *big.Int {
	if z.values == nil {
		z.values = big.NewInt(z.i64)
	}
	return z.values
}

func (z *Int) signed(signBit types.Size) *big.Int {
	bigInt := z.big()
	var sign int
	if signBit >= 0 {
		if bigInt.Bit(int(signBit)) == 1 {
			sign = -1
		} else {
			sign = 1
		}
	}
	result := big.NewInt(0).Set(bigInt)
	rsign := result.Sign()
	if sign != 0 && sign != rsign {
		result.Neg(result)
	}
	return result
}

// Debug prints debug information about z.
func (z *Int) Debug() {
	if z.isSmall() {
		fmt.Printf("mpa.Big: val=%v, bits=%v, i64=%v\n", z, z.bits, z.small())
	} else {
		fmt.Printf("mpa.Big: val=%v, bits=%v, bitLen=%v, values=%x\n",
			z, z.bits, z.BitLen(), z.big().Bits())
	}
}

// TypeSize returns the type size in bits.
func (z *Int) TypeSize() int {
	return int(z.bits)
}

// SetTypeSize sets the type size in bits.
func (z *Int) SetTypeSize(size types.Size) {
	z.bits = size
}

// Bit returns the value of the i'th bit of z.
func (z *Int) Bit(i int) uint {
	if z.isSmall() {
		return uint((z.small() >> uint(i)) & 0x1)
	}
	return z.big().Bit(i)
}

// BitLen returns the length of the absolute value of z.
func (z *Int) BitLen() int {
	if z.isSmall() {
		var bitLen int
		v := uint64(z.small())
		for bitLen = 1; bitLen < 64; bitLen++ {
			if (0xffffffffffffffff<<bitLen)&v == 0 {
				break
			}
		}
		return bitLen
	}
	return z.big().BitLen()
}

// Cmp compares z for x and returns -1, 0, 1 if z is smaller, equal,
// or greater than x.
func (z *Int) Cmp(x *Int) int {
	if z.isSmall() && x.isSmall() {
		zi64 := z.Int64()
		xi64 := x.Int64()
		if zi64 < xi64 {
			return -1
		} else if zi64 > xi64 {
			return 1
		} else {
			return 0
		}
	}
	zv := z.signed(z.bits - 1)
	xv := x.signed(x.bits - 1)
	return zv.Cmp(xv)
}

// Int64 returns the int64 representation of x. If x cannot be
// represented as int64, the result is undefined.
func (z *Int) Int64() int64 {
	if z.isSmall() {
		v := z.small()
		signBit := int64(0x1) << (z.bits - 1)
		if z.bits == 64 || v&signBit == 0 {
			return v
		}
		signBit <<= 1
		return -(signBit - v)
	}
	return z.big().Int64()
}

func (z *Int) String() string {
	if z.values != nil {
		return z.values.String()
	}
	return strconv.FormatInt(z.i64, 10)
}

// Text returns a string representation of z in the given base.
func (z *Int) Text(base int) string {
	if z.values != nil {
		return z.values.Text(base)
	}
	return strconv.FormatInt(z.i64, base)
}

// Add sets z to x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	if z.isSmall() {
		z.bits = max(x.bits, y.bits)
		z.setSmall(x.small() + y.small())
		return z
	}
	return z.bin(circuits.NewAdder, x, y)
}

// And sets z to x&y and returns z.
func (z *Int) And(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() & y.small())
	} else {
		z.values = big.NewInt(0).And(x.big(), y.big())
	}
	return z
}

// AndNot sets z to x&^y and returns z.
func (z *Int) AndNot(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() &^ y.small())
	} else {
		z.values = big.NewInt(0).AndNot(x.big(), y.big())
	}
	return z
}

// Div sets z to x/y and returns z.
func (z *Int) Div(x, y *Int) *Int {
	if z.isSmall() {
		if y.small() == 0 {
			z.setSmall(-1)
		} else {
			z.setSmall(x.small() / y.small())
		}
		return z
	}
	calloc := circuits.NewAllocator()
	inputs := circuit.IO{
		newIOArg("x", types.TInt, x.bits),
		newIOArg("y", types.TInt, y.bits),
	}
	outputs := circuit.IO{
		newIOArg("q", types.TInt, max(x.bits, y.bits)),
		newIOArg("r", types.TInt, max(x.bits, y.bits)),
	}
	i0w := calloc.Wires(inputs[0].Type.Bits)
	i1w := calloc.Wires(inputs[1].Type.Bits)

	var inputWires []*circuits.Wire
	inputWires = append(inputWires, i0w...)
	inputWires = append(inputWires, i1w...)

	o0w := calloc.Wires(outputs[0].Type.Bits)
	o1w := calloc.Wires(outputs[1].Type.Bits)

	var outputWires []*circuits.Wire
	outputWires = append(outputWires, o0w...)
	outputWires = append(outputWires, o1w...)

	for idx := range outputWires {
		outputWires[idx].SetOutput(true)
	}

	cc, err := circuits.NewCompiler(utils.NewParams(), calloc, inputs, outputs,
		inputWires, outputWires)
	if err != nil {
		panic(err)
	}

	err = circuits.NewIDivider(cc, i0w, i1w, o0w, o1w)
	if err != nil {
		panic(err)
	}

	circ := cc.Compile()

	obits, err := circ.Compute([]*big.Int{x.big(), y.big()})
	if err != nil {
		panic(err)
	}

	z.bits = outputs[0].Type.Bits
	z.values = obits[0]

	return z
}

// Lsh sets z to x<<n and returns z.
func (z *Int) Lsh(x *Int, n uint) *Int {
	if z.isSmall() {
		z.setSmall(x.small() << n)
		return z
	}
	if z != x {
		z.values = big.NewInt(0).Set(x.big())
	} else {
		// Make sure z.values is initialized.
		z.big()
	}
	z.values.Lsh(z.values, n)
	for i := z.values.BitLen() - 1; i >= int(z.bits); i-- {
		z.values.SetBit(z.values, i, 0)
	}
	return z
}

// Mod sets z to x%y and returns z.
func (z *Int) Mod(x, y *Int) *Int {
	if z.isSmall() {
		if y.small() == 0 {
			z.setSmall(x.small())
		} else {
			z.setSmall(x.small() % y.small())
		}
		return z
	}
	calloc := circuits.NewAllocator()
	inputs := circuit.IO{
		newIOArg("x", types.TInt, x.bits),
		newIOArg("y", types.TInt, y.bits),
	}
	outputs := circuit.IO{
		newIOArg("q", types.TInt, max(x.bits, y.bits)),
		newIOArg("r", types.TInt, max(x.bits, y.bits)),
	}
	i0w := calloc.Wires(inputs[0].Type.Bits)
	i1w := calloc.Wires(inputs[1].Type.Bits)

	var inputWires []*circuits.Wire
	inputWires = append(inputWires, i0w...)
	inputWires = append(inputWires, i1w...)

	o0w := calloc.Wires(outputs[0].Type.Bits)
	o1w := calloc.Wires(outputs[1].Type.Bits)

	var outputWires []*circuits.Wire
	outputWires = append(outputWires, o0w...)
	outputWires = append(outputWires, o1w...)

	for idx := range outputWires {
		outputWires[idx].SetOutput(true)
	}

	cc, err := circuits.NewCompiler(utils.NewParams(), calloc, inputs, outputs,
		inputWires, outputWires)
	if err != nil {
		panic(err)
	}

	err = circuits.NewIDivider(cc, i0w, i1w, o0w, o1w)
	if err != nil {
		panic(err)
	}

	circ := cc.Compile()

	obits, err := circ.Compute([]*big.Int{x.big(), y.big()})
	if err != nil {
		panic(err)
	}

	z.bits = outputs[1].Type.Bits
	z.values = obits[1]

	return z
}

// Mul sets z to x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() * y.small())
		return z
	}
	return z.bin(func(cc *circuits.Compiler, x, y, z []*circuits.Wire) error {
		return circuits.NewMultiplier(cc, 0, x, y, z)
	}, x, y)
}

// Or sets z to x|y and returns z.
func (z *Int) Or(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() | y.small())
	} else {
		z.values = big.NewInt(0).Or(x.big(), y.big())
	}
	return z
}

// Rsh sets z to x>>n and returns z.
func (z *Int) Rsh(x *Int, n uint) *Int {
	if z.isSmall() {
		z.setSmall(x.small() >> n)
		return z
	}
	if z != x {
		z.bits = x.bits
		z.values = big.NewInt(0).Set(x.big())
	} else {
		// Make sure z.values is initialized.
		z.big()
	}

	z.values.Rsh(z.values, n)
	return z
}

func (z *Int) setBig(x *big.Int) *Int {
	if x.IsInt64() {
		z.bits = 64
		z.setSmall(x.Int64())
		return z
	}
	z.bits = types.Size(x.BitLen())
	if z.bits > 0 && x.Sign() == 1 && x.Bit(int(z.bits-1)) == 1 {
		z.bits++
	}
	z.values = new(big.Int).Set(x)
	return z
}

func (z *Int) setSmall(x int64) {
	if z.bits > 64 {
		panic(fmt.Sprintf("Int.setSmall: bits=%v > 64", z.bits))
	}

	mask := uint64(0xffffffffffffffff)
	mask >>= 64 - z.bits
	z.i64 = int64(uint64(x) & mask)

	z.values = nil
}

// Parse s according to its ascii value and return Int. The argument
// base specifies how the argument string base is interpreted.
func Parse(s string, base int) (*Int, bool) {
	i, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, false
	}
	return new(Int).setBig(i), true
}

// Sign returns -1, 0, 1 if z is negative, zero, or positive.
func (z *Int) Sign() int {
	if z.isSmall() {
		v := z.small()
		if v < 0 {
			return -1
		} else if v > 0 {
			return 1
		} else {
			return 0
		}
	}
	return z.big().Sign()
}

// Sub sets z to x-y and returns z.
func (z *Int) Sub(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() - y.small())
		return z
	}
	return z.bin(circuits.NewSubtractor, x, y)
}

// Xor sets z to x^y and returns z.
func (z *Int) Xor(x, y *Int) *Int {
	if z.isSmall() {
		z.setSmall(x.small() ^ y.small())
	} else {
		z.values = big.NewInt(0).Xor(x.big(), y.big())
	}
	return z
}

type binaryOp func(cc *circuits.Compiler, x, y, z []*circuits.Wire) error

func (z *Int) bin(op binaryOp, x, y *Int) *Int {
	calloc := circuits.NewAllocator()
	inputs := circuit.IO{
		newIOArg("x", types.TInt, x.bits),
		newIOArg("y", types.TInt, y.bits),
	}
	outputs := circuit.IO{
		newIOArg("z", types.TInt, max(x.bits, y.bits)),
	}
	i0w := calloc.Wires(inputs[0].Type.Bits)
	i1w := calloc.Wires(inputs[1].Type.Bits)
	var inputWires []*circuits.Wire
	inputWires = append(inputWires, i0w...)
	inputWires = append(inputWires, i1w...)

	outputWires := calloc.Wires(outputs[0].Type.Bits)
	for idx := range outputWires {
		outputWires[idx].SetOutput(true)
	}

	cc, err := circuits.NewCompiler(utils.NewParams(), calloc, inputs, outputs,
		inputWires, outputWires)
	if err != nil {
		panic(err)
	}

	err = op(cc, i0w, i1w, outputWires)
	if err != nil {
		panic(err)
	}

	circ := cc.Compile()

	obits, err := circ.Compute([]*big.Int{x.big(), y.big()})
	if err != nil {
		panic(err)
	}

	z.bits = outputs[0].Type.Bits
	z.values = obits[0]

	return z
}

func newIOArg(name string, t types.Type, size types.Size) circuit.IOArg {
	return circuit.IOArg{
		Name: name,
		Type: types.Info{
			Type:       t,
			IsConcrete: true,
			Bits:       size,
		},
	}
}
