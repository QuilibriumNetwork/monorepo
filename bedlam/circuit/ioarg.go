//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"math/big"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// IO specifies circuit input and output arguments.
type IO []IOArg

// Size computes the size of the circuit input and output arguments in
// bits.
func (io IO) Size() int {
	var sum int
	for _, a := range io {
		sum += int(a.Type.Bits)
	}
	return sum
}

func (io IO) String() string {
	var str = ""
	for i, a := range io {
		if i > 0 {
			str += ", "
		}
		if len(a.Name) > 0 {
			str += a.Name + ":"
		}
		str += a.Type.String()
	}
	return str
}

// Split splits the value into separate I/O arguments.
func (io IO) Split(in *big.Int) []*big.Int {
	var result []*big.Int
	var bit int
	for _, arg := range io {
		r := big.NewInt(0)
		for i := 0; i < int(arg.Type.Bits); i++ {
			if in.Bit(bit) == 1 {
				r = big.NewInt(0).SetBit(r, i, 1)
			}
			bit++
		}
		result = append(result, r)
	}
	return result
}

// IOArg describes circuit input argument.
type IOArg struct {
	Name     string
	Type     types.Info
	Compound IO
}

func (io IOArg) String() string {
	if len(io.Compound) > 0 {
		return io.Compound.String()
	}

	if len(io.Name) > 0 {
		return io.Name + ":" + io.Type.String()
	}
	return io.Type.String()
}

// Parse parses the I/O argument from the input string values.
func (io IOArg) Parse(inputs []string) (*big.Int, error) {
	result := new(big.Int)

	if len(io.Compound) == 0 {
		if len(inputs) != 1 {
			return nil,
				fmt.Errorf("invalid amount of arguments, got %d, expected 1",
					len(inputs))
		}

		switch io.Type.Type {
		case types.TInt, types.TUint:
			_, ok := result.SetString(inputs[0], 0)
			if !ok {
				return nil, fmt.Errorf("invalid input '%s' for %s",
					inputs[0], io.Type)
			}

		case types.TBool:
			switch inputs[0] {
			case "0", "f", "false":
			case "1", "t", "true":
				result.SetInt64(1)
			default:
				return nil, fmt.Errorf("invalid bool constant: %s", inputs[0])
			}

		case types.TArray, types.TSlice:
			count := int(io.Type.ArraySize)
			elSize := int(io.Type.ElementType.Bits)
			if io.Type.Type == types.TArray && count == 0 {
				// Handle empty types.TArray arguments.
				break
			}

			val := new(big.Int)
			_, ok := val.SetString(inputs[0], 0)
			if !ok {
				return nil, fmt.Errorf("invalid input '%s' for %s",
					inputs[0], io.Type)
			}
			var bitLen int
			if strings.HasPrefix(inputs[0], "0x") {
				bitLen = (len(inputs[0]) - 2) * 4
			} else {
				bitLen = val.BitLen()
			}

			valElCount := bitLen / elSize
			if bitLen%elSize != 0 {
				valElCount++
			}
			if io.Type.Type == types.TSlice {
				// Set the count=valElCount for types.TSlice arguments.
				count = valElCount
			}
			if valElCount > count {
				return nil, fmt.Errorf("too many values for input: %s",
					inputs[0])
			}
			pad := count - valElCount
			val.Lsh(val, uint(pad*elSize))

			mask := new(big.Int)
			for i := 0; i < elSize; i++ {
				mask.SetBit(mask, i, 1)
			}

			for i := 0; i < count; i++ {
				next := new(big.Int).Rsh(val, uint((count-i-1)*elSize))
				next = next.And(next, mask)

				next.Lsh(next, uint(i*elSize))
				result.Or(result, next)
			}

		default:
			return nil, fmt.Errorf("unsupported input type: %s", io.Type)
		}

		return result, nil
	}
	if len(inputs) != len(io.Compound) {
		return nil,
			fmt.Errorf("invalid amount of arguments, got %d, expected %d",
				len(inputs), len(io.Compound))
	}

	var offset int

	for idx, arg := range io.Compound {
		input, err := arg.Parse(inputs[idx : idx+1])
		if err != nil {
			return nil, err
		}

		input.Lsh(input, uint(offset))
		result.Or(result, input)

		offset += int(arg.Type.Bits)
	}
	return result, nil
}

// InputSizes computes the bit sizes of the input arguments. This is
// used for parametrized main() when the program is instantiated based
// on input sizes.
func InputSizes(inputs []string) ([]int, error) {
	var result []int

	for _, input := range inputs {
		switch input {
		case "_":
			result = append(result, 0)

		case "0", "f", "false", "1", "t", "true":
			result = append(result, 1)

		default:
			if strings.HasPrefix(input, "0x") {
				result = append(result, (len(input)-2)*4)
			} else {
				val := new(big.Int)
				_, ok := val.SetString(input, 0)
				if !ok {
					return nil, fmt.Errorf("invalid input: %s", input)
				}
				result = append(result, val.BitLen())
			}
		}
	}

	return result, nil
}
