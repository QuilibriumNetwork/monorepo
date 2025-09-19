//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package bedlam

import (
	"fmt"
	"math/big"
	"reflect"
	"unicode"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// PrintResults prints the result values.
func PrintResults(results []*big.Int, outputs circuit.IO) {
	for idx, value := range Results(results, outputs) {
		fmt.Printf("Result[%d]: ", idx)
		switch v := value.(type) {
		case []byte:
			fmt.Printf("%x\n", v)
		default:
			fmt.Printf("%v\n", v)
		}
	}
}

// Results return the result values as an array of Go values.
func Results(results []*big.Int, outputs circuit.IO) []interface{} {
	var ret []interface{}

	for idx, result := range results {
		var r interface{}
		if outputs == nil {
			r = Result(result, circuit.IOArg{
				Type: types.Info{
					Type:       types.TUint,
					IsConcrete: true,
					Bits:       1024, // Anything >64 returns big.Int
				},
			})
		} else {
			r = Result(result, outputs[idx])
		}
		ret = append(ret, r)
	}
	return ret
}

// Result converts the result to Go value.
func Result(result *big.Int, output circuit.IOArg) interface{} {
	switch output.Type.Type {
	case types.TString:
		mask := big.NewInt(0xff)

		var str string
		for i := 0; i < int(output.Type.Bits)/8; i++ {
			tmp := new(big.Int).Rsh(result, uint(i*8))
			r := rune(tmp.And(tmp, mask).Uint64())
			if unicode.IsPrint(r) {
				str += string(r)
			} else {
				str += fmt.Sprintf("\\u%04x", r)
			}
		}
		return str

	case types.TUint:
		if output.Type.Bits <= 8 {
			return uint8(result.Uint64())
		} else if output.Type.Bits <= 16 {
			return uint16(result.Uint64())
		} else if output.Type.Bits <= 32 {
			return uint32(result.Uint64())
		} else if output.Type.Bits <= 64 {
			return result.Uint64()
		} else {
			return result
		}

	case types.TInt:
		bits := int(output.Type.Bits)
		if result.Bit(bits-1) == 1 {
			// Negative number.
			tmp := new(big.Int)
			tmp.SetBit(tmp, bits, 1)
			result.Sub(tmp, result)
			result.Neg(result)
		}
		if output.Type.Bits <= 8 {
			return int8(result.Int64())
		} else if output.Type.Bits <= 16 {
			return int16(result.Int64())
		} else if output.Type.Bits <= 32 {
			return int32(result.Int64())
		} else if output.Type.Bits <= 64 {
			return result.Int64()
		} else {
			return result
		}

	case types.TBool:
		return result.Uint64() != 0

	case types.TArray, types.TSlice:
		count := int(output.Type.ArraySize)
		elSize := int(output.Type.ElementType.Bits)

		mask := new(big.Int)
		for i := 0; i < elSize; i++ {
			mask.SetBit(mask, i, 1)
		}

		var slice reflect.Value
		var elementType reflect.Type

		switch output.Type.ElementType.Type {
		case types.TString:
			elementType = reflect.TypeOf("")

		case types.TUint:
			if elSize <= 8 {
				elementType = reflect.TypeOf(uint8(0))
			} else if elSize <= 16 {
				elementType = reflect.TypeOf(uint16(0))
			} else if elSize <= 32 {
				elementType = reflect.TypeOf(uint32(0))
			} else if elSize <= 64 {
				elementType = reflect.TypeOf(uint64(0))
			} else {
				elementType = reflect.TypeOf((*big.Int)(nil))
			}

		case types.TInt:
			if elSize <= 8 {
				elementType = reflect.TypeOf(int8(0))
			} else if elSize <= 16 {
				elementType = reflect.TypeOf(int16(0))
			} else if elSize <= 32 {
				elementType = reflect.TypeOf(int32(0))
			} else if elSize <= 64 {
				elementType = reflect.TypeOf(int64(0))
			} else {
				elementType = reflect.TypeOf((*big.Int)(nil))
			}

		case types.TBool:
			elementType = reflect.TypeOf(true)

		default:
			elementType = reflect.TypeOf(nil)
		}

		slice = reflect.MakeSlice(reflect.SliceOf(elementType), 0, count)

		for i := 0; i < count; i++ {
			r := new(big.Int).Rsh(result, uint(i*elSize))
			r = r.And(r, mask)

			v := reflect.ValueOf(Result(r, circuit.IOArg{
				Type: *output.Type.ElementType,
			}))

			slice = reflect.Append(slice, v)
		}
		return slice.Interface()

	default:
		return fmt.Sprintf("%v (%s)", result, output.Type)
	}
}
