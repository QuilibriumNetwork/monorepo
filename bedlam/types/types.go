//
// types.go
//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package types

import (
	"fmt"
)

// ID specifies an unique ID for named types.
type ID int32

// Type specifies an QCL type.
type Type int8

// Size specify sizes and bit counts in circuits.
type Size int32

func (t Type) String() string {
	for k, v := range Types {
		if v == t {
			return k
		}
	}
	return fmt.Sprintf("{Type %d}", t)
}

// ShortString returns a short string name for the type.
func (t Type) ShortString() string {
	name, ok := shortTypes[t]
	if ok {
		return name
	}
	return t.String()
}

// Array tests if the type is an Array or a Slice.
func (t Type) Array() bool {
	return t == TArray || t == TSlice
}

// ByteBits defines the byte size in bits.
const ByteBits = 8

// QCL types.
const (
	TUndefined Type = iota
	TBool
	TInt
	TUint
	TFloat
	TString
	TStruct
	TArray
	TSlice
	TPtr
	TNil
)

// Types define QCL types and their names.
var Types = map[string]Type{
	"<Undefined>": TUndefined,
	"bool":        TBool,
	"int":         TInt,
	"uint":        TUint,
	"float":       TFloat,
	"string":      TString,
	"struct":      TStruct,
	"array":       TArray,
	"slice":       TSlice,
	"ptr":         TPtr,
	"nil":         TNil,
}

var shortTypes = map[Type]string{
	TUndefined: "?",
	TBool:      "b",
	TInt:       "i",
	TUint:      "u",
	TFloat:     "f",
	TString:    "str",
	TStruct:    "struct",
	TArray:     "arr",
	TSlice:     "slice",
	TPtr:       "*",
	TNil:       "nil",
}

// Info specifies information about a type.
type Info struct {
	ID          ID
	Type        Type
	IsConcrete  bool
	Bits        Size
	MinBits     Size
	Struct      []StructField
	ElementType *Info
	ArraySize   Size
	Offset      Size
}

// Undefined defines type info for undefined types.
var Undefined = Info{
	Type:       TUndefined,
	IsConcrete: true,
}

// Nil defines type info for the nil value.
var Nil = Info{
	Type:       TNil,
	IsConcrete: true,
}

// Bool defines type info for boolean values.
var Bool = Info{
	Type:       TBool,
	IsConcrete: true,
	Bits:       1,
	MinBits:    1,
}

// Byte defines type info for byte values.
var Byte = Info{
	Type:       TUint,
	IsConcrete: true,
	Bits:       8,
	MinBits:    8,
}

// Rune defines type info for rune values.
var Rune = Info{
	Type:       TInt,
	IsConcrete: true,
	Bits:       32,
	MinBits:    32,
}

// Int32 defines type info for signed 32bit integers.
var Int32 = Info{
	Type:       TInt,
	IsConcrete: true,
	Bits:       32,
	MinBits:    32,
}

// Uint32 defines type info for unsigned 32bit integers.
var Uint32 = Info{
	Type:       TUint,
	IsConcrete: true,
	Bits:       32,
	MinBits:    32,
}

// Uint64 defines type info for unsigned 64bit integers.
var Uint64 = Info{
	Type:       TUint,
	IsConcrete: true,
	Bits:       64,
	MinBits:    64,
}

// StructField defines a structure field name and type.
type StructField struct {
	Name string
	Type Info
}

func (f StructField) String() string {
	return fmt.Sprintf("%s[%d:%d]",
		f.Type.Type, f.Type.Offset, f.Type.Offset+f.Type.Bits)
}

func (i Info) String() string {
	switch i.Type {
	case TArray:
		return fmt.Sprintf("[%d]%s", i.ArraySize, i.ElementType)

	case TSlice:
		return fmt.Sprintf("[]%s", i.ElementType)

	case TPtr:
		return fmt.Sprintf("*%s", i.ElementType)

	default:
		if !i.Concrete() {
			return i.Type.String()
		}
		return fmt.Sprintf("%s%d", i.Type, i.Bits)
	}
}

// ShortString returns a short string name for the type info.
func (i Info) ShortString() string {
	if !i.Concrete() {
		return i.Type.ShortString()
	}
	if i.Type == TPtr {
		return fmt.Sprintf("*%s", i.ElementType.ShortString())
	}
	return fmt.Sprintf("%s%d", i.Type.ShortString(), i.Bits)
}

// Undefined tests if type is undefined.
func (i Info) Undefined() bool {
	return i.Type == TUndefined
}

// Concrete tests if the type is concrete.
func (i Info) Concrete() bool {
	if i.Type != TStruct {
		return i.IsConcrete
	}
	for _, field := range i.Struct {
		if !field.Type.Concrete() {
			return false
		}
	}
	return true
}

// SetConcrete sets the type concrete status.
func (i *Info) SetConcrete(c bool) {
	i.IsConcrete = c
}

// Instantiate instantiates template type to match parameter type.
func (i *Info) Instantiate(o Info) bool {
	if i.Type != o.Type {
		switch i.Type {
		case TArray:
			switch o.Type {
			case TNil:
				// nil instantiates an empty array
				if !i.ElementType.Concrete() {
					return false
				}
				i.IsConcrete = true
				i.Bits = 0
				i.MinBits = 0
				i.ArraySize = 0
				return true

			case TPtr:
				if !o.ElementType.Type.Array() {
					return false
				}
				// Instantiating array from pointer to array
				// i.e. continue below.
				i.Type = TPtr
				i.ElementType = o.ElementType

			default:
				return false
			}

		case TSlice:
			switch o.Type {
			case TNil:
				// nil instantiates an empty slice
				i.IsConcrete = true
				i.Bits = 0
				i.MinBits = 0
				i.ArraySize = 0
				return true

			case TArray:
				// Instantiating slice from an array. Continue below.

			case TPtr:
				if !o.ElementType.Type.Array() {
					return false
				}
				// Instantiating slice from pointer to array
				// i.e. continue below.
				i.Type = TPtr
				i.ElementType = o.ElementType

			default:
				return false
			}

		case TInt:
			switch o.Type {
			case TUint:
				if o.MinBits < o.Bits {
					// Unsigned integer not using all bits i.e. it is
					// non-negative. We can use it as r-value for
					// signed integer.
					i.IsConcrete = true
					i.Bits = o.Bits
					i.MinBits = o.Bits
					return true
				}
			}
			return false

		default:
			return false
		}
	}
	if i.Concrete() {
		return false
	}
	switch i.Type {
	case TStruct:
		return false

	case TArray, TSlice:
		if !i.ElementType.Concrete() &&
			!i.ElementType.Instantiate(*o.ElementType) {
			return false
		}
		if i.ElementType.Type != o.ElementType.Type {
			return false
		}
		i.IsConcrete = true
		i.Bits = o.Bits
		i.ArraySize = o.ArraySize
		return true

	case TPtr:
		if i.ElementType.Type != o.ElementType.Type {
			return false
		}
		i.IsConcrete = true
		i.Bits = o.Bits
		return true

	default:
		i.IsConcrete = true
		i.Bits = o.Bits
		return true
	}
}

// InstantiateWithSizes creates a concrete type of the unspecified
// type with given element sizes.
func (i *Info) InstantiateWithSizes(sizes []int) error {
	if len(sizes) == 0 {
		return fmt.Errorf("not enought sizes for type %v", i)
	}

	switch i.Type {
	case TBool:

	case TInt, TUint, TFloat:
		if !i.Concrete() {
			i.Bits = Size(sizes[0])
		}

	case TStruct:
		var structBits Size
		for idx := range i.Struct {
			if idx >= len(sizes) {
				return fmt.Errorf("not enought sizes for type %v", i)
			}
			err := i.Struct[idx].Type.InstantiateWithSizes(sizes[idx:])
			if err != nil {
				return err
			}
			i.Struct[idx].Type.Offset = structBits
			structBits += i.Struct[idx].Type.Bits
		}
		i.Bits = structBits

	case TArray:
		if !i.ElementType.Concrete() {
			return fmt.Errorf("array element type unspecified: %v", i)
		}
		if !i.Concrete() {
			i.ArraySize = Size(sizes[0]) / i.ElementType.Bits
			if Size(sizes[0])%i.ElementType.Bits != 0 {
				i.ArraySize++
			}
			i.Bits = i.ArraySize * i.ElementType.Bits
		}

	case TSlice:
		if !i.ElementType.Concrete() {
			return fmt.Errorf("slice element type unspecified: %v", i)
		}
		i.ArraySize = Size(sizes[0]) / i.ElementType.Bits
		if Size(sizes[0])%i.ElementType.Bits != 0 {
			i.ArraySize++
		}
		i.Bits = i.ArraySize * i.ElementType.Bits

	default:
		return fmt.Errorf("can't specify %v", i)
	}
	i.SetConcrete(true)

	return nil
}

// Equal tests if the argument type is equal to this type info.
func (i Info) Equal(o Info) bool {
	if i.Type != o.Type {
		return false
	}
	switch i.Type {
	case TUndefined, TBool, TInt, TUint, TFloat, TString:
		return i.Bits == o.Bits

	case TStruct:
		if len(i.Struct) != len(o.Struct) || i.Bits != o.Bits {
			return false
		}
		for idx, ie := range i.Struct {
			if !ie.Type.Equal(o.Struct[idx].Type) {
				return false
			}
		}
		return true

	case TArray, TSlice:
		if i.ArraySize != o.ArraySize || i.Bits != o.Bits {
			return false
		}
		return i.ElementType.Equal(*o.ElementType)

	case TPtr:
		return i.ElementType.Equal(*o.ElementType)

	default:
		panic(fmt.Sprintf("Info.Equal called for %v (%T)", i.Type, i.Type))
	}
}

// Specializable tests if this type can be specialized with the
// argument type.
func (i Info) Specializable(o Info) bool {
	if i.Type != o.Type {
		return false
	}
	switch i.Type {
	case TUndefined, TBool, TInt, TUint, TFloat, TString:
		return !i.Concrete() || i.Bits == o.Bits

	case TStruct:
		if len(i.Struct) != len(o.Struct) ||
			(i.Concrete() && i.Bits != o.Bits) {
			return false
		}
		for idx, ie := range i.Struct {
			if !ie.Type.Specializable(o.Struct[idx].Type) {
				return false
			}
		}
		return true

	case TArray:
		if i.Concrete() && (i.ArraySize != o.ArraySize || i.Bits != o.Bits) {
			return false
		}
		return i.ElementType.Specializable(*o.ElementType)

	case TSlice:
		return i.ElementType.Specializable(*o.ElementType)

	case TPtr:
		return i.ElementType.Specializable(*o.ElementType)

	default:
		panic(fmt.Sprintf("Info.Specializable called for %v (%T)",
			i.Type, i.Type))
	}
}

// CanAssignConst tests if the argument const type can be assigned to
// this type.
func (i Info) CanAssignConst(o Info) bool {
	switch i.Type {
	case TInt, TUint:
		return (o.Type == TInt || o.Type == TUint) && i.Bits >= o.MinBits

	case TSlice:
		return o.Type.Array() && i.ElementType.Equal(*o.ElementType)

	case TArray:
		if o.Type == TNil {
			return true
		}
		if !o.Type.Array() || !i.ElementType.Equal(*o.ElementType) {
			return false
		}
		return i.Bits >= o.MinBits

	default:
		return i.Type == o.Type && i.Bits >= o.MinBits
	}
}
