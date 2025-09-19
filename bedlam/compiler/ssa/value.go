//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"errors"
	"fmt"
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/mpa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

var (
	errNotConstant = errors.New("value is not constant")
)

// Value implements SSA value binding.
type Value struct {
	Name       string
	ID         ValueID
	TypeRef    bool
	Const      bool
	Scope      Scope
	Version    int32
	Type       types.Info
	PtrInfo    *PtrInfo
	ConstValue interface{}
}

// Scope defines variable scope (max 65536 levels of nested blocks).
type Scope int16

// PtrInfo defines context information for pointer values.
type PtrInfo struct {
	Name          string
	Bindings      *Bindings
	Scope         Scope
	Offset        types.Size
	ContainerType types.Info
}

func (ptr PtrInfo) String() string {
	return fmt.Sprintf("*%s@%d", ptr.Name, ptr.Scope)
}

// Equal tests if this PtrInfo is equal to the argument PtrInfo.
func (ptr *PtrInfo) Equal(o *PtrInfo) bool {
	if ptr == nil {
		return o == nil
	}
	if o == nil {
		return false
	}
	return ptr.Name == o.Name && ptr.Scope == o.Scope && ptr.Offset == o.Offset
}

// Undefined defines an undefined value.
var Undefined Value

// ValueID defines unique value IDs.
type ValueID uint32

// Check tests that the value type is properly set.
func (v Value) Check() {
	if v.Type.Undefined() {
		panic(fmt.Sprintf("v.Type == TUndefined: %v", v))
	}
	if !v.Type.Concrete() {
		panic(fmt.Sprintf("v.Type not concrete: %v", v))
	}
}

// IndirectType returns the type that v points to. If v is not a
// pointer, IndirectType returns the type of v.
func (v Value) IndirectType() types.Info {
	if v.Type.Type == types.TPtr {
		return *v.Type.ElementType
	}
	return v.Type
}

// Indirect returns Value that v points to. If v is not a pointer,
// Indirect returns v.
func (v Value) Indirect(block *Block, gen *Generator) Value {
	if v.Type.Type != types.TPtr {
		return v
	}

	// Get container value.
	b, ok := v.PtrInfo.Bindings.Get(v.PtrInfo.Name)
	if !ok {
		panic("Value.Indirect: could not find pointer target")
	}
	cv := b.Value(block, gen)
	elType := *v.Type.ElementType

	if v.PtrInfo.ContainerType.Equal(elType) {
		return cv
	}

	// The pointed value is part of container value. Let's return that
	// slice.
	ev := gen.AnonVal(elType)
	fromConst := gen.Constant(int64(v.PtrInfo.Offset), types.Undefined)
	toConst := gen.Constant(int64(v.PtrInfo.Offset+elType.Bits),
		types.Undefined)
	block.AddInstr(NewSliceInstr(cv, fromConst, toConst, ev))

	return ev
}

// ContainerType returs the pointer container type of the value. For
// non-pointer values, this returns the value type itself.
func (v Value) ContainerType() types.Info {
	if v.Type.Type == types.TPtr {
		return v.PtrInfo.ContainerType
	}
	return v.Type
}

func (v Value) String() string {
	if v.Const {
		return v.Name
	}
	if v.TypeRef {
		return fmt.Sprintf("*%v", v.Type.String())
	}
	var version string
	if v.Version >= 0 {
		version = fmt.Sprintf("%d", v.Version)
	} else {
		version = "?"
	}

	// XXX Value should have type, now we have flags and Type.Type
	if v.Type.Type == types.TPtr {
		return fmt.Sprintf("%s{%d,%s}%s{%s{%d}%s[%d-%d]}",
			v.Name, v.Scope, version, v.Type.ShortString(),
			v.PtrInfo.Name, v.PtrInfo.Scope, v.PtrInfo.ContainerType,
			v.PtrInfo.Offset, v.PtrInfo.Offset+v.Type.Bits)
	}
	return fmt.Sprintf("%s{%d,%s}%s",
		v.Name, v.Scope, version, v.Type.ShortString())
}

// ConstInt returns the value as const integer.
func (v *Value) ConstInt() (types.Size, error) {
	if !v.Const {
		return 0, errNotConstant
	}
	switch val := v.ConstValue.(type) {
	case *mpa.Int:
		return types.Size(val.Int64()), nil

	default:
		return 0, fmt.Errorf("cannot use %v as integer", val)
	}
}

// ConstArray returns the value as contant array.
func (v *Value) ConstArray() (interface{}, error) {
	if !v.Const {
		return nil, errNotConstant
	}
	switch val := v.ConstValue.(type) {
	case []interface{}:
		return val, nil

	case string:
		return []byte(val), nil

	case nil:
		return []interface{}(nil), nil

	default:
		return nil, fmt.Errorf("cannot use %v as array", val)
	}
}

// ConstString returns the value as constant string.
func (v *Value) ConstString() (string, error) {
	if !v.Const {
		return "", errNotConstant
	}
	switch val := v.ConstValue.(type) {
	case []byte:
		return string(val), nil

	case string:
		return val, nil

	default:
		return "", fmt.Errorf("cannot use %v as string", val)
	}
}

// HashCode returns a hash code for the value.
func (v *Value) HashCode() (hash int) {
	for _, r := range v.Name {
		hash = hash<<4 ^ int(r) ^ hash>>24
	}
	hash ^= int(v.Scope) << 3
	hash ^= int(v.Version) << 1

	if hash < 0 {
		hash = -hash
	}
	return
}

// Equal implements BindingValue.Equal.
func (v *Value) Equal(other BindingValue) bool {
	o, ok := other.(*Value)
	if !ok {
		return false
	}
	if o.Const != v.Const {
		return false
	}
	if o.Name != v.Name || o.Scope != v.Scope || o.Version != v.Version {
		return false
	}
	return v.PtrInfo.Equal(o.PtrInfo)
}

// Value implements BindingValue.Value.
func (v *Value) Value(block *Block, gen *Generator) Value {
	return *v
}

// Bit tests if the argument bit is set in the value.
func (v *Value) Bit(bit types.Size) bool {
	arr, ok := v.ConstValue.([]interface{})
	if ok {
		var elType types.Info

		switch v.Type.Type {
		case types.TArray, types.TSlice:
			elType = *v.Type.ElementType
		case types.TString:
			elType = types.Byte
		case types.TStruct:
			for idx, sf := range v.Type.Struct {
				if sf.Type.Bits > bit {
					return isSet(arr[idx], sf.Type, bit)
				}
				bit -= sf.Type.Bits
			}
			panic("index out of struct size")

		default:
			panic(fmt.Sprintf("invalid array constant type %v", v.Type))
		}

		elBits := elType.Bits
		length := types.Size(len(arr))
		idx := bit / elBits
		ofs := bit % elBits
		if idx >= length {
			return false
		}
		return isSet(arr[idx], elType, ofs)
	}

	return isSet(v.ConstValue, v.Type, bit)
}

func isSet(v interface{}, vt types.Info, bit types.Size) bool {
	switch val := v.(type) {
	case bool:
		if bit == 0 {
			return val
		}
		return false

	case int8:
		return (val & (1 << bit)) != 0

	case uint8:
		return (val & (1 << bit)) != 0

	case int32:
		return (val & (1 << bit)) != 0

	case uint32:
		return (val & (1 << bit)) != 0

	case int64:
		return (val & (1 << bit)) != 0

	case uint64:
		return (val & (1 << bit)) != 0

	case *big.Int:
		if bit > types.Size(val.BitLen()) {
			return false
		}
		return val.Bit(int(bit)) != 0

	case *mpa.Int:
		if bit > types.Size(val.BitLen()) {
			return false
		}
		return val.Bit(int(bit)) != 0

	case string:
		bytes := []byte(val)
		idx := bit / types.ByteBits
		mod := bit % types.ByteBits
		if idx >= types.Size(len(bytes)) {
			return false
		}
		return bytes[idx]&(1<<mod) != 0

	case Value:
		switch val.Type.Type {
		case types.TBool, types.TInt, types.TUint, types.TFloat, types.TString:
			return isSet(val.ConstValue, val.Type, bit)

		case types.TArray, types.TSlice:
			elType := val.Type.ElementType
			idx := bit / elType.Bits
			mod := bit % elType.Bits
			if idx >= val.Type.ArraySize {
				return false
			}
			arr := val.ConstValue.([]interface{})
			return isSet(arr[idx], *elType, mod)

		case types.TStruct:
			fieldValues := val.ConstValue.([]interface{})
			for idx, f := range val.Type.Struct {
				if bit < f.Type.Bits {
					return isSet(fieldValues[idx], f.Type, bit)
				}
				bit -= f.Type.Bits
			}
			fallthrough

		default:
			panic(fmt.Sprintf("ssa.isSet: invalid Value %v (%v)",
				val, val.Type))
		}

	case types.Info:
		return false

	case []interface{}:
		switch vt.Type {
		case types.TStruct:
			for idx, f := range vt.Struct {
				if bit < f.Type.Bits {
					return isSet(val[idx], f.Type, bit)
				}
				bit -= f.Type.Bits
			}
			panic(fmt.Sprintf("ssa.isSet: bit overflow for %v", vt))

		case types.TArray, types.TSlice:
			elType := vt.ElementType
			idx := bit / elType.Bits
			mod := bit % elType.Bits
			if idx >= vt.ArraySize {
				return false
			}
			return isSet(val[idx], *elType, mod)

		default:
			panic(fmt.Sprintf("ssa.isSet: type %v not supported", vt))
		}

	default:
		panic(fmt.Sprintf("ssa.isSet: non const %v (%T)", v, val))
	}
}

// CanAssign checks if the value v can be assigned for lvalue l.
func CanAssign(l types.Info, v Value) bool {
	if v.Const {
		return l.CanAssignConst(v.Type)
	}
	if !l.Concrete() && v.Type.Concrete() {
		return l.Specializable(v.Type)
	}
	if l.Type == types.TArray {
		// [N]Type = []Type - check rvalue has corrent amount of elements
		vt := v.Type
		if vt.Type == types.TPtr {
			// Dereference pointer argument.
			vt = *vt.ElementType
		}
		return vt.Type.Array() &&
			l.ArraySize == vt.ArraySize &&
			l.ElementType.Equal(*vt.ElementType)
	}
	if l.Type == types.TSlice {
		// []Type = [N]Type ok,
		vt := v.Type
		if vt.Type == types.TPtr {
			// Dereference pointer argument.
			vt = *vt.ElementType
		}
		return vt.Type.Array() && l.ElementType.Equal(*vt.ElementType)
	}
	return l.Equal(v.Type)
}

// TypeCompatible tests if the argument value is type compatible with
// this value.
func (v Value) TypeCompatible(o Value) *types.Info {
	if v.Const && o.Const {
		if v.Type.Type == o.Type.Type {
			return &v.Type
		}
	} else if v.Const {
		if o.Type.CanAssignConst(v.Type) {
			return &o.Type
		}
	} else if o.Const {
		if v.Type.CanAssignConst(o.Type) {
			return &v.Type
		}
	}
	if v.Type.Equal(o.Type) {
		return &v.Type
	}
	return nil
}

// IntegerLike tests if the value is an integer.
func (v Value) IntegerLike() bool {
	switch v.Type.Type {
	case types.TInt, types.TUint:
		return true
	default:
		return false
	}
}
