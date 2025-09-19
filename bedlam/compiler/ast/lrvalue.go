//
// ast.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package ast

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ssa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// LRValue implements value as l-value or r-value. The LRValues have
// two types:
//
//  1. base type that specifies the base memory location containing
//     the value
//  2. value type that specifies the wires of the value
//
// Both types can be the same. The base and value types are set as
// follows for different names:
//
// 1. Struct.Field:
//   - baseInfo points to the containing variable
//   - baseValue is the Struct
//   - structField defines the structure field
//   - valueType is the type of the Struct.Field
//   - value is nil
//
// 2. Package.Name:
//   - baseInfo points to the containing variable in Package
//   - baseValue is the value of Package.Name
//   - structField is nil
//   - valueType is the type of Package.Name
//   - value is the value of Package.Name
//
// 3. Name:
//   - baseInfo points to the containing local variable
//   - baseValue is the value of Name
//   - structField is nil
//   - valueType is the type of Name
//   - value is the value of Name
type LRValue struct {
	ctx         *Codegen
	ast         AST
	block       *ssa.Block
	gen         *ssa.Generator
	baseInfo    *ssa.PtrInfo
	baseValue   ssa.Value
	valueType   types.Info
	value       ssa.Value
	structField *types.StructField
}

func (lrv LRValue) String() string {
	offset := lrv.baseInfo.Offset + lrv.valueType.Offset
	return fmt.Sprintf("%s[%d-%d]@%s{%d}%s/%v",
		lrv.valueType, offset, offset+lrv.valueType.Bits,
		lrv.baseInfo.Name, lrv.baseInfo.Scope, lrv.baseInfo.ContainerType,
		lrv.baseInfo.ContainerType.Bits)
}

// BaseType returns the base type of the LRValue.
func (lrv *LRValue) BaseType() types.Info {
	return lrv.baseInfo.ContainerType
}

// BaseValue returns the base value of the LRValue
func (lrv *LRValue) BaseValue() ssa.Value {
	return lrv.baseValue
}

// BasePtrInfo returns the base value as PtrInfo.
func (lrv *LRValue) BasePtrInfo() *ssa.PtrInfo {
	return lrv.baseInfo
}

// Indirect returns LRValue for the value that lrv points to. If lrv
// is not a pointer, Indirect returns lrv.
func (lrv *LRValue) Indirect() *LRValue {
	v := lrv.RValue()
	if v.Type.Type != types.TPtr {
		return lrv
	}

	ret := *lrv
	ret.valueType = *lrv.valueType.ElementType
	ret.value.PtrInfo = nil

	if lrv.baseInfo.ContainerType.Type == types.TStruct {
		// Set value to undefined so RValue() can regenerate it.
		ret.value.Type = types.Undefined

		// Lookup struct field.
		ret.structField = nil
		for idx, f := range lrv.baseValue.Type.Struct {
			if f.Type.Offset == lrv.baseInfo.Offset {
				ret.structField = &lrv.baseValue.Type.Struct[idx]
				break
			}
		}
		if ret.structField == nil {
			panic("LRValue.Indirect: could not find struct field")
		}
	} else {
		ret.value.Type = *lrv.value.Type.ElementType
		ret.value = lrv.baseValue
	}

	return &ret
}

// Set sets the l-value to rv.
func (lrv LRValue) Set(rv ssa.Value) error {
	if !ssa.CanAssign(lrv.valueType, rv) {
		return fmt.Errorf("cannot assing %v to variable of type %v",
			rv.Type, lrv.valueType)
	}
	lValue := lrv.LValue()

	if lrv.structField != nil {
		fromConst := lrv.gen.Constant(int64(lrv.structField.Type.Offset),
			types.Undefined)
		toConst := lrv.gen.Constant(int64(lrv.structField.Type.Offset+
			lrv.structField.Type.Bits), types.Undefined)

		lrv.block.AddInstr(ssa.NewAmovInstr(rv, lrv.baseValue,
			fromConst, toConst, lValue))
		return lrv.baseInfo.Bindings.Set(lValue, nil)
	}

	if rv.Const && rv.IntegerLike() {
		// Type coersions rules for const int r-values.
		if lValue.Type.Concrete() {
			rv.Type = lValue.Type
		} else if rv.Type.Concrete() {
			lValue.Type = rv.Type
		} else {
			return fmt.Errorf("unspecified size for type %v", rv.Type)
		}
	} else if rv.Type.Concrete() {
		// Specifying the value of an unspecified variable, or
		// specializing it (assining arrays with values of different
		// size).
		lValue.Type = rv.Type
	} else if lValue.Type.Concrete() {
		// Specializing r-value.
		rv.Type = lValue.Type
	} else {
		return fmt.Errorf("unspecified size for type %v", rv.Type)
	}
	lrv.block.AddInstr(ssa.NewMovInstr(rv, lValue))

	// The l-value and r-value types are now resolved. Let's define
	// the variable with correct type and value information,
	// overriding any old values.
	lrv.baseInfo.Bindings.Define(lValue, &rv)

	return nil
}

// LValue returns the l-value of the LRValue.
func (lrv *LRValue) LValue() ssa.Value {
	return lrv.gen.NewVal(lrv.baseInfo.Name, lrv.baseInfo.ContainerType,
		lrv.baseInfo.Scope)
}

// RValue returns the r-value of the LRValue.
func (lrv *LRValue) RValue() ssa.Value {
	if lrv.value.Type.Undefined() && lrv.structField != nil {
		fieldType := lrv.valueType
		fieldType.Offset = 0

		lrv.value = lrv.gen.AnonVal(fieldType)

		from := int64(lrv.valueType.Offset)
		to := int64(lrv.valueType.Offset + lrv.valueType.Bits)

		if to > from {
			fromConst := lrv.gen.Constant(from, types.Undefined)
			toConst := lrv.gen.Constant(to, types.Undefined)
			lrv.block.AddInstr(ssa.NewSliceInstr(lrv.baseValue, fromConst,
				toConst, lrv.value))
		}
	}
	return lrv.value
}

// ValueType returns the value type of the LRValue.
func (lrv *LRValue) ValueType() types.Info {
	return lrv.valueType
}

func (lrv *LRValue) ptrBaseValue() (ssa.Value, error) {
	b, ok := lrv.baseInfo.Bindings.Get(lrv.baseInfo.Name)
	if !ok {
		return ssa.Undefined, fmt.Errorf("undefined: %s", lrv.baseInfo.Name)
	}
	return b.Value(lrv.block, lrv.gen), nil
}

// ConstValue returns the constant value of the LRValue if available.
func (lrv *LRValue) ConstValue() (ssa.Value, bool, error) {
	switch lrv.value.Type.Type {
	case types.TUndefined:
		return lrv.value, false, nil

	case types.TBool, types.TInt, types.TUint, types.TFloat, types.TString,
		types.TStruct, types.TArray, types.TSlice, types.TNil:
		return lrv.value, true, nil

	default:
		return ssa.Undefined, false, lrv.ctx.Errorf(lrv.ast,
			"LRValue.ConstValue: %s not supported yet: %v",
			lrv.value.Type, lrv.value)
	}
}

// LookupVar resolves the named variable from the context.
func (ctx *Codegen) LookupVar(block *ssa.Block, gen *ssa.Generator,
	bindings *ssa.Bindings, ref *VariableRef) (
	lrv *LRValue, cf, df bool, err error) {

	lrv = &LRValue{
		ctx:   ctx,
		ast:   ref,
		block: block,
		gen:   gen,
	}

	var env *ssa.Bindings
	var b ssa.Binding
	var ok bool

	if len(ref.Name.Package) > 0 {
		// Check if package name is bound to a value.
		b, ok = bindings.Get(ref.Name.Package)
		if ok {
			env = bindings
		} else {
			// Check names in the current package.
			b, ok = ctx.Package.Bindings.Get(ref.Name.Package)
			if ok {
				env = ctx.Package.Bindings
			}
		}
		if ok {
			if block != nil {
				lrv.baseValue = b.Value(block, gen)
			} else {
				// Evaluating a const value.
				v, ok := b.Bound.(*ssa.Value)
				if !ok || !v.Const {
					// Value is not const
					return nil, false, false, nil
				}
				lrv.baseValue = *v
			}

			if lrv.baseValue.Type.Type == types.TPtr {
				lrv.baseInfo = lrv.baseValue.PtrInfo
				lrv.baseValue, err = lrv.ptrBaseValue()
				if err != nil {
					return nil, false, false, err
				}
			} else {
				lrv.baseInfo = &ssa.PtrInfo{
					Name:          ref.Name.Package,
					Bindings:      env,
					Scope:         b.Scope,
					ContainerType: b.Type,
				}
			}

			if lrv.baseValue.Type.Type != types.TStruct {
				return nil, false, false, fmt.Errorf("%s undefined", ref.Name)
			}

			for _, f := range lrv.baseValue.Type.Struct {
				if f.Name == ref.Name.Name {
					lrv.structField = &f
					break
				}
			}
			if lrv.structField == nil {
				return nil, false, false, fmt.Errorf(
					"%s undefined (type %s has no field or method %s)",
					ref.Name, lrv.baseValue.Type, ref.Name.Name)
			}
			lrv.valueType = lrv.structField.Type

			return lrv, true, false, nil
		}
	}

	// Explicit package references.
	var pkg *Package
	if len(ref.Name.Package) > 0 {
		pkg, ok = ctx.Packages[ref.Name.Package]
		if !ok {
			return nil, false, false, fmt.Errorf("package '%s' not found",
				ref.Name.Package)
		}
		env = pkg.Bindings
		b, ok = env.Get(ref.Name.Name)
		if !ok {
			return nil, false, false, fmt.Errorf("undefined variable '%s'",
				ref.Name)
		}
	} else {
		// Check block bindings.
		env = bindings
		b, ok = env.Get(ref.Name.Name)
		if !ok {
			// Check names in the name's package.
			if len(ref.Name.Defined) > 0 {
				pkg, ok = ctx.Packages[ref.Name.Defined]
				if !ok {
					return nil, false, false,
						fmt.Errorf("package '%s' not found", ref.Name.Defined)
				}
				env = pkg.Bindings
				b, ok = env.Get(ref.Name.Name)
			}
		}
	}
	if !ok {
		return nil, false, true, fmt.Errorf("undefined variable '%s'",
			ref.Name)
	}

	if block != nil {
		lrv.value = b.Value(block, gen)
	} else {
		// Evaluating const value.
		v, ok := b.Bound.(*ssa.Value)
		if !ok || !v.Const {
			// Value is not const
			return nil, false, false, nil
		}
		lrv.value = *v
	}
	lrv.valueType = lrv.value.Type

	if lrv.value.Type.Type == types.TPtr {
		lrv.baseInfo = lrv.value.PtrInfo
		lrv.baseValue, err = lrv.ptrBaseValue()
		if err != nil {
			return nil, false, false, err
		}
	} else {
		lrv.baseInfo = &ssa.PtrInfo{
			Name:          ref.Name.Name,
			Bindings:      env,
			Scope:         b.Scope,
			ContainerType: b.Type,
		}
		lrv.baseValue = lrv.value
	}

	return lrv, true, false, nil
}
