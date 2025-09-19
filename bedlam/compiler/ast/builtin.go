//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package ast

import (
	"fmt"
	"path"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/circuits"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ssa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Builtin implements QCL builtin functions.
type Builtin struct {
	SSA  SSA
	Eval Eval
}

// SSA implements the builtin SSA generation.
type SSA func(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error)

// Eval implements the builtin evaluation in constant folding.
type Eval func(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error)

// Predeclared identifiers.
var builtins = map[string]Builtin{
	"floorPow2": {
		SSA:  floorPow2SSA,
		Eval: floorPow2Eval,
	},
	"len": {
		SSA:  lenSSA,
		Eval: lenEval,
	},
	"native": {
		SSA: nativeSSA,
	},
	"panic": {
		SSA:  panicSSA,
		Eval: panicEval,
	},
	"size": {
		SSA:  sizeSSA,
		Eval: sizeEval,
	},
}

func floorPow2SSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {
	return nil, nil, ctx.Errorf(loc, "floorPow2SSA not implemented")
}

func floorPow2Eval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to floorPow2")
	}

	constVal, _, err := args[0].Eval(env, ctx, gen)
	if err != nil {
		return ssa.Undefined, false, ctx.Errorf(loc, "%s", err)
	}

	val, err := constVal.ConstInt()
	if err != nil {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"non-integer (%T) argument in %s: %s", constVal, args[0], err)
	}

	var i types.Size
	for i = 1; i <= val; i <<= 1 {
	}
	i >>= 1

	return gen.Constant(int64(i), types.Undefined), true, nil
}

func lenSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) != 1 {
		return nil, nil, ctx.Errorf(loc,
			"invalid amount of arguments in call to len")
	}

	var val types.Size
	switch args[0].Type.Type {
	case types.TString:
		val = args[0].Type.Bits / types.ByteBits

	case types.TArray, types.TSlice:
		val = args[0].Type.ArraySize

	case types.TNil:
		val = 0

	default:
		return nil, nil, ctx.Errorf(loc, "invalid argument 1 (type %s) for len",
			args[0].Type)
	}

	v := gen.Constant(int64(val), types.Undefined)
	gen.AddConstant(v)

	return block, []ssa.Value{v}, nil
}

func lenEval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to len")
	}

	switch arg := args[0].(type) {
	case *VariableRef:
		var typeInfo types.Info

		if len(arg.Name.Package) > 0 {
			// Check if the package name is bound to a value.
			b, ok := env.Get(arg.Name.Package)
			if ok {
				if b.Type.Type != types.TStruct {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"%s undefined", arg.Name)
				}
				ok = false
				for _, f := range b.Type.Struct {
					if f.Name == arg.Name.Name {
						typeInfo = f.Type
						ok = true
						break
					}
				}
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"undefined variable '%s'", arg.Name)
				}
			} else {
				// Resolve name from the package.
				pkg, ok := ctx.Packages[arg.Name.Package]
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"package '%s' not found", arg.Name.Package)
				}
				b, ok := pkg.Bindings.Get(arg.Name.Name)
				if !ok {
					return ssa.Undefined, false, ctx.Errorf(loc,
						"undefined variable '%s'", arg.Name)
				}
				typeInfo = b.Type
			}
		} else {
			b, ok := env.Get(arg.Name.Name)
			if !ok {
				return ssa.Undefined, false, ctx.Errorf(loc,
					"undefined variable '%s'", arg.Name)
			}
			typeInfo = b.Type
		}

		if typeInfo.Type == types.TPtr {
			typeInfo = *typeInfo.ElementType
		}

		switch typeInfo.Type {
		case types.TString:
			return gen.Constant(int64(typeInfo.Bits/types.ByteBits),
				types.Undefined), true, nil

		case types.TArray, types.TSlice:
			return gen.Constant(int64(typeInfo.ArraySize), types.Undefined),
				true, nil

		default:
			return ssa.Undefined, false, ctx.Errorf(loc,
				"invalid argument 1 (type %s) for len", typeInfo)
		}

	default:
		return ssa.Undefined, false, ctx.Errorf(loc,
			"len(%v/%T) is not constant", arg, arg)
	}
}

func nativeSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) < 1 {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	}
	name, ok := args[0].ConstValue.(string)
	if !args[0].Const || !ok {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	}
	// Our native name constant is not needed in the implementation.
	gen.RemoveConstant(args[0])
	args = args[1:]

	switch name {
	case "hamming":
		if len(args) != 2 {
			return nil, nil, ctx.Errorf(loc,
				"invalid amount of arguments in call to '%s'", name)
		}

		var typeInfo types.Info
		for _, arg := range args {
			if arg.Type.Bits > typeInfo.Bits {
				typeInfo = arg.Type
			}
		}

		v := gen.AnonVal(typeInfo)
		block.AddInstr(ssa.NewBuiltinInstr(circuits.Hamming, args[0], args[1],
			v))

		return block, []ssa.Value{v}, nil

	default:
		if circuit.IsFilename(name) {
			return nativeCircuit(name, block, ctx, gen, args, loc)
		}
		return nil, nil, ctx.Errorf(loc, "unknown native '%s'", name)
	}
}

func nativeCircuit(name string, block *ssa.Block, ctx *Codegen,
	gen *ssa.Generator, args []ssa.Value, loc utils.Point) (
	*ssa.Block, []ssa.Value, error) {

	dir := path.Dir(loc.Source)
	fp := path.Join(dir, name)

	var err error

	circ, ok := ctx.Native[fp]
	if !ok {
		circ, err = circuit.Parse(fp)
		if err != nil {
			return nil, nil, ctx.Errorf(loc, "failed to parse circuit: %s", err)
		}
		circ.AssignLevels()
		ctx.Native[fp] = circ
		if ctx.Verbose {
			fmt.Printf(" - native %s: %v\n", name, circ)
		}
	} else if ctx.Verbose {
		fmt.Printf(" - native %s: cached\n", name)
	}

	if len(circ.Inputs) > len(args) {
		return nil, nil, ctx.Errorf(loc,
			"not enough arguments in call to native")
	} else if len(circ.Inputs) < len(args) {
		return nil, nil, ctx.Errorf(loc, "too many argument in call to native")
	}
	// Check that the argument types match.
	for idx, io := range circ.Inputs {
		arg := args[idx]
		if io.Type.Bits < arg.Type.Bits || io.Type.Bits > arg.Type.Bits &&
			!arg.Const {
			return nil, nil, ctx.Errorf(loc,
				"invalid argument %d for native circuit: got %s, need %d",
				idx, arg.Type, io.Type.Bits)
		}
	}

	var result []ssa.Value

	for _, io := range circ.Outputs {
		result = append(result, gen.AnonVal(types.Info{
			Type:       types.TUndefined,
			IsConcrete: true,
			Bits:       io.Type.Bits,
		}))
	}

	block.AddInstr(ssa.NewCircInstr(args, circ, result))

	return block, result, nil
}

func panicSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	var arr []string
	for _, arg := range args {
		var str string
		if arg.Const {
			str = fmt.Sprintf("%v", arg.ConstValue)
		} else {
			str = arg.String()
		}
		arr = append(arr, str)
	}

	return nil, nil, ctx.Errorf(loc, "panic: %v", panicMessage(arr))
}

func panicEval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	var arr []string
	for _, arg := range args {
		arr = append(arr, arg.String())
	}

	return ssa.Undefined, false, ctx.Errorf(loc, "panic: %v", panicMessage(arr))
}

func panicMessage(args []string) string {
	if len(args) == 0 {
		return ""
	}
	format := args[0]
	args = args[1:]

	var result string

	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			result += string(format[i])
			continue
		}
		i++
		if len(args) == 0 {
			result += fmt.Sprintf("%%!%c(MISSING)", format[i])
			continue
		}
		switch format[i] {
		case 'v':
			result += args[0]
		default:
			result += fmt.Sprintf("%%!%c(%v)", format[i], args[0])
		}
		args = args[1:]
	}

	for _, arg := range args {
		result += " " + arg
	}

	return result
}

func sizeSSA(block *ssa.Block, ctx *Codegen, gen *ssa.Generator,
	args []ssa.Value, loc utils.Point) (*ssa.Block, []ssa.Value, error) {

	if len(args) != 1 {
		return nil, nil, ctx.Errorf(loc,
			"invalid amount of arguments in call to size")
	}

	v := gen.Constant(int64(args[0].Type.Bits), types.Undefined)
	gen.AddConstant(v)

	return block, []ssa.Value{v}, nil
}

func sizeEval(args []AST, env *Env, ctx *Codegen, gen *ssa.Generator,
	loc utils.Point) (ssa.Value, bool, error) {

	if len(args) != 1 {
		return ssa.Undefined, false, ctx.Errorf(loc,
			"invalid amount of arguments in call to size")
	}

	switch arg := args[0].(type) {
	case *VariableRef:
		var b ssa.Binding
		var ok bool

		if len(arg.Name.Package) > 0 {
			var pkg *Package
			pkg, ok = ctx.Packages[arg.Name.Package]
			if !ok {
				return ssa.Undefined, false, ctx.Errorf(loc,
					"package '%s' not found", arg.Name.Package)
			}
			b, ok = pkg.Bindings.Get(arg.Name.Name)
		} else {
			b, ok = env.Get(arg.Name.Name)
		}
		if !ok {
			return ssa.Undefined, false, ctx.Errorf(loc,
				"undefined variable '%s'", arg.Name.String())
		}
		return gen.Constant(int64(b.Type.Bits), types.Undefined), true, nil

	default:
		return ssa.Undefined, false, ctx.Errorf(loc,
			"size(%v/%T) is not constant", arg, arg)
	}
}
