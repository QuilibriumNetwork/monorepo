//
// Copyright (c) 2020-2024 Markku Rossi
//
// All rights reserved.
//

package ast

import (
	"errors"
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ssa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// Package implements a QCL package.
type Package struct {
	Name        string
	Source      string
	Annotations Annotations
	Initialized bool
	Imports     map[string]string
	Bindings    *ssa.Bindings
	Types       []*TypeInfo
	Constants   []*ConstantDef
	Variables   []*VariableDef
	Functions   map[string]*Func
}

// NewPackage creates a new package.
func NewPackage(name, source string, annotations Annotations) *Package {
	return &Package{
		Name:        name,
		Source:      source,
		Annotations: annotations,
		Imports:     make(map[string]string),
		Bindings:    new(ssa.Bindings),
		Functions:   make(map[string]*Func),
	}
}

// Compile compiles the package.
func (pkg *Package) Compile(ctx *Codegen) (*ssa.Program, Annotations, error) {

	main, err := pkg.Main()
	if err != nil {
		return nil, nil, ctx.Error(utils.Point{
			Source: pkg.Source,
		}, err.Error())
	}

	gen := ssa.NewGenerator(ctx.Params)

	// Init is the program start point.
	init := gen.Block()

	// Init package.
	block, err := pkg.Init(ctx.Packages, init, ctx, gen)
	if err != nil {
		return nil, nil, err
	}

	// Main block derives package's bindings from block with NextBlock().
	ctx.PushCompilation(gen.NextBlock(block), gen.Block(), nil, main)

	// Arguments.
	var inputs circuit.IO
	for idx, arg := range main.Args {
		typeInfo, err := arg.Type.Resolve(NewEnv(ctx.Start()), ctx, gen)
		if err != nil {
			return nil, nil, ctx.Errorf(arg, "invalid argument type: %s", err)
		}
		if !typeInfo.Concrete() {
			if ctx.MainInputSizes == nil {
				return nil, nil,
					ctx.Errorf(arg, "argument %s of %s has unspecified type",
						arg.Name, main)
			}
			// Specify unspecified argument type.
			if idx >= len(ctx.MainInputSizes) {
				return nil, nil, ctx.Errorf(arg,
					"not enough values for argument %s of %s",
					arg.Name, main)
			}
			err = typeInfo.InstantiateWithSizes(ctx.MainInputSizes[idx])
			if err != nil {
				return nil, nil, ctx.Errorf(arg,
					"can't specify unspecified argument %s of %s: %s",
					arg.Name, main, err)
			}
		}
		// Define argument in block.
		a := gen.NewVal(arg.Name, typeInfo, ctx.Scope())
		ctx.Start().Bindings.Define(a, nil)

		input := circuit.IOArg{
			Name: arg.Name,
			Type: a.Type,
		}
		if typeInfo.Type == types.TStruct {
			input.Compound = flattenStruct(typeInfo)
		}

		inputs = append(inputs, input)
	}

	// Compile main.
	_, returnVars, err := main.SSA(ctx.Start(), ctx, gen)
	if err != nil {
		return nil, nil, err
	}

	// Return values
	var outputs circuit.IO
	for idx, rt := range main.Return {
		if idx >= len(returnVars) {
			return nil, nil, fmt.Errorf("too few values for %s", main)
		}
		typeInfo, err := rt.Type.Resolve(NewEnv(ctx.Start()), ctx, gen)
		if err != nil {
			return nil, nil, ctx.Errorf(rt, "invalid return type: %s", err)
		}
		// Instantiate result values for template functions.
		if !typeInfo.Concrete() && !typeInfo.Instantiate(returnVars[idx].Type) {
			return nil, nil, ctx.Errorf(main,
				"invalid value %v for return value %d of %s",
				returnVars[idx].Type, idx, main)
		}
		// The native() returns undefined values.
		if returnVars[idx].Type.Undefined() {
			returnVars[idx].Type.Type = typeInfo.Type
		}
		if !ssa.CanAssign(typeInfo, returnVars[idx]) {
			return nil, nil,
				ctx.Errorf(main, "invalid value %v for return value %d of %s",
					returnVars[idx].Type, idx, main)
		}

		v := returnVars[idx]
		outputs = append(outputs, circuit.IOArg{
			Name: v.String(),
			Type: v.Type,
		})
	}

	steps := init.Serialize()

	program, err := ssa.NewProgram(ctx.Params, inputs, outputs, gen.Constants(),
		steps)
	if err != nil {
		return nil, nil, err
	}
	if false { // XXX Peephole liveness analysis is broken.
		err = program.Peephole()
		if err != nil {
			return nil, nil, err
		}
	}
	program.GC()

	if ctx.Params.SSAOut != nil {
		program.PP(ctx.Params.SSAOut)
	}
	if ctx.Params.SSADotOut != nil {
		ssa.Dot(ctx.Params.SSADotOut, init)
	}

	return program, main.Annotations, nil
}

// Main returns package's main function.
func (pkg *Package) Main() (*Func, error) {
	main, ok := pkg.Functions["main"]
	if !ok {
		return nil, errors.New("no main function defined")
	}
	return main, nil
}

func flattenStruct(t types.Info) circuit.IO {
	var result circuit.IO
	if t.Type != types.TStruct {
		return result
	}

	for _, f := range t.Struct {
		if f.Type.Type == types.TStruct {
			ios := flattenStruct(f.Type)
			result = append(result, ios...)
		} else {
			result = append(result, circuit.IOArg{
				Name: f.Name,
				Type: f.Type,
			})
		}
	}

	return result
}

// Init initializes the package.
func (pkg *Package) Init(packages map[string]*Package, block *ssa.Block,
	ctx *Codegen, gen *ssa.Generator) (*ssa.Block, error) {

	if pkg.Initialized {
		return block, nil
	}
	pkg.Initialized = true
	if ctx.Verbose {
		fmt.Printf("Initializing %s\n", pkg.Name)
	}

	// Imported packages.
	for alias, name := range pkg.Imports {
		p, ok := packages[alias]
		if !ok {
			return nil, fmt.Errorf("imported and not used: \"%s\"", name)
		}
		var err error
		block, err = p.Init(packages, block, ctx, gen)
		if err != nil {
			return nil, err
		}
	}

	// Define constants.
	for _, def := range pkg.Constants {
		err := pkg.defineConstant(def, ctx, gen)
		if err != nil {
			return nil, err
		}
	}

	// Define types.
	for _, typeDef := range pkg.Types {
		err := pkg.defineType(typeDef, ctx, gen)
		if err != nil {
			return nil, err
		}
	}

	// Package initializer block.
	block = gen.NextBlock(block)
	block.Name = fmt.Sprintf(".%s", pkg.Name)

	// Package sees only its bindings.
	block.Bindings = pkg.Bindings.Clone()

	var err error

	// Define variables.
	for _, def := range pkg.Variables {
		block, _, err = def.SSA(block, ctx, gen)
		if err != nil {
			return nil, err
		}
	}

	pkg.Bindings = block.Bindings

	return block, nil
}

func (pkg *Package) defineConstant(def *ConstantDef, ctx *Codegen,
	gen *ssa.Generator) error {

	env := &Env{
		Bindings: pkg.Bindings,
	}

	typeInfo, err := def.Type.Resolve(env, ctx, gen)
	if err != nil {
		return err
	}
	constVal, ok, err := def.Init.Eval(env, ctx, gen)
	if err != nil {
		return err
	}
	if !ok {
		return ctx.Errorf(def.Init, "init value is not constant")
	}
	constVar := gen.Constant(constVal, typeInfo)
	if typeInfo.Undefined() {
		typeInfo.Type = constVar.Type.Type
	}
	if !typeInfo.Concrete() {
		typeInfo.Bits = constVar.Type.Bits
	}
	if !typeInfo.CanAssignConst(constVar.Type) {
		return ctx.Errorf(def.Init,
			"invalid init value %s for type %s", constVar.Type, typeInfo)
	}

	_, ok = pkg.Bindings.Get(def.Name)
	if ok {
		return ctx.Errorf(def, "constant %s already defined", def.Name)
	}
	lValue := constVar
	lValue.Name = def.Name
	pkg.Bindings.Define(lValue, &constVar)
	gen.AddConstant(constVal)

	return nil
}

func (pkg *Package) defineType(def *TypeInfo, ctx *Codegen,
	gen *ssa.Generator) error {

	_, ok := pkg.Bindings.Get(def.TypeName)
	if ok {
		return ctx.Errorf(def, "type %s already defined", def.TypeName)
	}
	env := &Env{
		Bindings: pkg.Bindings,
	}
	var info types.Info
	var err error

	switch def.Type {
	case TypeStruct:
		// Construct compound type.
		var fields []types.StructField
		var bits types.Size
		var minBits types.Size
		var offset types.Size
		for _, field := range def.StructFields {
			info, err := field.Type.Resolve(env, ctx, gen)
			if err != nil {
				return err
			}
			field := types.StructField{
				Name: field.Name,
				Type: info,
			}
			field.Type.Offset = offset
			fields = append(fields, field)

			bits += info.Bits
			minBits += info.MinBits
			offset += info.Bits
		}
		info = types.Info{
			Type:       types.TStruct,
			IsConcrete: true,
			Bits:       bits,
			MinBits:    minBits,
			Struct:     fields,
		}

	case TypeArray:
		info, err = def.Resolve(env, ctx, gen)
		if err != nil {
			return err
		}

	case TypeAlias:
		info, err = def.AliasType.Resolve(env, ctx, gen)
		if err != nil {
			return err
		}

	default:
		return ctx.Errorf(def, "invalid type definition: %s", def)
	}

	info.ID = ctx.DefineType(def)

	v := gen.Constant(info, types.Undefined)
	lval := gen.NewVal(def.TypeName, info, ctx.Scope())
	pkg.Bindings.Define(lval, &v)

	return nil
}
