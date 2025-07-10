//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ast"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/p2p"
)

// Compiler implements QCL compiler.
type Compiler struct {
	params   *utils.Params
	packages map[string]*ast.Package
	pkgPath  string
}

type pkgPath struct {
	precond string
	env     string
	prefix  string
}

// New creates a new compiler instance.
func New(params *utils.Params) *Compiler {
	return &Compiler{
		params:   params,
		packages: make(map[string]*ast.Package),
	}
}

// Compile compiles the input program.
func (c *Compiler) Compile(data string, inputSizes [][]int) (
	*circuit.Circuit, ast.Annotations, error) {
	return c.compile("{data}", strings.NewReader(data), inputSizes)
}

// CompileFile compiles the input file.
func (c *Compiler) CompileFile(file string, inputSizes [][]int) (
	*circuit.Circuit, ast.Annotations, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return c.compile(file, f, inputSizes)
}

// ParseFile parses the input file.
func (c *Compiler) ParseFile(file string) (*ast.Package, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	logger := utils.NewLogger(os.Stdout)
	return c.parse(file, f, logger, nil)
}

func (c *Compiler) Parse(data string) (*ast.Package, error) {
	logger := utils.NewLogger(io.Discard)
	return c.parse("{data}", strings.NewReader(data), logger, ast.NewPackage("main", "{data}", nil))
}

func (c *Compiler) compile(source string, in io.Reader, inputSizes [][]int) (
	*circuit.Circuit, ast.Annotations, error) {

	logger := utils.NewLogger(os.Stdout)
	pkg, err := c.parse(source, in, logger, ast.NewPackage("main", source, nil))
	if err != nil {
		return nil, nil, err
	}

	ctx := ast.NewCodegen(logger, pkg, c.packages, c.params, inputSizes)

	program, annotation, err := pkg.Compile(ctx)
	if err != nil {
		return nil, nil, err
	}
	if c.params.NoCircCompile {
		return nil, annotation, nil
	}
	circ, err := program.CompileCircuit(c.params)
	if err != nil {
		return nil, nil, err
	}
	return circ, annotation, nil
}

// StreamFile compiles the input program and uses the streaming mode
// to garble and stream the circuit to the evaluator node.
func (c *Compiler) StreamFile(conn *p2p.Conn, oti ot.OT, file string,
	input []string, inputSizes [][]int) (circuit.IO, []*big.Int, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return c.stream(conn, oti, file, f, input, inputSizes)
}

func (c *Compiler) stream(conn *p2p.Conn, oti ot.OT, source string,
	in io.Reader, inputFlag []string, inputSizes [][]int) (
	circuit.IO, []*big.Int, error) {

	timing := circuit.NewTiming()

	logger := utils.NewLogger(os.Stdout)
	pkg, err := c.parse(source, in, logger, ast.NewPackage("main", source, nil))
	if err != nil {
		return nil, nil, err
	}

	ctx := ast.NewCodegen(logger, pkg, c.packages, c.params, inputSizes)

	program, _, err := pkg.Compile(ctx)
	if err != nil {
		return nil, nil, err
	}

	timing.Sample("Compile", nil)

	if c.params.BenchmarkCompile {
		fmt.Println("BenchmarkCompile")
		return nil, nil, nil
	}

	if len(program.Inputs) != 2 {
		return nil, nil,
			fmt.Errorf("invalid program for 2-party computation: %d parties",
				len(program.Inputs))
	}
	input, err := program.Inputs[0].Parse(inputFlag)
	if err != nil {
		main, err2 := pkg.Main()
		if err2 != nil {
			return nil, nil, err
		}
		return nil, nil, ctx.Errorf(main.Location(), "%s: %v", main.Name, err)
	}

	fmt.Printf(" + In1: %s\n", program.Inputs[0])
	fmt.Printf(" - In2: %s\n", program.Inputs[1])
	fmt.Printf(" - Out: %s\n", program.Outputs)
	fmt.Printf(" -  In: %s\n", inputFlag)

	out, bits, err := program.Stream(conn, oti, c.params, input, timing)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	// if false {
	program.StreamDebug()
	// }
	return out, bits, err
}

func (c *Compiler) parse(source string, in io.Reader, logger *utils.Logger,
	pkg *ast.Package) (*ast.Package, error) {

	parser := NewParser(source, c, logger, in)
	pkg, err := parser.Parse(pkg)
	if err != nil {
		return nil, err
	}
	c.packages[pkg.Name] = pkg

	for alias, name := range pkg.Imports {
		_, err := c.parsePkg(alias, name, source)
		if err != nil {
			return nil, err
		}
	}

	return pkg, nil
}

func (c *Compiler) resolvePkgPath() error {
	if len(c.pkgPath) != 0 {
		return nil
	}

	for _, pkgPath := range pkgPaths {
		// Check path precondition.
		if len(pkgPath.precond) > 0 {
			_, ok := os.LookupEnv(pkgPath.precond)
			if !ok {
				continue
			}
		}
		dir := path.Join(os.Getenv(pkgPath.env), pkgPath.prefix)
		df, err := os.Open(dir)
		if err != nil {
			continue
		}
		defer df.Close()
		fi, err := df.Stat()
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("pkg root is not directory: %s", dir)
		}
		c.pkgPath = dir
		break
	}
	if len(c.pkgPath) == 0 {
		fmt.Printf("could not resolve pkg root directory, tried:\n")
		for _, pkgPath := range pkgPaths {
			if len(pkgPath.precond) > 0 {
				fmt.Printf(" - $(%s):\n", pkgPath.precond)
			} else {
				fmt.Printf(" - *:\n")
			}
			fmt.Printf("   - $(%s)/%s\n", pkgPath.env, pkgPath.prefix)
		}
		return fmt.Errorf("could not find pkg root directory")
	}
	if c.params.Verbose {
		fmt.Printf("found PkgRoot from '%s'\n", c.pkgPath)
	}
	return nil
}

var pkgPaths = []*pkgPath{
	{
		precond: "QCLDIR",
		env:     "QCLDIR",
		prefix:  "pkg",
	},
	{
		precond: "GITHUB_WORKFLOW",
		env:     "GITHUB_WORKSPACE",
		prefix:  "pkg",
	},
	{
		env:    "HOME",
		prefix: "go/src/source.quilibrium.com/quilibrium/monorepo/bedlam/pkg",
	},
}

func (c *Compiler) parsePkg(alias, name, source string) (*ast.Package, error) {
	pkg, ok := c.packages[alias]
	if ok {
		return pkg, nil
	}
	pkg = ast.NewPackage(alias, source, nil)

	err := c.resolvePkgPath()
	if err != nil {
		return nil, err
	}

	if c.params.Verbose {
		fmt.Printf("looking for package %s (%s)\n", alias, name)
	}

	var dirs []string
	dirs = append(dirs, c.pkgPath)
	dirs = append(dirs, c.params.PkgPath...)

	for _, dir := range dirs {
		pkg, ok, err := c.tryParsePkg(pkg, dir, name)
		if err != nil {
			return nil, err
		}
		if ok {
			return pkg, nil
		}
	}
	return nil, fmt.Errorf("package %s not found", name)
}

func (c *Compiler) tryParsePkg(pkg *ast.Package, prefix, name string) (
	*ast.Package, bool, error) {

	dir := path.Join(prefix, name)
	df, err := os.Open(dir)
	if err != nil {
		return nil, false, nil
	}
	defer df.Close()

	files, err := df.Readdirnames(-1)
	if err != nil {
		return nil, false, fmt.Errorf("package %s not found: %s", name, err)
	}
	var qcls []string
	for _, f := range files {
		if strings.HasSuffix(f, ".qcl") {
			qcls = append(qcls, f)
		}
	}
	if len(qcls) == 0 {
		return nil, false, fmt.Errorf("package %s is empty", name)
	}

	for _, qcl := range qcls {
		fp := path.Join(dir, qcl)

		if c.params.Verbose {
			fmt.Printf(" - parsing @%v\n", fp[len(c.pkgPath):])
		}

		f, err := os.Open(fp)
		if err != nil {
			fmt.Printf("pkg not found: %s\n", err)
			return nil, false, fmt.Errorf("error reading package %s: %s",
				name, err)
		}
		defer f.Close()

		pkg, err = c.parse(fp, f, utils.NewLogger(os.Stdout), pkg)
		if err != nil {
			return nil, false, err
		}
	}
	return pkg, true, nil
}
