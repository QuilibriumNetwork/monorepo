//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package utils

import (
	"io"
)

// Params specify compiler parameters.
type Params struct {
	Verbose      bool
	Diagnostics  bool
	SSAOut       io.WriteCloser
	SSADotOut    io.WriteCloser
	QCLCErrorLoc bool

	// PkgPath defines additional directories to search for imported
	// packages.
	PkgPath []string

	// MaxVarBits specifies the maximum variable width in bits.
	MaxVarBits int

	// MaxLoopUnroll specifies the upper limit for loop unrolling.
	MaxLoopUnroll int

	NoCircCompile bool
	CircOut       io.WriteCloser
	CircDotOut    io.WriteCloser
	CircSvgOut    io.WriteCloser
	CircFormat    string

	CircMultArrayTreshold int

	OptPruneGates bool

	BenchmarkCompile bool
}

// NewParams returns new compiler params object, initialized with the
// default values.
func NewParams() *Params {
	return &Params{
		MaxVarBits:    0x20000,
		MaxLoopUnroll: 0x20000,
	}
}

// Close closes all open resources.
func (p *Params) Close() {
	if p.SSAOut != nil {
		p.SSAOut.Close()
		p.SSAOut = nil
	}
	if p.SSADotOut != nil {
		p.SSADotOut.Close()
		p.SSADotOut = nil
	}
	if p.CircOut != nil {
		p.CircOut.Close()
		p.CircOut = nil
	}
	if p.CircDotOut != nil {
		p.CircDotOut.Close()
		p.CircDotOut = nil
	}
	if p.CircSvgOut != nil {
		p.CircSvgOut.Close()
		p.CircSvgOut = nil
	}
}
