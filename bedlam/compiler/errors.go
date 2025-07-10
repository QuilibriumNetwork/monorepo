package compiler

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

type CompileError struct {
	Stage     CompileStage // "parse", "compile", "circuit"
	SourcePos string
	Location  *utils.Point
	Err       error // origin error
}

type CompileStage int

const (
	CompileStageParse CompileStage = iota
	CompileStageCompile
	CompileStageCircuit
)

var stateName = map[CompileStage]string{
	CompileStageParse:   "parse",
	CompileStageCompile: "compile",
	CompileStageCircuit: "circuit",
}

func (cs CompileStage) String() string {
	return stateName[cs]
}

func (e *CompileError) Error() string {
	msg := fmt.Sprintf("Compile error [%s]: %v", e.Stage, e.Err)
	if e.Location != nil {
		msg += fmt.Sprintf(", %s", e.Location)
	}
	if e.SourcePos != "" {
		msg += fmt.Sprintf("\n%s", e.SourcePos)
	}
	return msg
}
