package compiler

import (
	"fmt"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

func TestCompileError(t *testing.T) {
	t.Run("test compile error message without location", func(t *testing.T) {
		err := CompileError{
			Stage:     CompileStageParse,
			SourcePos: "file:1:1",
			Err:       fmt.Errorf("error message"),
		}
		want := "Compile error [parse]: error message\nfile:1:1"
		got := err.Error()
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("test compile error message with location", func(t *testing.T) {
		err := CompileError{
			Stage:     CompileStageParse,
			SourcePos: "func main(a, b int4 int4",
			Location:  &utils.Point{Source: "file", Line: 1, Col: 1},
			Err:       fmt.Errorf("error message"),
		}
		want := "Compile error [parse]: error message, file:1:1\nfunc main(a, b int4 int4"
		got := err.Error()
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
