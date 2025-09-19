//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package circuits

import (
	"testing"
)

func TestWire(t *testing.T) {
	w := calloc.Wire()
	if w.ID() != UnassignedID {
		t.Error("w.ID")
	}
	w.SetID(42)
	if w.ID() != 42 {
		t.Error("w.SetID")
	}
	if !w.Assigned() {
		t.Error("Assigned")
	}
	if w.Output() {
		t.Error("Output")
	}
	w.SetOutput(true)
	if !w.Output() {
		t.Error("SetOutput")
	}
	if w.Value() != Unknown {
		t.Error("Value")
	}
	w.SetValue(One)
	if w.Value() != One {
		t.Error("SetValue")
	}
	if w.NumOutputs() != 0 {
		t.Error("NumOutputs")
	}
	w.SetNumOutputs(42)
	if w.NumOutputs() != 42 {
		t.Error("SetNumOutputs")
	}
	w.SetNumOutputs(1)
	if w.NumOutputs() != 1 {
		t.Error("SetNumOutputs")
	}
	if w.Input() != nil {
		t.Error("Input")
	}
	gate := &Gate{}
	w.SetInput(gate)
	if w.Input() != gate {
		t.Error("SetInput")
	}

	w.Reset(UnassignedID)
	if w.Output() {
		t.Error("Reset: Output")
	}
	if w.Value() != Unknown {
		t.Error("Reset: Value")
	}
	if w.ID() != UnassignedID {
		t.Error("Reset: ID")
	}
	if !w.IsInput() {
		t.Error("Reset: IsInput")
	}
	if w.NumOutputs() != 0 {
		t.Error("Reset: NumOutputs")
	}
}
