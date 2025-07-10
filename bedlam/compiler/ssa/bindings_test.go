//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

func TestSet(t *testing.T) {
	a := new(Bindings)
	a.Define(Value{
		Name: "a",
	}, nil)

	_, ok := a.Get("a")
	if !ok {
		t.Errorf("binding for value 'a' not found")
	}
	_, ok = a.Get("b")
	if ok {
		t.Errorf("non-existing binding for value 'b' found")
	}

	a.Define(Value{
		Name: "b",
	}, nil)
	_, ok = a.Get("b")
	if !ok {
		t.Errorf("binding for value 'b' not found")
	}
}

func TestClone(t *testing.T) {
	a := new(Bindings)
	a.Define(Value{
		Name: "a",
	}, nil)
	_, ok := a.Get("a")
	if !ok {
		t.Errorf("binding for value 'a' not found")
	}

	b := a.Clone()
	_, ok = b.Get("a")
	if !ok {
		t.Errorf("binding for value 'a' not found")
	}
	b.Define(Value{
		Name: "b",
	}, nil)
	_, ok = a.Get("b")
	if ok {
		t.Errorf("non-existing binding for value 'b' found")
	}
	_, ok = b.Get("b")
	if !ok {
		t.Errorf("binding for value 'b' not found")
	}
}

func TestMerge(t *testing.T) {
	a := new(Bindings)
	b := new(Bindings)

	a.Define(Value{
		Name: "a",
		Type: types.Int32,
	}, constInt(1))
	a.Define(Value{
		Name: "b",
		Type: types.Int32,
	}, constInt(42))

	b.Define(Value{
		Name: "a",
		Type: types.Int32,
	}, constInt(2))
	merged := a.Merge(Value{
		Name: "c",
	}, b)
	if merged.Count() != 2 {
		t.Errorf("Bindings.Merge failed: #values: %d != %d", merged.Count(), 2)
	}

	bound, ok := merged.Get("b")
	if !ok {
		t.Errorf("binding for value 'b' not found")
	}
	_, ok = bound.Bound.(*Value)
	if !ok {
		t.Errorf("binding for value 'b' is not *Value: %T", bound.Bound)
	}
	bound, ok = merged.Get("a")
	if !ok {
		t.Errorf("binding for value 'a' not found")
	}
	fmt.Printf("merged.a: %v (%T)\n", bound, bound)
	_, ok = bound.Bound.(*Select)
	if !ok {
		t.Errorf("binding for value 'a' is not *Select: %T", bound.Bound)
	}
}

func constInt(i int) *Value {
	return &Value{
		Name:       fmt.Sprintf("%v/i32", i),
		Const:      true,
		Type:       types.Int32,
		ConstValue: i,
	}
}

func makeBindings(count int) *Bindings {
	b := new(Bindings)

	for i := 0; i < count; i++ {
		b.Set(Value{
			Name: fmt.Sprintf("a%d", i),
			Type: types.Int32,
		}, constInt(i))
	}

	return b
}

func BenchmarkSet(b *testing.B) {
	bindings := makeBindings(20)

	for i := 0; i < b.N; i++ {
		bindings.Set(Value{
			Name: "b",
			Type: types.Int32,
		}, constInt(i))
	}
}

func BenchmarkGet(b *testing.B) {
	bindings := makeBindings(20)

	for i := 0; i < b.N; i++ {
		_, ok := bindings.Get("b")
		if ok {
			b.Errorf("non-existing item found")
		}
	}
}

func BenchmarkClone(b *testing.B) {
	bindings := makeBindings(20)

	for i := 0; i < b.N; i++ {
		_ = bindings.Clone()
	}
}

func BenchmarkCloneModify(b *testing.B) {
	bindings := makeBindings(20)

	for i := 0; i < b.N; i++ {
		n := bindings.Clone()
		n.Set(Value{
			Name: "a",
			Type: types.Int32,
		}, constInt(i))
	}
}

func BenchmarkMerge(b *testing.B) {
	t := makeBindings(20)
	f := makeBindings(20)

	for i := 0; i < b.N; i++ {
		_ = t.Merge(Value{
			Name: "c",
		}, f)
	}
}
