//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

var (
	_ BindingValue = &Value{}
	_ BindingValue = &Select{}
)

// Bindings defines value bindings.
type Bindings struct {
	shared bool
	Values []Binding
}

// Debug prints the bindings.
func (bindings *Bindings) Debug() {
	fmt.Printf("Bindings: shared=%v, Values=[\n", bindings.shared)
	for _, value := range bindings.Values {
		fmt.Printf("\t%s,\n", value)
	}
	fmt.Println("]")
}

// Count returns the number of variable bindings the Bindings
// contains.
func (bindings *Bindings) Count() int {
	return len(bindings.Values)
}

// Clone makes a copy of the bindings.
func (bindings Bindings) Clone() *Bindings {
	result := &Bindings{
		shared: true,
		Values: bindings.Values,
	}
	bindings.shared = true

	return result
}

// Define defines name v in the bindings.  The argument val specifies
// an optional value for the name. If val is nil, the value of the
// name will be v.
func (bindings *Bindings) Define(v Value, val *Value) {
	bindings.set(v, v.Type, val)
}

// Set sets a new binding for the name. It is an error if the name is
// not defined.
func (bindings *Bindings) Set(v Value, val *Value) error {
	b, ok := bindings.Get(v.Name)
	if !ok {
		return fmt.Errorf("name %s not defined", v.Name)
	}
	bindings.set(v, b.Type, val)
	return nil
}

func (bindings *Bindings) set(v Value, t types.Info, val *Value) {
	if bindings.shared {
		// Make our own copy of the values.
		values := make([]Binding, len(bindings.Values))
		copy(values, bindings.Values)
		bindings.Values = values
		bindings.shared = false
	}

	for idx, b := range bindings.Values {
		if b.Name == v.Name && b.Scope == v.Scope {
			b.Type = t
			if val != nil {
				b.Bound = val
			} else {
				b.Bound = &v
			}
			bindings.Values[idx] = b
			return
		}
	}

	b := Binding{
		Name:  v.Name,
		Scope: v.Scope,
		Type:  t,
	}
	if val != nil {
		b.Bound = val
	} else {
		b.Bound = &v
	}

	bindings.Values = append(bindings.Values, b)
}

// Get gets the value binding.
func (bindings Bindings) Get(name string) (ret Binding, ok bool) {
	for _, b := range bindings.Values {
		if b.Name == name {
			if len(ret.Name) == 0 || b.Scope > ret.Scope {
				ret = b
			}
		}
	}
	if len(ret.Name) == 0 {
		return ret, false
	}
	return ret, true
}

func contains(values []Binding, name string) bool {
	for _, v := range values {
		if v.Name == name {
			return true
		}
	}
	return false
}

// Merge merges the argument false-branch bindings into this bindings
// instance that represents the true-branch values.
func (bindings Bindings) Merge(cond Value, falseBindings *Bindings) *Bindings {
	var result []Binding
	for _, b := range bindings.Values {
		name := b.Name
		if contains(result, name) {
			continue
		}

		bTrue, okTrue := bindings.Get(name)
		bFalse, okFalse := falseBindings.Get(name)
		if !okTrue && !okFalse {
			continue
		} else if !okTrue {
			result = append(result, bFalse)
		} else if !okFalse {
			result = append(result, bTrue)
		} else {
			if bTrue.Bound.Equal(bFalse.Bound) {
				result = append(result, bTrue)
			} else {
				var phiType types.Info
				if bTrue.Type.Bits > bFalse.Type.Bits {
					phiType = bTrue.Type
				} else {
					phiType = bFalse.Type
				}

				result = append(result, Binding{
					Name:  name,
					Scope: bTrue.Scope,
					Type:  phiType,
					Bound: &Select{
						Cond:  cond,
						Type:  phiType,
						True:  bTrue.Bound,
						False: bFalse.Bound,
					},
				})
			}
		}
	}
	return &Bindings{
		Values: result,
	}
}

// Binding implements a value binding.
type Binding struct {
	Name  string
	Scope Scope
	Type  types.Info
	Bound BindingValue
}

func (b Binding) String() string {
	return fmt.Sprintf("%s@%d/%s=%s", b.Name, b.Scope, b.Type, b.Bound)
}

// Value returns the binding value.
func (b Binding) Value(block *Block, gen *Generator) Value {
	return b.Bound.Value(block, gen)
}

// BindingValue represents value binding.
type BindingValue interface {
	Equal(o BindingValue) bool
	Value(block *Block, gen *Generator) Value
}

// Select implements Phi-bindings for value.
type Select struct {
	Cond     Value
	Type     types.Info
	True     BindingValue
	False    BindingValue
	Resolved Value
}

func (phi *Select) String() string {
	return fmt.Sprintf("\u03D5(%s|%s|%s)/%s",
		phi.Cond, phi.True, phi.False, phi.Type)
}

// Equal tests if this select binding is equal to the argument bindind
// value.
func (phi *Select) Equal(other BindingValue) bool {
	o, ok := other.(*Select)
	if !ok {
		return false
	}
	if !phi.Cond.Equal(&o.Cond) {
		return false
	}
	return phi.True.Equal(o.True) && phi.False.Equal(o.False)
}

// Value returns the binding value.
func (phi *Select) Value(block *Block, gen *Generator) Value {
	if phi.Resolved.Type.Type != types.TUndefined {
		return phi.Resolved
	}

	t := phi.True.Value(block, gen)
	f := phi.False.Value(block, gen)
	v := gen.AnonVal(phi.Type)
	block.AddInstr(NewPhiInstr(phi.Cond, t, f, v))

	phi.Resolved = v

	return v
}
