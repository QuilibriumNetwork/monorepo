//
// Copyright (c) 2020-2021 Markku Rossi
//
// All rights reserved.
//

package ssa

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule defines a peephole optimization rule.
type Rule struct {
	Name    string
	Source  string
	Pattern []Template
	Replace []Template
}

// Template defines an instruction template.
type Template struct {
	Op  Operand
	In  []string
	Out string
}

// Expand expands the template with given environment bindings.
func (t Template) Expand(env map[string]Value) (Instr, error) {
	var in []Value
	var out Value

	for _, i := range t.In {
		v, ok := env[i]
		if !ok {
			return Instr{}, fmt.Errorf("input value %s not bound", i)
		}
		in = append(in, v)
	}
	out, ok := env[t.Out]
	if !ok {
		return Instr{}, fmt.Errorf("output value %s not bound", t.Out)
	}

	return Instr{
		Op:  t.Op,
		In:  in,
		Out: &out,
	}, nil
}

// Match tests if the rule matches the steps span.
func (rule Rule) Match(steps []Step) []Step {
	env := make(map[string]Value)

	// Match all patterns
	for idx, p := range rule.Pattern {
		step := steps[idx]
		if step.Instr.Op != p.Op {
			return nil
		}
		if len(step.Instr.In) != len(p.In) {
			return nil
		}
		for i, in := range p.In {
			if !matchVar(env, in, step.Instr.In[i]) {
				return nil
			}
		}
		if step.Instr.Out == nil {
			return nil
		}
		if !matchVar(env, p.Out, *step.Instr.Out) {
			return nil
		}
	}

	var result []Step
	for _, r := range rule.Replace {
		instr, err := r.Expand(env)
		if err != nil {
			fmt.Printf("template expansion failed: %s\n", err)
			return nil
		}

		// Base liveness from the first replaced instruction.
		live := steps[0].Live.Copy()
		if instr.Out != nil {
			live.Add(*instr.Out)
		}

		result = append(result, Step{
			Instr: instr,
			Live:  live,
		})
	}

	return result
}

func matchVar(env map[string]Value, pattern string, v Value) bool {
	binding, ok := env[pattern]
	if ok {
		// Pattern already bound, must be equal binding.
		return v.Equal(&binding)
	}
	switch pattern[0] {
	case 'V':
	case 'C':
		if !v.Const {
			return false
		}
	case '$':
		if pattern != v.Name {
			return false
		}
	}
	env[pattern] = v

	return true
}

var rules = []*Rule{
	{
		Name: "Constant-shift-test => bts",
		Source: `rshift V1 C1 V2
                 band   V2 $1 V3
                 neq    V3 $0 V4
              =>
                 bts    V1 C1 V4`,
	},
	{
		Name: "Constant-shift-test => btc",
		Source: `rshift V1 C1 V2
                 band   V2 $1 V3
                 eq     V3 $0 V4
              =>
                 btc    V1 C1 V4`,
	},
	{
		Name: "Constant-shift-test => bts",
		Source: `rshift V1 C1 V2
                 band   V2 $1 V3
                 eq     V3 $1 V4
              =>
                 bts    V1 C1 V4`,
	},
	{
		Name: "Constant-shift-test => btc",
		Source: `rshift V1 C1 V2
                 band   V2 $1 V3
                 neq    V3 $1 V4
              =>
                 btc    V1 C1 V4`,
	},
}

var reSpace = regexp.MustCompilePOSIX(`[[:space:]]+`)

func init() {
	for _, r := range rules {
		var inReplace bool

		for _, line := range strings.Split(r.Source, "\n") {
			parts := reSpace.Split(strings.TrimSpace(line), -1)
			if len(parts) == 1 && parts[0] == "=>" {
				inReplace = true
				continue
			}
			if len(parts) < 3 {
				panic(fmt.Sprintf("unexpected pattern: %s", line))
			}
			var op Operand
			var found bool

			for k, v := range operands {
				if v == parts[0] {
					op = k
					found = true
					break
				}
			}
			if !found {
				panic(fmt.Sprintf("unknown operand '%s'", parts[0]))
			}
			tmpl := Template{
				Op:  op,
				In:  parts[1 : len(parts)-1],
				Out: parts[len(parts)-1],
			}
			if inReplace {
				r.Replace = append(r.Replace, tmpl)
			} else {
				r.Pattern = append(r.Pattern, tmpl)
			}
		}
	}
}

// Peephole runs the peephole optimizer for the program.
func (prog *Program) Peephole() error {

	prog.liveness()
outer:
	for i := 0; i < len(prog.Steps); i++ {
		for _, rule := range rules {
			if len(rule.Pattern) > len(prog.Steps)-i {
				continue
			}
			match := rule.Match(prog.Steps[i : i+len(rule.Pattern)])
			if match == nil {
				continue
			}

			var n []Step
			n = append(n, prog.Steps[:i]...)
			n = append(n, match...)
			n = append(n, prog.Steps[i+len(rule.Pattern):]...)
			prog.Steps = n
			continue outer
		}
	}

	return nil
}
