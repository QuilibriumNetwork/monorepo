//
// Copyright (c) 2022-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"testing"
)

var tmplXOR = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <path fill="none" stroke="#000" stroke-width="1"
        d="M {{25}} {{20}}
           c {{10}} {{10}} {{40}} {{10}} {{50}} 0" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 25 25
           c 10 10 40 10 50 0" />

  <path fill="none" stroke="#000" stroke-width="1"
        d="M 75 25
           v 25
           s 0 10 -25 25 " />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 25 25
           v 25
           s 0 10 25 25 " />

  <!-- Wires -->
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 35 0
           v 25
           z" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 65 0
           v 25
           z" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 50 75
           v 25
           z" />
</svg>
`

var tmplXORExpanded = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 6.25 5
           c 2.5 2.5 10 2.5 12.5 0" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 25 25
           c 10 10 40 10 50 0" />

  <path fill="none" stroke="#000" stroke-width="1"
        d="M 75 25
           v 25
           s 0 10 -25 25 " />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 25 25
           v 25
           s 0 10 25 25 " />

  <!-- Wires -->
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 35 0
           v 25
           z" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 65 0
           v 25
           z" />
  <path fill="none" stroke="#000" stroke-width="1"
        d="M 50 75
           v 25
           z" />
</svg>
`

func TestTemplate(t *testing.T) {
	tmpl := NewTemplate(tmplXOR)
	tmpl.IntCvt = func(v int) float64 {
		return float64(v) * 25 / 100
	}
	expanded := tmpl.Expand()
	if expanded != tmplXORExpanded {
		t.Errorf("template expansion failed: got\n%v\n", expanded)
	}
}
