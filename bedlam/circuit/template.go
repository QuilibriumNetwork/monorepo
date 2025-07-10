//
// Copyright (c) 2022 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var reVar = regexp.MustCompilePOSIX(`{(.?){([^\}]+)}}`)

// Template defines an expandable text template.
type Template struct {
	parts     []*part
	FloatCvt  FloatCvt
	IntCvt    IntCvt
	StringCvt StringCvt
}

// FloatCvt converts a float64 value to float64 value.
type FloatCvt func(v float64) float64

// IntCvt converts an integer value to float64 value.
type IntCvt func(v int) float64

// StringCvt converts a string value to a string value.
type StringCvt func(v string) string

const (
	partFloat = iota
	partInt
	partString
)

type part struct {
	t  int
	fv float64
	iv int
	sv string
}

func (p part) String() string {
	switch p.t {
	case partFloat:
		return fmt.Sprintf("float64:%v", p.fv)
	case partInt:
		return fmt.Sprintf("int:%v", p.iv)
	case partString:
		return p.sv
	default:
		return fmt.Sprintf("{part %d}", p.t)
	}
}

// NewTemplate parses the input string and returns the parsed
// Template.
func NewTemplate(input string) *Template {
	t := &Template{
		FloatCvt:  func(v float64) float64 { return v },
		IntCvt:    func(v int) float64 { return float64(v) },
		StringCvt: func(v string) string { return v },
	}
	matches := reVar.FindAllStringSubmatchIndex(input, -1)
	if matches == nil {
		return t
	}

	var start int
	var err error

	for _, m := range matches {
		if m[0] > start {
			t.parts = append(t.parts, &part{
				t:  partString,
				sv: input[start:m[0]],
			})
		}
		content := input[m[4]:m[5]]
		part := &part{
			t:  partFloat,
			sv: content,
		}
		t.parts = append(t.parts, part)
		start = m[1]

		if m[2] != m[3] {
			switch input[m[2]:m[3]] {
			default:
				panic(fmt.Sprintf("unknown template variable conversion: %s",
					input[m[2]:m[3]]))
			}
		} else {
			part.iv, err = strconv.Atoi(content)
			if err == nil {
				part.t = partInt
			} else {
				part.fv, err = strconv.ParseFloat(content, 64)
				if err == nil {
					part.t = partFloat
				} else {
					part.sv = content
					part.t = partString
				}
			}
		}

	}
	if start < len(input) {
		t.parts = append(t.parts, &part{
			t:  partString,
			sv: input[start:],
		})
	}

	return t
}

// Expand expands the template.
func (t *Template) Expand() string {
	var b strings.Builder

	for _, part := range t.parts {
		switch part.t {
		case partFloat:
			b.WriteString(fmt.Sprintf("%v", t.FloatCvt(part.fv)))
		case partInt:
			b.WriteString(fmt.Sprintf("%v", t.IntCvt(part.iv)))
		case partString:
			b.WriteString(part.sv)
		default:
			panic(fmt.Sprintf("invalid part type: %v", part.t))
		}
	}

	return b.String()
}
