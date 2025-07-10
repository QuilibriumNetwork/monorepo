//
// parse.go
//
// Copyright (c) 2021-2024 Markku Rossi
//
// All rights reserved.
//

package types

import (
	"fmt"
	"regexp"
	"strconv"
)

var (
	reArr   = regexp.MustCompilePOSIX(`^\[([[:digit:]]*)\](.+)$`)
	reSized = regexp.MustCompilePOSIX(`^([[:alpha:]]+)([[:digit:]]*)$`)
)

// Parse parses type definition and returns its type information.
func Parse(val string) (info Info, err error) {
	var ival int64

	switch val {
	case "b", "bool":
		info = Bool
		return

	case "byte":
		info = Byte
		return

	case "rune":
		info = Rune
		return
	}

	m := reSized.FindStringSubmatch(val)
	if m != nil {
		switch m[1] {
		case "b", "bool":
			info.Type = TBool

		case "i", "int":
			info.Type = TInt

		case "u", "uint":
			info.Type = TUint

		case "s", "string":
			info.Type = TString

		case "struct":
			info.Type = TStruct

		default:
			return info, fmt.Errorf("types.Parse: unknown type: %s", val)
		}
		var bits int64
		if len(m[2]) > 0 {
			bits, err = strconv.ParseInt(m[2], 10, 32)
			if err != nil {
				return
			}
			info.IsConcrete = true
		}
		info.Bits = Size(bits)
		info.MinBits = info.Bits
		return
	}

	m = reArr.FindStringSubmatch(val)
	if m == nil {
		return info, fmt.Errorf("types.Parse: unknown type: %s", val)
	}
	var elType Info
	elType, err = Parse(m[2])
	if err != nil {
		return
	}
	if len(m[1]) > 0 {
		ival, err = strconv.ParseInt(m[1], 10, 32)
		if err != nil {
			return
		}
		info.Type = TArray
	} else {
		info.Type = TSlice
	}

	info.IsConcrete = true
	info.Bits = Size(ival) * elType.Bits
	info.MinBits = info.Bits
	info.ElementType = &elType
	info.ArraySize = Size(ival)

	return
}
