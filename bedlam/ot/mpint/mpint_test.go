//
// mpint_test.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package mpint

import (
	"testing"
)

var (
	oneData   = []byte{0x1}
	twoData   = []byte{0x2}
	threeData = []byte{0x3}
)

func TestMPInt(t *testing.T) {
	one := FromBytes(oneData)
	two := FromBytes(twoData)
	three := FromBytes(threeData)

	sum := Add(one, two)
	if sum.Cmp(three) != 0 {
		t.Errorf("%s + %s = %s, expected %s\n", one, two, sum, three)
	}
}
