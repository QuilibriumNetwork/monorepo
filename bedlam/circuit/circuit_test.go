//
// Copyright (c) 2022-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"testing"
	"unsafe"
)

func TestSize(t *testing.T) {
	var g Gate
	if unsafe.Sizeof(g) != 20 {
		t.Errorf("unexpected gate size: got %v, expected 20", unsafe.Sizeof(g))
	}
}
