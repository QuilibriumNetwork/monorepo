//
// parser_test.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"bytes"
	"testing"
)

var data = `1 3
2 1 1
1 1

2 1 0 1 2 AND
`

func TestParse(t *testing.T) {
	_, err := ParseBristol(bytes.NewReader([]byte(data)))
	if err != nil {
		t.Fatalf("Parse failed: %s", err)
	}
}
