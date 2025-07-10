//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

const (
	verbose = false
)

var parserTests = []string{
	`
package main
`,
	`
package main
func main() {}
`,
	`
package main
func main(a int4) {}
`,
	`
package main
func main(a int4, b int4) {}
`,
	`
package main
func main(a, b int4) {}
`,
	`
package main
func main(a, b int4) int5 {}
`,
	`
package main
func main(a, b int4) (int5) {}
`,
	`
package main
func main(a, b int4) (int5, int6) {}
`,
	`
package main
func main(a, b int4) (int5) {
  return
}`,
	`
package main
func main(a, b int4) (int5) {
  return a * b + c * d
}`,
	`
package main
func main(a, b int4) (int5) {
  return a * b * c
}`,
	`
package main
func main(a, b int4) (int5) {
  return a + b + c * d + e
}`,
	`
package main
func main(a, b int4) (int4) {
  if a > b {
    return a
  }
  return b
}`,
	`
package main
func main(a, b int4) (int4) {
  if a > b {
    return a
  } else {
    return b
  }
}`,
	`
package main
func main(a, b int4) (int4) {
  if a > b || a == b {
    return a
  } else {
    return b
  }
}`,
	`
package main
func main(a, b int4) int4 {
    return max(a, b)
}

func max(a, b int4) int4 {
    if a > b {
        return a
    }
    return v
}
`,
}

func TestParser(t *testing.T) {
	min := 0
	for idx, test := range parserTests {
		if idx < min {
			continue
		}
		logger := utils.NewLogger(os.Stdout)
		parser := NewParser(fmt.Sprintf("{test %d}", idx), nil, logger,
			bytes.NewReader([]byte(test)))
		_, err := parser.Parse(nil)
		if err != nil {
			t.Fatalf("Parse test %d failed: %v", idx, err)
		}
	}
}
