// -*- go -*-
//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package bytes

// Compare compares two byte slices lexicographically. The result is 0
// if a == b, -1 if a < b, and +1 if a > b.
func Compare(a, b []byte) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
