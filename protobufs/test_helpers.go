package protobufs

import "bytes"

// equalBytes compares two byte slices, treating nil and empty slices as equal
func equalBytes(a, b []byte) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return bytes.Equal(a, b)
}