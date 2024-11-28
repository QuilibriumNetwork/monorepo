package fragmentation

import "crypto/sha256"

const hashSize = 32

func hash(b []byte) []byte {
	var h [hashSize]byte = sha256.Sum256(b)
	return h[:]
}
