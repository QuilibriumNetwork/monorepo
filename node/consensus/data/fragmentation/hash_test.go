package fragmentation_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

func BenchmarkHashFunctions(b *testing.B) {
	data := make([]byte, 20*1024*1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct {
		name string
		f    func([]byte) []byte
	}{
		{
			name: "SHA256-224",
			f: func(data []byte) []byte {
				b := sha256.Sum224(data)
				return b[:]
			},
		},
		{
			name: "SHA256-256",
			f: func(data []byte) []byte {
				b := sha256.Sum256(data)
				return b[:]
			},
		},
		{
			name: "SHA3-224",
			f: func(data []byte) []byte {
				b := sha3.Sum224(data)
				return b[:]
			},
		},
		{
			name: "SHA3-256",
			f: func(data []byte) []byte {
				b := sha3.Sum256(data)
				return b[:]
			},
		},
		{
			name: "SHA3-384",
			f: func(data []byte) []byte {
				b := sha3.Sum384(data)
				return b[:]
			},
		},
		{
			name: "SHA3-512",
			f: func(data []byte) []byte {
				b := sha3.Sum512(data)
				return b[:]
			},
		},
		{
			name: "BLAKE2b-256",
			f: func(data []byte) []byte {
				b := blake2b.Sum256(data)
				return b[:]
			},
		},
		{
			name: "BLAKE2b-384",
			f: func(data []byte) []byte {
				b := blake2b.Sum384(data)
				return b[:]
			},
		},
		{
			name: "BLAKE2b-512",
			f: func(data []byte) []byte {
				b := blake2b.Sum512(data)
				return b[:]
			},
		},
		{
			name: "BLAKE2s-256",
			f: func(data []byte) []byte {
				b := blake2s.Sum256(data)
				return b[:]
			},
		},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = bc.f(data)
			}
		})
	}
}
