package protobufs

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestKeyRegistryCanonicalDump(t *testing.T) {
	kr := &KeyRegistry{
		IdentityKey: &Ed448PublicKey{
			KeyValue: make([]byte, 57),
		},
		ProverKey: &BLS48581G2PublicKey{
			KeyValue: make([]byte, 585),
		},
		IdentityToProver: &Ed448Signature{
			Signature: make([]byte, 114),
		},
		ProverToIdentity: &BLS48581Signature{
			Signature: make([]byte, 74),
		},
		LastUpdated: 1000,
	}

	data, err := kr.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Go KeyRegistry: %d bytes\n", len(data))
	for i := 0; i < len(data) && i < 300; i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("  %04x: %s\n", i, hex.EncodeToString(data[i:end]))
	}
	if len(data) > 300 {
		fmt.Printf("  ... (%d more bytes)\n", len(data)-300)
	}

	kr2 := &KeyRegistry{}
	if err := kr2.FromCanonicalBytes(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	fmt.Println("Roundtrip OK")
}
