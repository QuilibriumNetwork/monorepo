package protobufs

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

func TestPoseidonJoinDomain(t *testing.T) {
	// GLOBAL_INTRINSIC_ADDRESS = [0xFF; 32]
	addr := make([]byte, 32)
	for i := range addr { addr[i] = 0xFF }
	input := append(addr, []byte("PROVER_JOIN")...)
	
	result, err := poseidon.HashBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	
	domain := result.FillBytes(make([]byte, 32))
	fmt.Printf("Go PROVER_JOIN domain: %s\n", hex.EncodeToString(domain))
}
