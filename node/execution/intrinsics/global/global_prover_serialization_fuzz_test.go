package global_test

import (
	"bytes"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

func FuzzBLS48581SignatureWithProofOfPossession(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		sig := &global.BLS48581SignatureWithProofOfPossession{
			PublicKey:    make([]byte, 585),
			Signature:    make([]byte, 74),
			PopSignature: make([]byte, 74),
		}
		copy(sig.PublicKey, data)
		copy(sig.Signature, data)
		copy(sig.PopSignature, data)

		encoded, err := sig.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.BLS48581SignatureWithProofOfPossession{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(sig.PublicKey, decoded.PublicKey) {
			t.Errorf("PublicKey mismatch")
		}
		if !bytes.Equal(sig.Signature, decoded.Signature) {
			t.Errorf("Signature mismatch")
		}
		if !bytes.Equal(sig.PopSignature, decoded.PopSignature) {
			t.Errorf("PopSignature mismatch")
		}
	})
}

func FuzzBLS48581AddressedSignature(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		sig := &global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		}
		copy(sig.Address, data)
		copy(sig.Signature, data)

		encoded, err := sig.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.BLS48581AddressedSignature{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(sig.Address, decoded.Address) {
			t.Errorf("Address mismatch")
		}
		if !bytes.Equal(sig.Signature, decoded.Signature) {
			t.Errorf("Signature mismatch")
		}
	})
}

func FuzzProverJoin(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create some test filters
		filters := [][]byte{
			[]byte("filter1"),
			[]byte("filter2"),
		}
		if len(data) > 0 {
			filters[0] = data
		}

		pj := &global.ProverJoin{
			Filters:     filters,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581SignatureWithProofOfPossession{
				PublicKey:    make([]byte, 585),
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 74),
			},
			MergeTargets: []*global.SeniorityMerge{},
		}
		copy(pj.PublicKeySignatureBLS48581.PublicKey, data)
		copy(pj.PublicKeySignatureBLS48581.Signature, data)
		copy(pj.PublicKeySignatureBLS48581.PopSignature, data)

		encoded, err := pj.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverJoin{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if len(pj.Filters) != len(decoded.Filters) {
			t.Errorf("Filters length mismatch")
		}
		if pj.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pj.PublicKeySignatureBLS48581.PublicKey, decoded.PublicKeySignatureBLS48581.PublicKey) {
			t.Errorf("PublicKey mismatch")
		}
	})
}

func FuzzProverLeave(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create some test filters
		filters := [][]byte{
			[]byte("filter1"),
			[]byte("filter2"),
		}
		if len(data) > 0 {
			filters[0] = data
		}

		pl := &global.ProverLeave{
			Filters:     filters,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
				Address:   make([]byte, 32),
				Signature: make([]byte, 74),
			},
		}
		copy(pl.PublicKeySignatureBLS48581.Address, data)
		copy(pl.PublicKeySignatureBLS48581.Signature, data)

		encoded, err := pl.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverLeave{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if len(pl.Filters) != len(decoded.Filters) {
			t.Errorf("Filters length mismatch")
		}
		if pl.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pl.PublicKeySignatureBLS48581.Address, decoded.PublicKeySignatureBLS48581.Address) {
			t.Errorf("Address mismatch")
		}
	})
}

func FuzzProverPause(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		filter := []byte("test_filter")
		if len(data) > 0 {
			filter = data
		}

		pp := &global.ProverPause{
			Filter:      filter,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
				Address:   make([]byte, 32),
				Signature: make([]byte, 74),
			},
		}
		copy(pp.PublicKeySignatureBLS48581.Address, data)
		copy(pp.PublicKeySignatureBLS48581.Signature, data)

		encoded, err := pp.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverPause{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(pp.Filter, decoded.Filter) {
			t.Errorf("Filter mismatch")
		}
		if pp.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pp.PublicKeySignatureBLS48581.Address, decoded.PublicKeySignatureBLS48581.Address) {
			t.Errorf("Address mismatch")
		}
	})
}

func FuzzProverResume(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		filter := []byte("test_filter")
		if len(data) > 0 {
			filter = data
		}

		pr := &global.ProverResume{
			Filter:      filter,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
				Address:   make([]byte, 32),
				Signature: make([]byte, 74),
			},
		}
		copy(pr.PublicKeySignatureBLS48581.Address, data)
		copy(pr.PublicKeySignatureBLS48581.Signature, data)

		encoded, err := pr.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverResume{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(pr.Filter, decoded.Filter) {
			t.Errorf("Filter mismatch")
		}
		if pr.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pr.PublicKeySignatureBLS48581.Address, decoded.PublicKeySignatureBLS48581.Address) {
			t.Errorf("Address mismatch")
		}
	})
}

func FuzzProverConfirm(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		filter := []byte("test_filter")
		if len(data) > 0 {
			filter = data
		}

		pc := &global.ProverConfirm{
			Filter:      filter,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
				Address:   make([]byte, 32),
				Signature: make([]byte, 74),
			},
		}
		copy(pc.PublicKeySignatureBLS48581.Address, data)
		copy(pc.PublicKeySignatureBLS48581.Signature, data)

		encoded, err := pc.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverConfirm{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(pc.Filter, decoded.Filter) {
			t.Errorf("Filter mismatch")
		}
		if pc.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pc.PublicKeySignatureBLS48581.Address, decoded.PublicKeySignatureBLS48581.Address) {
			t.Errorf("Address mismatch")
		}
	})
}

func FuzzProverReject(f *testing.F) {
	// Add a valid test case
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		filter := []byte("test_filter")
		if len(data) > 0 {
			filter = data
		}

		pr := &global.ProverReject{
			Filter:      filter,
			FrameNumber: 12345,
			PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
				Address:   make([]byte, 32),
				Signature: make([]byte, 74),
			},
		}
		copy(pr.PublicKeySignatureBLS48581.Address, data)
		copy(pr.PublicKeySignatureBLS48581.Signature, data)

		encoded, err := pr.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes failed: %v", err)
		}

		decoded := &global.ProverReject{}
		err = decoded.FromBytes(encoded)
		if err != nil {
			t.Fatalf("FromBytes failed: %v", err)
		}

		if !bytes.Equal(pr.Filter, decoded.Filter) {
			t.Errorf("Filter mismatch")
		}
		if pr.FrameNumber != decoded.FrameNumber {
			t.Errorf("FrameNumber mismatch")
		}
		if !bytes.Equal(pr.PublicKeySignatureBLS48581.Address, decoded.PublicKeySignatureBLS48581.Address) {
			t.Errorf("Address mismatch")
		}
	})
}

func FuzzProverKick_Deserialization(f *testing.F) {
	// Add valid case
	validKick := &global.ProverKick{
		FrameNumber:           12345,
		KickedProverPublicKey: make([]byte, 585),
		ConflictingFrame1:     []byte("frame1"),
		ConflictingFrame2:     []byte("frame2"),
		Commitment:            make([]byte, 32),
		Proof:                 make([]byte, 100),
	}
	validData, _ := validKick.ToBytes()
	f.Add(validData)

	// Add truncated cases
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		pk := &global.ProverKick{}
		err := pk.FromBytes(data)

		// We expect errors for malformed data, but shouldn't panic
		if err == nil {
			// Verify successful deserialization
			if pk.KickedProverPublicKey == nil || len(pk.KickedProverPublicKey) == 0 {
				t.Errorf("KickedProverPublicKey should not be nil or empty after successful deserialization")
			}
		}
	})
}

// Deserialization fuzz tests to test robustness against malformed inputs
func FuzzBLS48581SignatureWithProofOfPossession_Deserialization(f *testing.F) {
	// Add valid case
	validSig := &global.BLS48581SignatureWithProofOfPossession{
		PublicKey:    make([]byte, 585),
		Signature:    make([]byte, 74),
		PopSignature: make([]byte, 74),
	}
	validData, _ := validSig.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	// Add malformed data
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // Invalid length

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		sig := &global.BLS48581SignatureWithProofOfPossession{}
		_ = sig.FromBytes(data) // Should not panic
	})
}

func FuzzBLS48581AddressedSignature_Deserialization(f *testing.F) {
	// Add valid case
	validSig := &global.BLS48581AddressedSignature{
		Address:   make([]byte, 32),
		Signature: make([]byte, 74),
	}
	validData, _ := validSig.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 30; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		sig := &global.BLS48581AddressedSignature{}
		_ = sig.FromBytes(data) // Should not panic
	})
}

func FuzzProverJoin_Deserialization(f *testing.F) {
	// Add valid case
	validJoin := &global.ProverJoin{
		Filters:     [][]byte{[]byte("filter1")},
		FrameNumber: 12345,
		PublicKeySignatureBLS48581: global.BLS48581SignatureWithProofOfPossession{
			PublicKey:    make([]byte, 585),
			Signature:    make([]byte, 74),
			PopSignature: make([]byte, 74),
		},
	}
	validData, _ := validJoin.ToBytes()
	f.Add(validData)

	// Add invalid type prefix
	f.Add([]byte{0x00, 0x00, 0x00, 0x99})

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		join := &global.ProverJoin{}
		_ = join.FromBytes(data) // Should not panic
	})
}

func FuzzProverLeave_Deserialization(f *testing.F) {
	// Add valid case
	validLeave := &global.ProverLeave{
		Filters:     [][]byte{[]byte("filter1")},
		FrameNumber: 12345,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		},
	}
	validData, _ := validLeave.ToBytes()
	f.Add(validData)

	// Add truncated cases
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		leave := &global.ProverLeave{}
		_ = leave.FromBytes(data) // Should not panic
	})
}

func FuzzMixedTypeDeserialization(f *testing.F) {
	// Add valid prefixes for each type
	types := []uint32{
		protobufs.ProverJoinType,
		protobufs.ProverLeaveType,
		protobufs.ProverPauseType,
		protobufs.ProverResumeType,
		protobufs.ProverConfirmType,
		protobufs.ProverRejectType,
		protobufs.ProverKickType,
	}

	for _, typ := range types {
		data := make([]byte, 4)
		data[0] = byte(typ >> 24)
		data[1] = byte(typ >> 16)
		data[2] = byte(typ >> 8)
		data[3] = byte(typ)
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		// Try deserializing as each type - should handle gracefully
		_ = (&global.ProverJoin{}).FromBytes(data)
		_ = (&global.ProverLeave{}).FromBytes(data)
		_ = (&global.ProverPause{}).FromBytes(data)
		_ = (&global.ProverResume{}).FromBytes(data)
		_ = (&global.ProverConfirm{}).FromBytes(data)
		_ = (&global.ProverReject{}).FromBytes(data)

		// Try deserializing as ProverKick
		_ = (&global.ProverKick{}).FromBytes(data)
	})
}
