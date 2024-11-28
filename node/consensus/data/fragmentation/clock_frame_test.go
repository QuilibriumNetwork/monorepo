package fragmentation_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data/fragmentation"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func BenchmarkReedSolomonClockFrameFragmentation(b *testing.B) {
	frame := &protobufs.ClockFrame{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 123,
		Timestamp:   456,
		Padding:     make([]byte, 20*1024*1024),
	}
	if _, err := rand.Read(frame.Padding); err != nil {
		b.Fatal(err)
	}
	benchmarkCases := []struct {
		dataShardCount   int
		parityShardCount int
	}{
		{
			dataShardCount:   4,
			parityShardCount: 2,
		},
		{
			dataShardCount:   8,
			parityShardCount: 4,
		},
		{
			dataShardCount:   16,
			parityShardCount: 8,
		},
		{
			dataShardCount:   32,
			parityShardCount: 16,
		},
		{
			dataShardCount:   48,
			parityShardCount: 16,
		},
		{
			dataShardCount:   64,
			parityShardCount: 32,
		},
		{
			dataShardCount:   128,
			parityShardCount: 64,
		},
		{
			dataShardCount:   192,
			parityShardCount: 64,
		},
		{
			dataShardCount:   224,
			parityShardCount: 32,
		},
	}
	b.Run("Splitter", func(b *testing.B) {
		for _, bc := range benchmarkCases {
			b.Run(fmt.Sprintf("DS_%d/PS_%d", bc.dataShardCount, bc.parityShardCount), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					splitter, err := fragmentation.NewReedSolomonClockFrameSplitter(bc.dataShardCount, bc.parityShardCount)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := splitter.SplitClockFrame(frame); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
	b.Run("Assembler", func(b *testing.B) {
		for _, bc := range benchmarkCases {
			b.Run(fmt.Sprintf("DS_%d/PS_%d", bc.dataShardCount, bc.parityShardCount), func(b *testing.B) {
				splitter, err := fragmentation.NewReedSolomonClockFrameSplitter(bc.dataShardCount, bc.parityShardCount)
				if err != nil {
					b.Fatal(err)
				}
				fragments, err := splitter.SplitClockFrame(frame)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					assembler := fragmentation.NewReedSolomonClockFrameAssembler()
					if _, err := assembler.AssembleClockFrame(fragments); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
}

func TestReedSolomonClockFrameFragmentation(t *testing.T) {
	splitter, err := fragmentation.NewReedSolomonClockFrameSplitter(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	originalFrame := &protobufs.ClockFrame{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 123,
		Timestamp:   456,
		Padding:     make([]byte, 20*1024*1024),
	}
	if _, err := rand.Read(originalFrame.Padding); err != nil {
		t.Fatal(err)
	}
	fragments, err := splitter.SplitClockFrame(originalFrame)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) != 6 {
		t.Fatalf("fragment count mismatch: %d, expected %d", len(fragments), 5)
	}
	for _, fragment := range fragments {
		if fragment.FrameNumber != 123 {
			t.Fatalf("frame number mismatch: %d, expected %d", fragment.FrameNumber, 123)
		}
		if !bytes.Equal(fragment.Filter, bytes.Repeat([]byte{0x01}, 32)) {
			t.Fatalf("filter mismatch")
		}
		if fragment.Timestamp != 456 {
			t.Fatalf("timestamp mismatch: %d, expected %d", fragment.Timestamp, 456)
		}
	}
	for _, tc := range []struct {
		name        string
		erase       []int
		expectError bool
	}{
		{
			name:        "no erasures",
			erase:       nil,
			expectError: false,
		},
		{
			name:        "one erasure",
			erase:       []int{0},
			expectError: false,
		},
		{
			name:        "two erasures",
			erase:       []int{2, 0},
			expectError: false,
		},
		{
			name:        "three erasures",
			erase:       []int{2, 4, 0},
			expectError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fragments := slices.Clone(fragments)
			for _, idx := range tc.erase {
				fragments[idx] = nil
			}
			for i, fragment := range fragments {
				if fragment == nil {
					fragments = append(fragments[:i], fragments[i+1:]...)
				}
			}
			assembler := fragmentation.NewReedSolomonClockFrameAssembler()
			assembledFrame, err := assembler.AssembleClockFrame(fragments)
			switch {
			case tc.expectError:
				if err == nil {
					t.Fatal("expected error")
				}
				return
			case err != nil:
				t.Fatal(err)
			}
			if !proto.Equal(assembledFrame, originalFrame) {
				t.Fatalf("frame mismatch")
			}
		})
	}
}

func TestClockFrameFragmentCircularBuffer(t *testing.T) {
	t.Parallel()
	splitter, err := fragmentation.NewReedSolomonClockFrameSplitter(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	originalFrames := []*protobufs.ClockFrame{
		{
			Filter:      bytes.Repeat([]byte{0x01}, 32),
			FrameNumber: 123,
			Timestamp:   456,
			Padding:     make([]byte, 20*1024*1024),
		},
		{
			Filter:      bytes.Repeat([]byte{0x02}, 32),
			FrameNumber: 124,
			Timestamp:   457,
			Padding:     make([]byte, 20*1024*1024),
		},
		{
			Filter:      bytes.Repeat([]byte{0x03}, 32),
			FrameNumber: 125,
			Timestamp:   458,
			Padding:     make([]byte, 20*1024*1024),
		},
	}
	fragments := make([][]*protobufs.ClockFrameFragment, len(originalFrames))
	for i, originalFrame := range originalFrames {
		if _, err := rand.Read(originalFrame.Padding); err != nil {
			t.Fatal(err)
		}
		fragments[i], err = splitter.SplitClockFrame(originalFrame)
		if err != nil {
			t.Fatal(err)
		}
	}
	allFragments := slices.Concat(fragments...)
	mrand.Shuffle(len(allFragments), func(i, j int) {
		allFragments[i], allFragments[j] = allFragments[j], allFragments[i]
	})
	buffer, err := fragmentation.NewClockFrameFragmentCircularBuffer(
		fragmentation.NewReedSolomonClockFrameFragmentBuffer,
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	var seen [3]bool
	for _, fragment := range allFragments {
		frame, err := buffer.AccumulateClockFrameFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if frame == nil {
			continue
		}
		if !proto.Equal(frame, originalFrames[frame.FrameNumber-123]) {
			t.Fatalf("frame mismatch")
		}
		if seen[frame.FrameNumber-123] {
			t.Fatal("duplicate frame")
		}
		seen[frame.FrameNumber-123] = true
	}
	for i := range seen {
		if !seen[i] {
			t.Fatalf("missing frame: %d", i+123)
		}
	}
	buffer, err = fragmentation.NewClockFrameFragmentCircularBuffer(
		fragmentation.NewReedSolomonClockFrameFragmentBuffer,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(seen[:])
	for _, fragments := range fragments {
		for _, fragment := range fragments {
			frame, err := buffer.AccumulateClockFrameFragment(fragment)
			if err != nil {
				t.Fatal(err)
			}
			if frame == nil {
				continue
			}
			if !proto.Equal(frame, originalFrames[frame.FrameNumber-123]) {
				t.Fatalf("frame mismatch")
			}
			if seen[frame.FrameNumber-123] {
				t.Fatal("duplicate frame")
			}
			seen[frame.FrameNumber-123] = true
		}
	}
	for i := range seen {
		if !seen[i] {
			t.Fatalf("missing frame: %d", i+123)
		}
	}
}

func TestReedSolomonClockFrameFragmentBuffer(t *testing.T) {
	splitter, err := fragmentation.NewReedSolomonClockFrameSplitter(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	originalFrame := &protobufs.ClockFrame{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 123,
		Timestamp:   456,
		Padding:     make([]byte, 20*1024*1024),
	}
	if _, err := rand.Read(originalFrame.Padding); err != nil {
		t.Fatal(err)
	}
	fragments, err := splitter.SplitClockFrame(originalFrame)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		fragments []*protobufs.ClockFrameFragment
		errorIdx  int
		frameIdx  int
	}{
		{
			name: "one insert",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0],
			},
			errorIdx: -1,
			frameIdx: -1,
		},
		{
			name: "two insert",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0], fragments[2],
			},
			errorIdx: -1,
			frameIdx: -1,
		},
		{
			name: "three insert",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0], fragments[4], fragments[2],
			},
			errorIdx: -1,
			frameIdx: -1,
		},
		{
			name: "four insert",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0], fragments[4], fragments[1], fragments[2],
			},
			errorIdx: -1,
			frameIdx: 3,
		},
		{
			name: "one insert, one bogus",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0],
				{
					FrameNumber: 123,
					Filter:      bytes.Repeat([]byte{0x01}, 32),
					Timestamp:   456,
				},
			},
			errorIdx: 1,
			frameIdx: -1,
		},
		{
			name: "one insert, one duplicate",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0], fragments[0],
			},
			errorIdx: 1,
			frameIdx: -1,
		},
		{
			name: "four insert, one bogus",
			fragments: []*protobufs.ClockFrameFragment{
				fragments[0], fragments[2], fragments[4],
				{
					FrameNumber: 123,
					Filter:      bytes.Repeat([]byte{0x01}, 32),
					Timestamp:   456,
				},
				fragments[1],
			},
			errorIdx: 3,
			frameIdx: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buffer := fragmentation.NewReedSolomonClockFrameFragmentBuffer()
			for i, fragment := range tc.fragments {
				frame, err := buffer.AccumulateClockFrameFragment(fragment)
				switch {
				case tc.errorIdx == i:
					if err == nil {
						t.Fatal("expected error")
					}
					continue
				case err != nil:
					t.Fatal(err)
				}
				switch {
				case tc.frameIdx == i:
					if frame == nil {
						t.Fatal("expected frame")
					}
					if !proto.Equal(frame, originalFrame) {
						t.Fatalf("frame mismatch")
					}
				case frame != nil:
					t.Fatal("unexpected frame")
				}
			}
		})
	}
}
