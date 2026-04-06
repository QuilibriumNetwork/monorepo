package global

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestComputeShardRingInfo calls the actual production function that
// worker_allocator.go uses to assign ring numbers. This validates that
// the 8th prover lands on ring 0 (not 1), and similarly for other
// boundary cases.
func TestComputeShardRingInfo(t *testing.T) {
	tests := []struct {
		name                    string
		totalActiveJoining      int
		wantCurrentRing         uint8
		wantJoinerRing          uint8
		wantActiveOnCurrentRing uint64
		wantActiveOnJoinerRing  uint64
	}{
		{
			name:                    "0 provers — empty shard",
			totalActiveJoining:      0,
			wantCurrentRing:         0,
			wantJoinerRing:          0,
			wantActiveOnCurrentRing: 0,
			wantActiveOnJoinerRing:  1,
		},
		{
			name:                    "1 prover",
			totalActiveJoining:      1,
			wantCurrentRing:         0, // position 0 → ring 0
			wantJoinerRing:          0, // position 1 → ring 0
			wantActiveOnCurrentRing: 1,
			wantActiveOnJoinerRing:  2,
		},
		{
			name:                    "7 provers",
			totalActiveJoining:      7,
			wantCurrentRing:         0,
			wantJoinerRing:          0,
			wantActiveOnCurrentRing: 7,
			wantActiveOnJoinerRing:  8,
		},
		{
			// Key regression case: 8th prover must be ring 0, not 1.
			name:                    "8 provers — boundary, 8th prover is ring 0",
			totalActiveJoining:      8,
			wantCurrentRing:         0, // position 7 → floor(7/8) = 0
			wantJoinerRing:          1, // position 8 → floor(8/8) = 1
			wantActiveOnCurrentRing: 8,
			wantActiveOnJoinerRing:  1,
		},
		{
			name:                    "9 provers",
			totalActiveJoining:      9,
			wantCurrentRing:         1,
			wantJoinerRing:          1,
			wantActiveOnCurrentRing: 1,
			wantActiveOnJoinerRing:  2,
		},
		{
			name:                    "15 provers",
			totalActiveJoining:      15,
			wantCurrentRing:         1,
			wantJoinerRing:          1,
			wantActiveOnCurrentRing: 7,
			wantActiveOnJoinerRing:  8,
		},
		{
			// Key regression case: 16th prover must be ring 1, not 2.
			name:                    "16 provers — boundary, 16th prover is ring 1",
			totalActiveJoining:      16,
			wantCurrentRing:         1, // position 15 → floor(15/8) = 1
			wantJoinerRing:          2, // position 16 → floor(16/8) = 2
			wantActiveOnCurrentRing: 8,
			wantActiveOnJoinerRing:  1,
		},
		{
			name:                    "24 provers — boundary",
			totalActiveJoining:      24,
			wantCurrentRing:         2,
			wantJoinerRing:          3,
			wantActiveOnCurrentRing: 8,
			wantActiveOnJoinerRing:  1,
		},
		{
			name:                    "32 provers — boundary",
			totalActiveJoining:      32,
			wantCurrentRing:         3,
			wantJoinerRing:          4,
			wantActiveOnCurrentRing: 8,
			wantActiveOnJoinerRing:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ri := computeShardRingInfo(tt.totalActiveJoining)

			assert.Equal(t, tt.wantCurrentRing, ri.currentRing,
				"currentRing (existing prover's ring)")
			assert.Equal(t, tt.wantJoinerRing, ri.joinerRing,
				"joinerRing (new joiner's ring)")
			assert.Equal(t, tt.wantActiveOnCurrentRing, ri.activeOnCurrentRing,
				"activeOnCurrentRing")
			assert.Equal(t, tt.wantActiveOnJoinerRing, ri.activeOnJoinerRing,
				"activeOnJoinerRing")
		})
	}
}

// TestComputeShardRingInfo_BoundaryRegression specifically validates the
// reported bug: an active 8th prover showing ring 1 instead of 0, and
// a 16th prover showing ring 2 instead of 1. If computeShardRingInfo is
// reverted to use totalActiveJoining/8 for currentRing, this test fails.
func TestComputeShardRingInfo_BoundaryRegression(t *testing.T) {
	// 8 provers: existing prover is on ring 0, new joiner would be ring 1.
	ri8 := computeShardRingInfo(8)
	assert.Equal(t, uint8(0), ri8.currentRing,
		"BUG REGRESSION: 8th prover must be ring 0, not %d", ri8.currentRing)
	assert.Equal(t, uint8(1), ri8.joinerRing)
	assert.NotEqual(t, ri8.currentRing, ri8.joinerRing,
		"at exact multiple of 8, currentRing and joinerRing must differ")

	// 16 provers: existing prover is on ring 1, new joiner would be ring 2.
	ri16 := computeShardRingInfo(16)
	assert.Equal(t, uint8(1), ri16.currentRing,
		"BUG REGRESSION: 16th prover must be ring 1, not %d", ri16.currentRing)
	assert.Equal(t, uint8(2), ri16.joinerRing)

	// 24 provers
	ri24 := computeShardRingInfo(24)
	assert.Equal(t, uint8(2), ri24.currentRing,
		"BUG REGRESSION: 24th prover must be ring 2, not %d", ri24.currentRing)
	assert.Equal(t, uint8(3), ri24.joinerRing)
}

// makeAddrs creates n distinct 32-byte addresses for testing.
func makeAddrs(n int) [][]byte {
	addrs := make([][]byte, n)
	for i := range addrs {
		a := make([]byte, 32)
		a[0] = byte(i)
		addrs[i] = a
	}
	return addrs
}

// TestResolveProverRing_AllocatedFound tests the RPC path: the prover is
// allocated and found in the sorted candidate list. This is the path used
// by the manage TUI via GetShardInfo.
func TestResolveProverRing_AllocatedFound(t *testing.T) {
	addrs := makeAddrs(16)

	tests := []struct {
		name       string
		total      int
		selfRank   int // index into addrs used as selfAddress
		wantRing   uint8
		wantOnRing int
	}{
		{"rank 0 of 8", 8, 0, 0, 8},
		{"rank 7 of 8 — last on ring 0", 8, 7, 0, 8},
		{"rank 0 of 9", 9, 0, 0, 8},
		{"rank 8 of 9 — first on ring 1", 9, 8, 1, 1},
		{"rank 7 of 16", 16, 7, 0, 8},
		{"rank 8 of 16", 16, 8, 1, 8},
		{"rank 15 of 16 — last on ring 1", 16, 15, 1, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := addrs[:tt.total]
			self := candidates[tt.selfRank]

			ring, onRing := resolveProverRing(
				tt.total, true, self,
				func() [][]byte { return candidates },
			)

			assert.Equal(t, tt.wantRing, ring, "ring")
			assert.Equal(t, tt.wantOnRing, onRing, "onRing")
		})
	}
}

// TestResolveProverRing_AllocatedNotFound tests the case where the prover
// is allocated but NOT in the candidate list (e.g. leaving or paused).
// This was the bug path: it used to return joinerRing (too high at
// multiples of 8) instead of currentRing.
func TestResolveProverRing_AllocatedNotFound(t *testing.T) {
	addrs := makeAddrs(9)
	notInList := []byte{0xff, 0xff, 0xff} // won't match any candidate

	tests := []struct {
		name       string
		total      int
		wantRing   uint8
		wantOnRing int
	}{
		{"8 candidates, self missing → ring 0", 8, 0, 8},
		{"9 candidates, self missing → ring 1", 9, 1, 1},
		{"16 candidates, self missing → ring 1", 16, 1, 8},
		{"1 candidate, self missing → ring 0", 1, 0, 1},
		{"0 candidates, self missing → ring 0", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := addrs[:min(tt.total, len(addrs))]
			if tt.total > len(addrs) {
				candidates = makeAddrs(tt.total)
			}

			ring, onRing := resolveProverRing(
				tt.total, true, notInList,
				func() [][]byte { return candidates },
			)

			assert.Equal(t, tt.wantRing, ring,
				"allocated but not found should use currentRing")
			assert.Equal(t, tt.wantOnRing, onRing, "onRing")
		})
	}
}

// TestResolveProverRing_Unallocated tests that unallocated shards show the
// ring a new joiner would land on.
func TestResolveProverRing_Unallocated(t *testing.T) {
	tests := []struct {
		total      int
		wantRing   uint8
		wantOnRing int
	}{
		{0, 0, 1},
		{7, 0, 8},
		{8, 1, 1},
		{15, 1, 8},
		{16, 2, 1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_candidates", tt.total), func(t *testing.T) {
			ring, onRing := resolveProverRing(
				tt.total, false, nil,
				func() [][]byte { panic("should not be called") },
			)

			assert.Equal(t, tt.wantRing, ring, "joinerRing")
			assert.Equal(t, tt.wantOnRing, onRing, "activeOnJoinerRing")
		})
	}
}

// TestResolveProverRing_BoundaryRegression is the specific bug scenario:
// 8 active provers, local prover allocated but not found in candidate list.
// Before fix: returned ring 1 (joinerRing). After fix: returns ring 0
// (currentRing).
func TestResolveProverRing_BoundaryRegression(t *testing.T) {
	addrs := makeAddrs(8)
	missing := []byte{0xde, 0xad}

	ring, _ := resolveProverRing(8, true, missing, func() [][]byte { return addrs })
	assert.Equal(t, uint8(0), ring,
		"BUG REGRESSION: allocated prover not in candidate list with 8 members must show ring 0, got %d", ring)

	ring16, _ := resolveProverRing(16, true, missing, func() [][]byte { return makeAddrs(16) })
	assert.Equal(t, uint8(1), ring16,
		"BUG REGRESSION: allocated prover not in candidate list with 16 members must show ring 1, got %d", ring16)
}
