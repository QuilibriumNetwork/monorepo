package rpm_test

import (
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/sharing"
	"source.quilibrium.com/quilibrium/monorepo/rpm"
)

func genPolyFrags(val *curves.ScalarEd25519, n, t int) []*curves.ScalarEd25519 {
	if t < 1 || t > n {
		panic("invalid threshold")
	}

	feldman, err := sharing.NewFeldman(uint32(t), uint32(n), curves.ED25519())
	if err != nil {
		panic(err)
	}

	_, shares, err := feldman.Split(val, rand.Reader)
	if err != nil {
		panic(err)
	}
	result := []*curves.ScalarEd25519{}
	for _, share := range shares {
		v, _ := (&curves.ScalarEd25519{}).SetBytes(share.Value)
		result = append(result, v.(*curves.ScalarEd25519))
	}
	return result
}

func TestFullSequence(t *testing.T) {
	depth := 15
	players := 4
	dealers := 2

	is1 := rpm.RPMGenerateInitialShares(100, uint64(depth), uint64(dealers), uint64(players))
	is2 := rpm.RPMGenerateInitialShares(100, uint64(depth), uint64(dealers), uint64(players))

	m1, r1 := is1.Ms, is1.Rs
	m2, r2 := is2.Ms, is2.Rs

	// ms: [players][dealers][depth][10][10][10][32]
	ms := make([][][][][][][]byte, players)
	for i := 0; i < players; i++ {
		ms[i] = make([][][][][][]byte, dealers)
		for d := 0; d < dealers; d++ {
			ms[i][d] = make([][][][][]byte, depth)
			for j := 0; j < depth; j++ {
				ms[i][d][j] = make([][][][]byte, 10)
				for k := 0; k < 10; k++ {
					ms[i][d][j][k] = make([][][]byte, 10)
					for u := 0; u < 10; u++ {
						ms[i][d][j][k][u] = make([][]byte, 10)
						for v := 0; v < 10; v++ {
							ms[i][d][j][k][u][v] = make([]byte, 32)
						}
					}
				}
			}
		}
	}

	// rs: [players][dealers][depth][100][32]
	rs := make([][][][][]byte, players)
	for i := 0; i < players; i++ {
		rs[i] = make([][][][]byte, dealers)
		for d := 0; d < dealers; d++ {
			rs[i][d] = make([][][]byte, depth)
			for j := 0; j < depth; j++ {
				rs[i][d][j] = make([][]byte, 100)
				for idx := 0; idx < 100; idx++ {
					rs[i][d][j][idx] = make([]byte, 32)
				}
			}
		}
	}

	mc := make([][][][][][]uint8, players)
	rc := make([][][][]uint8, players)
	mrmc := make([][][][][][]uint8, players)
	mccs := make([][][][][]uint8, players)
	rccs := make([][][]uint8, players)

	for i := 0; i < players; i++ {
		for j := 0; j < depth; j++ {
			for k := 0; k < 10; k++ {
				ms[i][0][j][k] = clone3D(m1[j][k][i])
				ms[i][1][j][k] = clone3D(m2[j][k][i])
			}

			rs[i][0][j] = clone2D(r1[j][i])
			rs[i][1][j] = clone2D(r2[j][i])
		}

		// Combine dealer shares for this player.
		cs := rpm.RPMCombineSharesAndMask(ms[i], rs[i], 100, uint64(depth), uint64(dealers))
		m, r, mrm := cs.Ms, cs.Rs, cs.Mrms // m: [][][][][]uint8, r: [][][]uint8, mrm: [][][][][]uint8

		// Propose sketches
		sp := rpm.RPMSketchPropose(m, r)
		mcc, rcc := sp.Mp, sp.Rp // mcc: [][][][]uint8, rcc: [][]uint8

		// Store per-player artifacts.
		mc[i] = m
		rc[i] = r
		mrmc[i] = mrm
		mccs[i] = mcc
		rccs[i] = rcc
	}

	if ok := rpm.RPMSketchVerify(mccs, rccs, uint64(dealers)); !ok {
		t.Fatalf("RPMSketchVerify failed")
	}

	// xs: [players][100][32]
	xs := make([][][]uint8, players)
	for j := 0; j < players; j++ {
		xs[j] = make([][]uint8, 100)
		for i := 0; i < 100; i++ {
			xs[j][i] = make([]uint8, 32)
		}
	}

	// For i in 0..99, create Shamir shares of Scalar(i) with n=players, t=dealers; add rc[j][0][i]
	for i := 1; i <= 100; i++ {
		// Encode i into a field element
		ival := (&curves.ScalarEd25519{}).New(i)
		shares := genPolyFrags(ival.(*curves.ScalarEd25519), players, dealers) // [][]byte length players

		for j := 0; j < players; j++ {
			rci, _ := (&curves.ScalarEd25519{}).SetBytes(rc[j][0][i-1])
			x := shares[j].Add(rci)
			xs[j][i-1] = x.Bytes()
		}
	}

	// parties = [1..players]
	parties := make([]uint64, players)
	for i := 0; i < players; i++ {
		parties[i] = uint64(i + 1)
	}

	for d := 0; d < depth; d++ {
		// ys: [players][100][32]
		ys := make([][][]uint8, players)
		for i := 0; i < players; i++ {
			out := rpm.RPMPermute(xs, mc[i], rc[i], mrmc[i], uint64(d), parties)
			ys[i] = clone2D(out[0]) // out[0] is [][]uint8
		}
		xs = ys

		if d == depth-1 {
			results := make([][][]byte, players)
			for i := 0; i < players; i++ {
				results[i] = rpm.RPMFinalize(xs, parties)
			}

			// Check the last layer yields a permutation of 0..99 (compare first byte for simplicity)
			// sort.Slice(results[0], func(i, j int) bool { return results[0][i][0] < results[0][j][0] })
			for i := 0; i < 100; i++ {
				fmt.Printf("%x\n", results[0][i])
			}
			t.Fatalf("")
		}
	}
}

// ---- small deep-clone helpers for nested byte-slices ----

func clone2D(a [][]byte) [][]byte {
	out := make([][]byte, len(a))
	for i := range a {
		if a[i] != nil {
			out[i] = slices.Clone(a[i])
		}
	}
	return out
}

// [][][]byte
func clone3D(a [][][]byte) [][][]byte {
	out := make([][][]byte, len(a))
	for i := range a {
		out[i] = clone2D(a[i])
	}
	return out
}

// clone3D for [10][10][32] represented as [][][]byte
func clone3DExact(a [][][]byte) [][][]byte {
	out := make([][][]byte, len(a))
	for i := range a {
		out[i] = make([][]byte, len(a[i]))
		for j := range a[i] {
			out[i][j] = slices.Clone(a[i][j])
		}
	}
	return out
}

// If the incoming shape is known to match, we can alias clone3D.
var _ = clone3DExact
