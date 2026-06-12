//go:build rocksdb

package store

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// goLeafRoundTripsToRustSolo builds a known leaf via the same
// `tries.SerializeLeafNode` Go uses on disk, hands it to
// `translateGoNodeToRustSolo`, and checks the emitted bytes decode
// in the order Rust's `deserialize_node_solo` expects: type,
// key (len-prefixed u64), empty value (len-prefixed u64=0),
// hash_target (len-prefixed u64), commitment (len-prefixed u64),
// size (len-prefixed u64, signed BE).
func TestGoLeafTranslatesToRustSolo(t *testing.T) {
	leaf := &tries.LazyVectorCommitmentLeafNode{
		Key:        []byte{0xAA, 0xBB, 0xCC},
		Value:      []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		HashTarget: bytes.Repeat([]byte{0x11}, 32),
		Commitment: bytes.Repeat([]byte{0x22}, 64),
		Size:       big.NewInt(57005), // 0xDEAD — high bit set in 2-byte encoding
	}
	var lbuf bytes.Buffer
	if err := tries.SerializeLeafNode(&lbuf, leaf); err != nil {
		t.Fatalf("SerializeLeafNode: %v", err)
	}
	goBytes := append([]byte{tries.TypeLeaf}, lbuf.Bytes()...)

	rustBytes, leafKey, leafValue, err := translateGoNodeToRustSolo(goBytes)
	if err != nil {
		t.Fatalf("translateGoNodeToRustSolo: %v", err)
	}
	if !bytes.Equal(leafKey, leaf.Key) {
		t.Fatalf("leafKey mismatch: got %x, want %x", leafKey, leaf.Key)
	}
	if !bytes.Equal(leafValue, leaf.Value) {
		t.Fatalf("leafValue mismatch: got %x, want %x", leafValue, leaf.Value)
	}

	// Decode the emitted Rust solo bytes by hand and assert each
	// field. This catches any drift in the serializer layout.
	rb := bytes.NewBuffer(rustBytes)
	if b, _ := rb.ReadByte(); b != 1 {
		t.Fatalf("first byte should be TYPE_LEAF (1), got %d", b)
	}
	gotKey := readLenU64OrFail(t, rb, "key")
	if !bytes.Equal(gotKey, leaf.Key) {
		t.Fatalf("rust key mismatch: got %x, want %x", gotKey, leaf.Key)
	}
	gotValue := readLenU64OrFail(t, rb, "value")
	if len(gotValue) != 0 {
		t.Fatalf("rust value must be empty after migration, got %x", gotValue)
	}
	gotHashTarget := readLenU64OrFail(t, rb, "hash_target")
	if !bytes.Equal(gotHashTarget, leaf.HashTarget) {
		t.Fatalf("rust hash_target mismatch")
	}
	gotCommitment := readLenU64OrFail(t, rb, "commitment")
	if !bytes.Equal(gotCommitment, leaf.Commitment) {
		t.Fatalf("rust commitment mismatch")
	}
	gotSize := readLenU64OrFail(t, rb, "size")
	// Rust's signed BE encoding for 0xDEAD = positive 57005:
	// the high bit of the high byte would be set, so we expect a
	// leading 0x00.
	want := []byte{0x00, 0xDE, 0xAD}
	if !bytes.Equal(gotSize, want) {
		t.Fatalf("rust size mismatch: got %x, want %x", gotSize, want)
	}
}

// goBranchTranslatesToRustSolo builds a known branch via Go's
// on-disk format (type + pathLen + fullPrefix +
// SerializeBranchNode(false)) and verifies the migrator emits the
// matching Rust solo layout (which drops the pathLen + fullPrefix).
func TestGoBranchTranslatesToRustSolo(t *testing.T) {
	branch := &tries.LazyVectorCommitmentBranchNode{
		Prefix:        []int{1, 2, 3},
		FullPrefix:    []int{7, 8},
		Commitment:    bytes.Repeat([]byte{0x33}, 64),
		Size:          big.NewInt(258), // 0x0102 — high bit clear
		LeafCount:     7,
		LongestBranch: 3,
	}
	var bbuf bytes.Buffer
	if err := tries.SerializeBranchNode(&bbuf, branch, false); err != nil {
		t.Fatalf("SerializeBranchNode: %v", err)
	}
	// Prepend type + pathLen + fullPrefix (matching
	// `PebbleHypergraphStore.InsertNode` line 1538-1554).
	hdr := []byte{tries.TypeBranch}
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(branch.FullPrefix)))
	for _, p := range branch.FullPrefix {
		hdr = binary.BigEndian.AppendUint32(hdr, uint32(p))
	}
	goBytes := append(hdr, bbuf.Bytes()...)

	rustBytes, leafKey, leafValue, err := translateGoNodeToRustSolo(goBytes)
	if err != nil {
		t.Fatalf("translateGoNodeToRustSolo: %v", err)
	}
	if leafKey != nil || leafValue != nil {
		t.Fatalf("branches must not produce per-vertex KV")
	}

	rb := bytes.NewBuffer(rustBytes)
	if b, _ := rb.ReadByte(); b != 2 {
		t.Fatalf("first byte should be TYPE_BRANCH (2), got %d", b)
	}
	var prefixLen uint32
	if err := binary.Read(rb, binary.BigEndian, &prefixLen); err != nil {
		t.Fatalf("prefix_len: %v", err)
	}
	if prefixLen != 3 {
		t.Fatalf("prefix_len: got %d, want 3", prefixLen)
	}
	for i := uint32(0); i < prefixLen; i++ {
		var p int32
		if err := binary.Read(rb, binary.BigEndian, &p); err != nil {
			t.Fatalf("prefix[%d]: %v", i, err)
		}
		if int(p) != branch.Prefix[i] {
			t.Fatalf("prefix[%d] mismatch: got %d, want %d", i, p, branch.Prefix[i])
		}
	}
	gotCommitment := readLenU64OrFail(t, rb, "commitment")
	if !bytes.Equal(gotCommitment, branch.Commitment) {
		t.Fatalf("commitment mismatch")
	}
	gotSize := readLenU64OrFail(t, rb, "size")
	// 258 = 0x0102, high bit clear → no prepended 0.
	if !bytes.Equal(gotSize, []byte{0x01, 0x02}) {
		t.Fatalf("size mismatch: got %x, want 0102", gotSize)
	}
	var leafCount int64
	if err := binary.Read(rb, binary.BigEndian, &leafCount); err != nil {
		t.Fatalf("leaf_count: %v", err)
	}
	if leafCount != 7 {
		t.Fatalf("leaf_count: got %d, want 7", leafCount)
	}
	var longestBranch int32
	if err := binary.Read(rb, binary.BigEndian, &longestBranch); err != nil {
		t.Fatalf("longest_branch: %v", err)
	}
	if longestBranch != 3 {
		t.Fatalf("longest_branch: got %d, want 3", longestBranch)
	}
	if rb.Len() != 0 {
		t.Fatalf("%d trailing bytes after branch", rb.Len())
	}
}

// TestTranslateByKeyAndByPathKeys exercises the key-translation
// branch: the eight Go sub-prefixes map to (set_byte, phase_byte,
// is_by_path) tuples consistent with the Rust `set_type_byte` /
// `phase_type_byte` helpers.
func TestTranslateByKeyAndByPathKeys(t *testing.T) {
	cases := []struct {
		name      string
		subPrefix byte
		set       byte
		phase     byte
		byPath    bool
	}{
		{"vertex_adds_by_key", VERTEX_ADDS_TREE_NODE, 0, 0, false},
		{"vertex_removes_by_key", VERTEX_REMOVES_TREE_NODE, 0, 1, false},
		{"hyperedge_adds_by_key", HYPEREDGE_ADDS_TREE_NODE, 1, 0, false},
		{"hyperedge_removes_by_key", HYPEREDGE_REMOVES_TREE_NODE, 1, 1, false},
		{"vertex_adds_by_path", VERTEX_ADDS_TREE_NODE_BY_PATH, 0, 0, true},
		{"vertex_removes_by_path", VERTEX_REMOVES_TREE_NODE_BY_PATH, 0, 1, true},
		{"hyperedge_adds_by_path", HYPEREDGE_ADDS_TREE_NODE_BY_PATH, 1, 0, true},
		{"hyperedge_removes_by_path", HYPEREDGE_REMOVES_TREE_NODE_BY_PATH, 1, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, bp, ok := classifyTreeNodeKey(tc.subPrefix)
			if !ok {
				t.Fatalf("classify returned ok=false for known sub-prefix 0x%02x", tc.subPrefix)
			}
			if s != tc.set || p != tc.phase || bp != tc.byPath {
				t.Fatalf("classify mismatch: got (set=%d, phase=%d, byPath=%v), want (set=%d, phase=%d, byPath=%v)",
					s, p, bp, tc.set, tc.phase, tc.byPath)
			}
		})
	}
	// Anything not in the table is not a tree node.
	if _, _, _, ok := classifyTreeNodeKey(0xFF); ok {
		t.Fatalf("classify accepted unknown sub-prefix 0xFF")
	}
}

// TestUnsignedToSignedBigInt covers the encoding bridge: Go writes
// big.Int.Bytes() (unsigned); Rust reads BigInt::from_signed_bytes_be.
func TestUnsignedToSignedBigInt(t *testing.T) {
	// Small positive: 0x01 stays as [0x01].
	if got := goUnsignedToRustSignedBigInt([]byte{0x01}); !bytes.Equal(got, []byte{0x01}) {
		t.Fatalf("small positive: got %x", got)
	}
	// High bit set (0xDEAD): needs leading 0 to stay positive.
	if got := goUnsignedToRustSignedBigInt([]byte{0xDE, 0xAD}); !bytes.Equal(got, []byte{0x00, 0xDE, 0xAD}) {
		t.Fatalf("high-bit set: got %x", got)
	}
	// High bit clear (0x7FFF): keeps as-is.
	if got := goUnsignedToRustSignedBigInt([]byte{0x7F, 0xFF}); !bytes.Equal(got, []byte{0x7F, 0xFF}) {
		t.Fatalf("high-bit clear: got %x", got)
	}
	// Single 0x80: high bit set, single byte → [0x00, 0x80].
	if got := goUnsignedToRustSignedBigInt([]byte{0x80}); !bytes.Equal(got, []byte{0x00, 0x80}) {
		t.Fatalf("single 0x80: got %x", got)
	}
	// Empty stays empty (Rust treats empty as zero).
	if got := goUnsignedToRustSignedBigInt(nil); len(got) != 0 {
		t.Fatalf("empty: got %x", got)
	}
	// Defensive leading-zero strip (Go's Bytes() never emits them
	// but the helper handles it anyway).
	if got := goUnsignedToRustSignedBigInt([]byte{0x00, 0x00, 0x42}); !bytes.Equal(got, []byte{0x42}) {
		t.Fatalf("leading-zero strip: got %x", got)
	}
}

func readLenU64OrFail(t *testing.T, buf *bytes.Buffer, label string) []byte {
	t.Helper()
	var n uint64
	if err := binary.Read(buf, binary.BigEndian, &n); err != nil {
		t.Fatalf("%s len header: %v", label, err)
	}
	out := make([]byte, n)
	if _, err := buf.Read(out); err != nil {
		t.Fatalf("%s body: %v", label, err)
	}
	return out
}
