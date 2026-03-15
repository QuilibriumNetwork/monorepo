package hypergraph

import (
	"testing"
)

func TestBuildAndParseFileIndex(t *testing.T) {
	addrs := [][32]byte{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}

	data := BuildFileIndex(12345678, 4*1024*1024, addrs)

	totalSize, chunkSize, parsedAddrs, err := ParseFileIndex(data)
	if err != nil {
		t.Fatalf("ParseFileIndex: %v", err)
	}

	if totalSize != 12345678 {
		t.Errorf("totalSize = %d, want 12345678", totalSize)
	}
	if chunkSize != 4*1024*1024 {
		t.Errorf("chunkSize = %d, want %d", chunkSize, 4*1024*1024)
	}
	if len(parsedAddrs) != 3 {
		t.Fatalf("len(parsedAddrs) = %d, want 3", len(parsedAddrs))
	}
	for i, addr := range parsedAddrs {
		if addr != addrs[i] {
			t.Errorf("addr[%d] = %v, want %v", i, addr, addrs[i])
		}
	}
}

func TestIsFileIndex(t *testing.T) {
	data := BuildFileIndex(100, 50, [][32]byte{{1}})
	if !IsFileIndex(data) {
		t.Error("IsFileIndex returned false for valid index")
	}

	if IsFileIndex([]byte("not an index")) {
		t.Error("IsFileIndex returned true for non-index data")
	}

	if IsFileIndex(nil) {
		t.Error("IsFileIndex returned true for nil")
	}

	if IsFileIndex([]byte("FILE")) {
		t.Error("IsFileIndex returned true for short data")
	}
}

func TestParseFileIndexErrors(t *testing.T) {
	// Too short
	_, _, _, err := ParseFileIndex([]byte("short"))
	if err == nil {
		t.Error("expected error for short data")
	}

	// Wrong magic
	bad := make([]byte, 28)
	copy(bad, "BADMAGIC")
	_, _, _, err = ParseFileIndex(bad)
	if err == nil {
		t.Error("expected error for wrong magic")
	}

	// Truncated body
	data := BuildFileIndex(100, 50, [][32]byte{{1}, {2}})
	_, _, _, err = ParseFileIndex(data[:40])
	if err == nil {
		t.Error("expected error for truncated body")
	}
}

func TestBuildFileIndexEmpty(t *testing.T) {
	data := BuildFileIndex(0, 4*1024*1024, nil)
	totalSize, chunkSize, addrs, err := ParseFileIndex(data)
	if err != nil {
		t.Fatalf("ParseFileIndex: %v", err)
	}
	if totalSize != 0 {
		t.Errorf("totalSize = %d, want 0", totalSize)
	}
	if chunkSize != 4*1024*1024 {
		t.Errorf("chunkSize = %d, want %d", chunkSize, 4*1024*1024)
	}
	if len(addrs) != 0 {
		t.Errorf("len(addrs) = %d, want 0", len(addrs))
	}
}
