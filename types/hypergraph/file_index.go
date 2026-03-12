package hypergraph

import (
	"encoding/binary"
	"fmt"
)

// File index binary format:
//
//	Header (28 bytes):
//	  magic:       8 bytes = "FILEINDX"
//	  version:     4 bytes = uint32(1) big-endian
//	  chunk_size:  4 bytes = uint32 big-endian
//	  total_size:  8 bytes = uint64 big-endian
//	  chunk_count: 4 bytes = uint32 big-endian
//	Body:
//	  blob_addrs:  chunk_count * 32 bytes (dataAddresses in chunk order)

const (
	fileIndexMagic      = "FILEINDX"
	fileIndexVersion    = 1
	fileIndexHeaderSize = 28
	fileIndexAddrSize   = 32
)

// BuildFileIndex constructs a binary file index from the given parameters.
func BuildFileIndex(totalSize uint64, chunkSize uint32, blobAddresses [][32]byte) []byte {
	buf := make([]byte, fileIndexHeaderSize+len(blobAddresses)*fileIndexAddrSize)

	copy(buf[0:8], fileIndexMagic)
	binary.BigEndian.PutUint32(buf[8:12], fileIndexVersion)
	binary.BigEndian.PutUint32(buf[12:16], chunkSize)
	binary.BigEndian.PutUint64(buf[16:24], totalSize)
	binary.BigEndian.PutUint32(buf[24:28], uint32(len(blobAddresses)))

	for i, addr := range blobAddresses {
		copy(buf[fileIndexHeaderSize+i*fileIndexAddrSize:], addr[:])
	}

	return buf
}

// ParseFileIndex parses a binary file index, returning its components.
func ParseFileIndex(data []byte) (totalSize uint64, chunkSize uint32, blobAddresses [][32]byte, err error) {
	if len(data) < fileIndexHeaderSize {
		return 0, 0, nil, fmt.Errorf("file index too short: %d bytes", len(data))
	}

	if string(data[0:8]) != fileIndexMagic {
		return 0, 0, nil, fmt.Errorf("invalid file index magic")
	}

	version := binary.BigEndian.Uint32(data[8:12])
	if version != fileIndexVersion {
		return 0, 0, nil, fmt.Errorf("unsupported file index version: %d", version)
	}

	chunkSize = binary.BigEndian.Uint32(data[12:16])
	totalSize = binary.BigEndian.Uint64(data[16:24])
	chunkCount := binary.BigEndian.Uint32(data[24:28])

	expectedLen := fileIndexHeaderSize + int(chunkCount)*fileIndexAddrSize
	if len(data) < expectedLen {
		return 0, 0, nil, fmt.Errorf(
			"file index truncated: expected %d bytes, got %d",
			expectedLen, len(data),
		)
	}

	blobAddresses = make([][32]byte, chunkCount)
	for i := uint32(0); i < chunkCount; i++ {
		offset := fileIndexHeaderSize + int(i)*fileIndexAddrSize
		copy(blobAddresses[i][:], data[offset:offset+fileIndexAddrSize])
	}

	return totalSize, chunkSize, blobAddresses, nil
}

// IsFileIndex checks whether data begins with the "FILEINDX" magic prefix.
func IsFileIndex(data []byte) bool {
	return len(data) >= 8 && string(data[0:8]) == fileIndexMagic
}
