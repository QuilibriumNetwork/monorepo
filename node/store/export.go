package store

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

// ExportDatabase exports all key-value pairs from a Pebble database
// to a portable binary format file for migration to RocksDB.
//
// Format:
//
//	[magic: 4 bytes "QMIG"]
//	[version: uint32 BE = 1]
//	[entry_count: uint64 BE]
//	repeated {
//	  [key_len: uint32 BE][key bytes]
//	  [value_len: uint32 BE][value bytes]
//	}
//	[sha256: 32 bytes checksum of all preceding bytes]
func ExportDatabase(dbPath string, outputPath string) error {
	fmt.Printf("opening database at %s (read-only)\n", dbPath)

	opts := &pebble.Options{
		MemTableSize:          64 << 20,
		MaxOpenFiles:          1000,
		L0CompactionThreshold: 8,
		L0StopWritesThreshold: 32,
		LBaseMaxBytes:         64 << 20,
		FormatMajorVersion:    pebble.FormatNewest,
		ReadOnly:              true,
	}

	db, err := pebble.Open(dbPath, opts)
	if err != nil {
		return errors.Wrap(err, "open database")
	}
	defer db.Close()

	fmt.Println("database opened successfully")
	return exportFromDB(db, outputPath)
}

// ExportDatabaseFromConfig resolves the database path from a config and core
// ID, matching the logic in NewPebbleDB, then exports to outputPath.
func ExportDatabaseFromConfig(
	cfg *config.Config,
	coreId uint,
	outputPath string,
) error {
	path := cfg.DB.Path
	if coreId > 0 && len(cfg.DB.WorkerPaths) > int(coreId-1) {
		path = cfg.DB.WorkerPaths[coreId-1]
	} else if coreId > 0 {
		path = fmt.Sprintf(cfg.DB.WorkerPathPrefix, coreId)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("database path does not exist: %s", path)
	}

	return ExportDatabase(path, outputPath)
}

// exportFromDB performs the actual export from an already-open database.
// Use outputPath="-" to write to stdout (for piping to the Rust importer
// without using any extra disk space).
func exportFromDB(db *pebble.DB, outputPath string) error {
	var outFile *os.File
	var isStdout bool
	if outputPath == "-" {
		outFile = os.Stdout
		isStdout = true
	} else {
		var err error
		outFile, err = os.Create(outputPath)
		if err != nil {
			return errors.Wrap(err, "create output file")
		}
		defer outFile.Close()
	}
	_ = isStdout

	// Use a checksumming writer that hashes everything written.
	cw := &checksumWriter{
		w: outFile,
		h: sha256.New(),
	}

	// Write magic bytes.
	if _, err := cw.Write([]byte("QMIG")); err != nil {
		return errors.Wrap(err, "write magic")
	}

	// Write version = 1.
	if err := binary.Write(cw, binary.BigEndian, uint32(1)); err != nil {
		return errors.Wrap(err, "write version")
	}

	// Write placeholder entry count (8 bytes). We will seek back to fill this
	// once we know the real count.
	countOffset := int64(4 + 4) // after magic + version
	if err := binary.Write(cw, binary.BigEndian, uint64(0)); err != nil {
		return errors.Wrap(err, "write placeholder count")
	}

	// Iterate all entries.
	iter, err := db.NewIter(nil)
	if err != nil {
		return errors.Wrap(err, "create iterator")
	}
	defer iter.Close()

	var (
		entryCount uint64
		totalBytes uint64
		buf4       [4]byte
		startTime  = time.Now()
	)

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		val, err := iter.ValueAndErr()
		if err != nil {
			return errors.Wrapf(err, "read value at entry %d", entryCount)
		}

		// Write key_len + key.
		binary.BigEndian.PutUint32(buf4[:], uint32(len(key)))
		if _, err := cw.Write(buf4[:]); err != nil {
			return errors.Wrap(err, "write key length")
		}
		if _, err := cw.Write(key); err != nil {
			return errors.Wrap(err, "write key")
		}

		// Write value_len + value.
		binary.BigEndian.PutUint32(buf4[:], uint32(len(val)))
		if _, err := cw.Write(buf4[:]); err != nil {
			return errors.Wrap(err, "write value length")
		}
		if _, err := cw.Write(val); err != nil {
			return errors.Wrap(err, "write value")
		}

		entryCount++
		totalBytes += uint64(len(key) + len(val))

		if entryCount%100_000 == 0 {
			elapsed := time.Since(startTime)
			fmt.Printf(
				"  exported %d entries (%s data, %s elapsed)\n",
				entryCount,
				formatBytes(totalBytes),
				elapsed.Round(time.Second),
			)
		}
	}

	if err := iter.Error(); err != nil {
		return errors.Wrap(err, "iterator error")
	}

	if isStdout {
		// Streaming mode: no seek possible. Write the checksum from the
		// running hash (which includes entry_count=0 in the header — the
		// Rust importer skips checksum verification for stdin).
		checksum := cw.h.Sum(nil)
		if _, err := outFile.Write(checksum); err != nil {
			return errors.Wrap(err, "write streaming checksum")
		}
		fmt.Fprintf(os.Stderr,
			"export complete: %d entries, %s data, %s elapsed (streamed)\n",
			entryCount, formatBytes(totalBytes),
			time.Since(startTime).Round(time.Second),
		)
		return nil
	}

	// File mode: seek back to patch entry count, recompute checksum.
	tempChecksum := cw.h.Sum(nil)
	if _, err := outFile.Write(tempChecksum); err != nil {
		return errors.Wrap(err, "write temp checksum")
	}

	if _, err := outFile.Seek(countOffset, io.SeekStart); err != nil {
		return errors.Wrap(err, "seek to count offset")
	}
	if err := binary.Write(outFile, binary.BigEndian, entryCount); err != nil {
		return errors.Wrap(err, "write entry count")
	}

	fileInfo, err := outFile.Stat()
	if err != nil {
		return errors.Wrap(err, "stat output file")
	}
	dataLen := fileInfo.Size() - sha256.Size

	if _, err := outFile.Seek(0, io.SeekStart); err != nil {
		return errors.Wrap(err, "seek to start for checksum")
	}

	h := sha256.New()
	if _, err := io.CopyN(h, outFile, dataLen); err != nil {
		return errors.Wrap(err, "recompute checksum")
	}
	finalChecksum := h.Sum(nil)

	if _, err := outFile.Seek(dataLen, io.SeekStart); err != nil {
		return errors.Wrap(err, "seek to checksum position")
	}
	if _, err := outFile.Write(finalChecksum); err != nil {
		return errors.Wrap(err, "write final checksum")
	}

	elapsed := time.Since(startTime)
	fmt.Printf(
		"export complete: %d entries, %s data, %s total file size, %s elapsed\n",
		entryCount,
		formatBytes(totalBytes),
		formatBytes(uint64(fileInfo.Size())),
		elapsed.Round(time.Second),
	)
	fmt.Printf("output: %s\n", outputPath)
	fmt.Printf("sha256: %x\n", finalChecksum)

	return nil
}

// VerifyExport reads an exported file and verifies its checksum.
// Returns the entry count and nil error on success.
func VerifyExport(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "open export file")
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, errors.Wrap(err, "stat export file")
	}

	minSize := int64(4 + 4 + 8 + sha256.Size)
	if info.Size() < minSize {
		return 0, fmt.Errorf(
			"file too small to be a valid export (%d bytes, minimum %d)",
			info.Size(), minSize,
		)
	}

	dataLen := info.Size() - sha256.Size

	// Hash everything except the trailing checksum.
	h := sha256.New()
	if _, err := io.CopyN(h, f, dataLen); err != nil {
		return 0, errors.Wrap(err, "hash file data")
	}
	computed := h.Sum(nil)

	// Read the stored checksum.
	stored := make([]byte, sha256.Size)
	if _, err := io.ReadFull(f, stored); err != nil {
		return 0, errors.Wrap(err, "read stored checksum")
	}

	for i := range computed {
		if computed[i] != stored[i] {
			return 0, fmt.Errorf(
				"checksum mismatch: computed %x, stored %x",
				computed, stored,
			)
		}
	}

	// Seek back and read the header to extract entry count.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, errors.Wrap(err, "seek to start")
	}

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return 0, errors.Wrap(err, "read magic")
	}
	if string(magic) != "QMIG" {
		return 0, fmt.Errorf("invalid magic: %q", magic)
	}

	var version uint32
	if err := binary.Read(f, binary.BigEndian, &version); err != nil {
		return 0, errors.Wrap(err, "read version")
	}
	if version != 1 {
		return 0, fmt.Errorf("unsupported version: %d", version)
	}

	var entryCount uint64
	if err := binary.Read(f, binary.BigEndian, &entryCount); err != nil {
		return 0, errors.Wrap(err, "read entry count")
	}

	return entryCount, nil
}

// checksumWriter wraps a writer and feeds all written bytes into a hash.
type checksumWriter struct {
	w io.Writer
	h hash.Hash
}

func (cw *checksumWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.h.Write(p[:n])
	}
	return n, err
}

func formatBytes(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
