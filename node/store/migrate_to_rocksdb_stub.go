//go:build !rocksdb

package store

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/config"
)

// MigrateToRocksDB is a stub when built without the "rocksdb" tag.
// Build with: go build -tags rocksdb
func MigrateToRocksDB(pebblePath string, rocksdbPath string) error {
	return fmt.Errorf(
		"migration requires RocksDB support; rebuild with: go build -tags rocksdb",
	)
}

// MigrateToRocksDBFromConfig is a stub when built without the "rocksdb" tag.
func MigrateToRocksDBFromConfig(cfg *config.Config, rocksdbPath string) error {
	return MigrateToRocksDB("", rocksdbPath)
}

// VerifyRocksDBMigration is a stub when built without the "rocksdb" tag.
// Build with: go build -tags rocksdb
func VerifyRocksDBMigration(rocksdbPath string) error {
	return fmt.Errorf(
		"migration verification requires RocksDB support; rebuild with: go build -tags rocksdb",
	)
}
