package data

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (e *DataClockConsensusEngine) downloadSnapshot(
	dbPath string,
	network uint8,
) error {
	frame, _, err := e.clockStore.GetLatestDataClockFrame(e.filter)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}

	if frame.Timestamp > time.Now().Add(-6*time.Hour).UnixMilli() {
		return errors.Wrap(
			errors.New("synced higher than recent snapshot"),
			"download snapshot",
		)
	}

	resp, err := http.Get(
		fmt.Sprintf(
			"https://frame-snapshots.quilibrium.com/%d/latest-backup",
			network,
		),
	)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() {
		return errors.Wrap(
			errors.New("metadata file is empty"),
			"download snapshot",
		)
	}
	zipURL := strings.TrimSpace(scanner.Text())

	if !scanner.Scan() {
		return errors.Wrap(
			errors.New("metadata file missing hash"),
			"download snapshot",
		)
	}
	expectedHash := strings.TrimSpace(scanner.Text())

	resp, err = http.Get(
		fmt.Sprintf(
			"https://frame-snapshots.quilibrium.com/%d/%s",
			network,
			zipURL,
		),
	)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}
	defer resp.Body.Close()

	err = os.MkdirAll(
		path.Join(dbPath, "snapshot"),
		0755,
	)
	if err != nil {
		return errors.Wrap(
			fmt.Errorf("failed to create extraction directory: %w", err),
			"download snapshot",
		)
	}

	tempFile, err := os.CreateTemp(
		path.Join(dbPath, "snapshot"),
		"snapshot.zip",
	)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(tempFile, hasher)

	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		return errors.Wrap(err, "download snapshot")
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != expectedHash {
		return errors.Wrap(
			fmt.Errorf(
				"hash mismatch: expected %s, got %s",
				expectedHash,
				actualHash,
			),
			"download snapshot",
		)
	}

	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		destPath := filepath.Join(
			path.Join(dbPath, "snapshot"),
			file.Name,
		)
		if !strings.HasPrefix(
			destPath,
			filepath.Clean(path.Join(dbPath, "snapshot"))+string(os.PathSeparator),
		) {
			return errors.Wrap(
				fmt.Errorf("invalid file path in zip: %s", file.Name),
				"download snapshot",
			)
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, file.Mode())
			continue
		}
		err := os.MkdirAll(filepath.Dir(destPath), 0755)
		if err != nil {
			return errors.Wrap(
				fmt.Errorf(
					"failed to create directory for file %s: %w",
					file.Name,
					err,
				),
				"download snapshot",
			)
		}

		destFile, err := os.OpenFile(
			destPath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode(),
		)
		if err != nil {
			return errors.Wrap(
				fmt.Errorf("failed to create destination file %s: %w", file.Name, err),
				"download snapshot",
			)
		}

		srcFile, err := file.Open()
		if err != nil {
			destFile.Close()
			return errors.Wrap(
				fmt.Errorf("failed to open file in zip %s: %w", file.Name, err),
				"download snapshot",
			)
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()
		if err != nil {
			return errors.Wrap(
				fmt.Errorf("failed to extract file %s: %w", file.Name, err),
				"download snapshot",
			)
		}
	}

	return nil
}

func (e *DataClockConsensusEngine) applySnapshot(
	dbPath string,
) error {
	dirEntries, err := os.ReadDir(
		path.Join(dbPath, "snapshot"),
	)
	if err != nil {
		return errors.Wrap(
			err,
			"apply snapshot",
		)
	}
	defer os.RemoveAll(path.Join(dbPath, "snapshot"))

	snapshotDBPath := ""
	for _, entry := range dirEntries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "exporter") {
			snapshotDBPath = path.Join(path.Join(dbPath, "snapshot"), entry.Name())
		}
	}

	if snapshotDBPath == "" {
		return nil
	}

	temporaryStore := store.NewPebbleDB(&config.DBConfig{
		Path: snapshotDBPath,
	})
	temporaryClockStore := store.NewPebbleClockStore(temporaryStore, e.logger)

	max, _, err := e.clockStore.GetLatestDataClockFrame(e.filter)
	if err != nil {
		temporaryStore.Close()
		return errors.Wrap(
			err,
			"apply snapshot",
		)
	}

	key := []byte{store.CLOCK_FRAME, store.CLOCK_DATA_FRAME_DATA}
	key = binary.BigEndian.AppendUint64(key, 0)
	key = append(key, e.filter...)

	_, _, err = temporaryClockStore.GetDataClockFrame(
		e.filter,
		max.FrameNumber+1,
		false,
	)
	if err != nil {
		fmt.Println("not found", max.FrameNumber+1)
		temporaryStore.Close()
		return errors.Wrap(
			err,
			"apply snapshot",
		)
	}

	for i := max.FrameNumber + 1; true; i++ {
		frame, _, err := temporaryClockStore.GetDataClockFrame(
			e.filter,
			i,
			false,
		)
		if err != nil {
			break
		}

		if err := e.handleClockFrame([]byte{}, []byte{}, frame); err != nil {
			temporaryStore.Close()
			return errors.Wrap(
				err,
				"apply snapshot",
			)
		}
	}

	temporaryStore.Close()

	e.logger.Info("imported snapshot")

	return nil
}
