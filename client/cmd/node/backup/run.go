package backup

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	nodeconfig "source.quilibrium.com/quilibrium/monorepo/config"
)

// manifestVersion is the schema version written by this client. Version
// 2 adds host-context fields (HostOS, Home, ConfigsDir, NodeStateDir,
// NodeInstallDir) so cross-OS restore can remap absolute paths to the
// new host's equivalents. Restore accepts v1 manifests for back-compat.
const manifestVersion = 2

// normalizeBucketPrefix trims surrounding whitespace and leading/
// trailing slashes from a user-supplied bucket prefix. Empty input
// returns "" (meaning: store at the bucket root).
func normalizeBucketPrefix(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "/")
	return p
}

// joinKey joins a bucket prefix with one or more path segments using
// S3-style forward slashes. An empty prefix yields the segments joined
// directly (no leading slash). Empty segments are skipped.
func joinKey(prefix string, segs ...string) string {
	prefix = normalizeBucketPrefix(prefix)
	parts := make([]string, 0, len(segs)+1)
	if prefix != "" {
		parts = append(parts, prefix)
	}
	for _, s := range segs {
		s = strings.Trim(s, "/")
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "/")
}

const (
	// manifestObjectKey is the per-config manifest name at the root of
	// the config's S3 prefix. Clients read this on restore.
	manifestObjectKey = "manifest.json"

	// backupConcurrency is the number of parallel uploads/downloads.
	backupConcurrency = 4
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the node backup now (uploads config and worker data)",
	Long: `Upload the active node config plus its store/ and worker-store/*
directories to the configured S3-compatible bucket. Files are uploaded as-is
(no compression, no encryption beyond TLS to the endpoint).

The object layout is:

  <configName>/manifest.json
  <configName>/files/<relative path from config dir>

Files that live outside the config directory (if a custom DB.Path or
WorkerPaths is configured) are uploaded under:

  <configName>/absolute/<absolute path with leading slash stripped>

Restore uses manifest.json to place each object back at its recorded
absolute path.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading qclient config: %v\n", err)
			os.Exit(1)
		}
		if !cfg.Backup.Enabled {
			fmt.Fprintln(os.Stderr, "Warning: backups are disabled in qclient config. Proceeding anyway because `run` was invoked explicitly.")
		}
		if err := validateBackupConfigured(&cfg.Backup); err != nil {
			fmt.Fprintf(os.Stderr, "Error: backup not configured: %v\n", err)
			fmt.Fprintln(os.Stderr, "Run `qclient node backup config` first.")
			os.Exit(1)
		}
		if err := runBackup(&cfg.Backup); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// backupFile describes a single file selected for backup.
type backupFile struct {
	LocalPath string `json:"localPath"`
	ObjectKey string `json:"objectKey"`
	Size      int64  `json:"size"`
	MD5Hex    string `json:"md5"`
}

// manifest is the JSON document uploaded alongside the files.
//
// Host-context fields (HostOS, Home, ConfigsDir, NodeStateDir,
// NodeInstallDir) are populated starting at Version 2 and let restore
// remap absolute paths recorded on the source host to the equivalent
// locations on the destination host (e.g. Linux /home/alice →
// macOS /Users/alice, Linux /var/lib/quilibrium →
// macOS /usr/local/var/quilibrium). They are optional — a Version 1
// manifest restores to the recorded paths verbatim, as before.
type manifest struct {
	Version    int          `json:"version"`
	ConfigName string       `json:"configName"`
	ConfigDir  string       `json:"configDir"`
	CreatedAt  time.Time    `json:"createdAt"`
	Files      []backupFile `json:"files"`

	// v2 host context
	HostOS         string `json:"hostOS,omitempty"`
	Home           string `json:"home,omitempty"`
	ConfigsDir     string `json:"configsDir,omitempty"`
	NodeStateDir   string `json:"nodeStateDir,omitempty"`
	NodeInstallDir string `json:"nodeInstallDir,omitempty"`
}

func runBackup(b *utils.NodeBackupConfig) error {
	configName, configDir, cfg, err := resolveActiveNodeConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Backing up config %q from %s\n", configName, configDir)

	localFiles, err := gatherFilesForBackup(configDir, cfg)
	if err != nil {
		return fmt.Errorf("gather files: %w", err)
	}
	if len(localFiles) == 0 {
		return fmt.Errorf("no files found to back up in %s", configDir)
	}

	client, err := newS3Client(b)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}

	bucketPrefix := normalizeBucketPrefix(b.BucketPrefix)
	prefix := strings.TrimSuffix(configName, "/")
	entries := make([]backupFile, 0, len(localFiles))
	for _, local := range localFiles {
		key := objectKeyFor(bucketPrefix, prefix, configDir, local)
		entries = append(entries, backupFile{LocalPath: local, ObjectKey: key})
	}

	ctx := context.Background()
	if err := uploadFiles(ctx, client, b.Bucket, entries); err != nil {
		return err
	}

	mf := manifest{
		Version:        manifestVersion,
		ConfigName:     configName,
		ConfigDir:      configDir,
		CreatedAt:      time.Now().UTC(),
		Files:          entries,
		HostOS:         runtime.GOOS,
		Home:           currentHomeDir(),
		ConfigsDir:     utils.GetNodeConfigsDir(),
		NodeStateDir:   utils.GetNodeStateDir(),
		NodeInstallDir: utils.GetNodeInstallDir(),
	}
	if err := uploadManifest(ctx, client, b.Bucket, bucketPrefix, prefix, &mf); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}

	fmt.Printf("Backup complete: %d files uploaded to s3://%s/%s/\n",
		len(entries), b.Bucket, joinKey(bucketPrefix, prefix))
	return nil
}

// resolveActiveNodeConfig loads the active node config and returns a
// short name, its absolute config directory, and the loaded config.
// Mirrors the logic in client/cmd/node/node.go's PersistentPreRun so
// the backup package can run without importing its parent and causing
// an import cycle.
func resolveActiveNodeConfig() (name, dir string, cfg *nodeconfig.Config, err error) {
	cfg, err = utils.LoadDefaultNodeConfig()
	if err != nil {
		return "", "", nil, fmt.Errorf("load node config: %w", err)
	}
	resolved, dErr := utils.GetDefaultNodeConfigDir()
	if dErr == nil {
		dir = resolved
	} else {
		dir = utils.GetDefaultNodeConfigSymlink()
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		dir = abs
	}
	name = filepath.Base(dir)
	if name == "" || name == "/" {
		name = utils.DefaultNodeConfigName
	}
	return name, dir, cfg, nil
}

// gatherFilesForBackup returns all local files under configDir plus
// any external worker-store / db paths resolved from cfg.
func gatherFilesForBackup(configDir string, cfg *nodeconfig.Config) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string

	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	// Walk the entire config directory (config.yml, keys.yml, alias
	// file, and by default store/ + worker-store/* since they live
	// under configDir).
	if err := walkRegularFiles(configDir, add); err != nil {
		return nil, err
	}

	// If DB.Path or WorkerPaths point outside configDir, pick them up
	// too. Defaults keep them inside configDir so this is a no-op in
	// the common case.
	if cfg != nil && cfg.DB != nil {
		if cfg.DB.Path != "" {
			if err := walkRegularFiles(cfg.DB.Path, add); err != nil {
				return nil, err
			}
		}
		for _, wp := range cfg.DB.WorkerPaths {
			if err := walkRegularFiles(wp, add); err != nil {
				return nil, err
			}
		}
		// WorkerPathPrefix with %d is expanded by the node per core
		// at runtime; we can't know the core count here, so we
		// best-effort-glob siblings under the prefix's parent dir.
		if cfg.DB.WorkerPathPrefix != "" {
			if paths := expandWorkerPrefix(cfg.DB.WorkerPathPrefix); paths != nil {
				for _, wp := range paths {
					if err := walkRegularFiles(wp, add); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	sort.Strings(out)
	return out, nil
}

// expandWorkerPrefix returns directories matching a WorkerPathPrefix
// like "<base>/worker-store/%d" by listing sibling directories under
// "<base>/worker-store" whose names are pure integers.
func expandWorkerPrefix(prefix string) []string {
	idx := strings.LastIndex(prefix, "%d")
	if idx < 0 {
		if _, err := os.Stat(prefix); err == nil {
			return []string{prefix}
		}
		return nil
	}
	parent := strings.TrimRight(prefix[:idx], "/")
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only accept numeric names to avoid swallowing unrelated
		// siblings the operator may have put under worker-store/.
		if _, err := fmt.Sscanf(e.Name(), "%d", new(int)); err == nil {
			out = append(out, filepath.Join(parent, e.Name()))
		}
	}
	return out
}

func walkRegularFiles(root string, add func(string)) error {
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		abs, _ := filepath.Abs(root)
		add(abs)
		return nil
	}
	return filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		abs, aerr := filepath.Abs(p)
		if aerr != nil {
			abs = p
		}
		add(abs)
		return nil
	})
}

// objectKeyFor maps a local absolute path to an S3 object key under
// the (optional) bucket prefix and the configName prefix. Paths inside
// configDir become "<bucketPrefix>/<configName>/files/<relpath>";
// paths outside become
// "<bucketPrefix>/<configName>/absolute/<absolute path without leading slash>".
// When bucketPrefix is empty the layout is unchanged from v1.
func objectKeyFor(bucketPrefix, configName, configDir, localPath string) string {
	absConfig, _ := filepath.Abs(configDir)
	absLocal, _ := filepath.Abs(localPath)
	if rel, err := filepath.Rel(absConfig, absLocal); err == nil &&
		!strings.HasPrefix(rel, "..") {
		return joinKey(bucketPrefix, configName, "files", filepath.ToSlash(rel))
	}
	stripped := strings.TrimPrefix(absLocal, string(filepath.Separator))
	return joinKey(bucketPrefix, configName, "absolute", filepath.ToSlash(stripped))
}

func uploadFiles(ctx context.Context, client *s3.Client, bucket string, entries []backupFile) error {
	type result struct {
		idx int
		err error
	}
	results := make(chan result, len(entries))
	sem := make(chan struct{}, backupConcurrency)

	var wg sync.WaitGroup
	for i := range entries {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			size, md5Hex, err := uploadOne(ctx, client, bucket, &entries[i])
			if err == nil {
				entries[i].Size = size
				entries[i].MD5Hex = md5Hex
			}
			results <- result{idx: i, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var firstErr error
	done := 0
	for r := range results {
		done++
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s: %v\n", done, len(entries), entries[r.idx].LocalPath, r.err)
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		fmt.Printf("  [%d/%d] uploaded %s (%d bytes)\n", done, len(entries), entries[r.idx].ObjectKey, entries[r.idx].Size)
	}
	return firstErr
}

func uploadOne(ctx context.Context, client *s3.Client, bucket string, bf *backupFile) (int64, string, error) {
	f, err := os.Open(bf.LocalPath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return 0, "", err
	}

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return 0, "", err
	}
	md5Hex := hex.EncodeToString(h.Sum(nil))

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(bf.ObjectKey),
		Body:   f,
	})
	if err != nil {
		return 0, "", err
	}
	return fi.Size(), md5Hex, nil
}

// currentHomeDir returns the invoking user's home directory, preferring
// the sudo-invoking user so a root-run backup still records the human
// user's $HOME (matching GetNodeConfigsDir's resolution). Falls back to
// os.UserHomeDir, then empty string.
func currentHomeDir() string {
	if u, err := utils.GetCurrentSudoUser(); err == nil && u != nil && u.HomeDir != "" {
		return u.HomeDir
	}
	if u, err := user.Current(); err == nil && u != nil && u.HomeDir != "" {
		return u.HomeDir
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

func uploadManifest(ctx context.Context, client *s3.Client, bucket, bucketPrefix, prefix string, mf *manifest) error {
	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	key := joinKey(bucketPrefix, prefix, manifestObjectKey)
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        strings.NewReader(string(data)),
		ContentType: aws.String("application/json"),
	})
	return err
}
