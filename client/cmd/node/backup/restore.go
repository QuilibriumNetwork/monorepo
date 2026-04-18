package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	restoreConfigName string
	restoreForce      bool
	restoreDryRun     bool
	restoreConfigOnly bool
	restoreMaster     bool
	restoreWorkerAll  bool
	restoreWorkers    []string
	restorePathSubs   []string
	restorePathMaps   []string
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Download a previous backup back into its original locations",
	Long: `Restore files from the configured S3-compatible bucket to the local
filesystem, placing each file at the absolute path recorded in manifest.json.

By default the active node config name is used as the backup prefix. Override
with --name to restore a different config (e.g. when recovering onto a fresh
host). Existing files are skipped unless --force is passed.

Selective restore (combinable, union semantics — a file matches if ANY filter
matches; with no filters, everything in the manifest is restored):

  --config              only config files: config.yml, keys.yml, alias file,
                        logger dir, and anything else outside store/ and
                        worker-store/
  --master              only the master store/ directory
  --worker EXPR         only the listed worker-store/<N> directories. EXPR
                        accepts integers, ranges, and comma-separated lists,
                        e.g. --worker 3 | --worker 1-3,5,7-16 | --worker 0,2,4.
                        Flag is repeatable; selections are unioned.
  --worker-all          all worker-store/* directories
  --path SUBSTR         only files whose local path contains SUBSTR (repeatable)

Cross-OS / cross-host restore:

  Backups taken by a recent client record the source host's $HOME,
  configs dir, node state dir, and install dir in manifest.json. On
  restore, absolute paths are automatically remapped to the equivalent
  locations on this host (e.g. Linux /home/alice → macOS /Users/alice,
  Linux /var/lib/quilibrium → macOS /usr/local/var/quilibrium), and the
  restored config.yml has its embedded logger/alias/key/db paths
  rewritten to match. For any leftover absolute paths that can't be
  mapped automatically, pass one or more --path-map OLD=NEW flags.

  --path-map OLD=NEW    rewrite destination paths whose prefix is OLD
                        to NEW (both must be absolute; repeatable)

Examples:

  qclient node backup restore --config
  qclient node backup restore --master
  qclient node backup restore --worker 0 --worker 3
  qclient node backup restore --worker 1-3,5,7-16
  qclient node backup restore --worker-all --master
  qclient node backup restore --path config.yml`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading qclient config: %v\n", err)
			os.Exit(1)
		}
		if err := validateBackupConfigured(&cfg.Backup); err != nil {
			fmt.Fprintf(os.Stderr, "Error: backup not configured: %v\n", err)
			fmt.Fprintln(os.Stderr, "Run `qclient node backup config` first.")
			os.Exit(1)
		}

		name := restoreConfigName
		if name == "" {
			resolvedName, _, _, rerr := resolveActiveNodeConfig()
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "Error resolving active node config: %v\n", rerr)
				fmt.Fprintln(os.Stderr, "Pass --name <configName> to specify a backup to restore.")
				os.Exit(1)
			}
			name = resolvedName
		}

		workers, wErr := parseWorkerSelectors(restoreWorkers)
		if wErr != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid --worker value: %v\n", wErr)
			os.Exit(1)
		}
		sel := restoreSelector{
			configOnly: restoreConfigOnly,
			master:     restoreMaster,
			workerAll:  restoreWorkerAll,
			workers:    workers,
			pathSubs:   restorePathSubs,
		}
		if err := runRestore(&cfg.Backup, name, sel, restorePathMaps, restoreForce, restoreDryRun); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	restoreCmd.Flags().StringVar(&restoreConfigName, "name", "", "backup name to restore (defaults to active node config)")
	restoreCmd.Flags().BoolVar(&restoreForce, "force", false, "overwrite existing files")
	restoreCmd.Flags().BoolVar(&restoreDryRun, "dry-run", false, "show what would be downloaded without writing")
	restoreCmd.Flags().BoolVar(&restoreConfigOnly, "config", false, "restore only config files (config.yml, keys.yml, alias, logger) and skip store/worker-store")
	restoreCmd.Flags().BoolVar(&restoreMaster, "master", false, "restore only the master store/ directory")
	restoreCmd.Flags().BoolVar(&restoreWorkerAll, "worker-all", false, "restore all worker-store/* directories")
	restoreCmd.Flags().StringSliceVar(&restoreWorkers, "worker", nil, "worker indices to restore: single (3), range (1-3), or list (1-3,5,7-16); repeatable")
	restoreCmd.Flags().StringSliceVar(&restorePathSubs, "path", nil, "restore files whose local path contains this substring (repeatable)")
	restoreCmd.Flags().StringSliceVar(&restorePathMaps, "path-map", nil, "rewrite destination paths: --path-map /old/prefix=/new/prefix (repeatable)")
}

// restoreSelector is the set of include filters parsed from flags.
// When all fields are zero-valued, every file in the manifest is
// selected (full restore).
type restoreSelector struct {
	configOnly bool
	master     bool
	workerAll  bool
	workers    []int
	pathSubs   []string
}

func (s restoreSelector) isFull() bool {
	return !s.configOnly && !s.master && !s.workerAll &&
		len(s.workers) == 0 && len(s.pathSubs) == 0
}

// parseWorkerSelectors parses one or more --worker values into a
// deduplicated, sorted list of worker indices. Each value may be a
// comma-separated list of integers or inclusive ranges, e.g.
// "3", "1-3", "0,2,4", "1-3,5,7-16". Negative indices are rejected.
func parseWorkerSelectors(values []string) ([]int, error) {
	set := make(map[int]struct{})
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				bounds := strings.SplitN(part, "-", 2)
				lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("bad range %q", part)
				}
				if lo < 0 || hi < 0 {
					return nil, fmt.Errorf("negative worker index in %q", part)
				}
				if lo > hi {
					return nil, fmt.Errorf("range %q: lower bound greater than upper bound", part)
				}
				for i := lo; i <= hi; i++ {
					set[i] = struct{}{}
				}
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad worker index %q", part)
			}
			if n < 0 {
				return nil, fmt.Errorf("negative worker index %d", n)
			}
			set[n] = struct{}{}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out, nil
}

// workerIndexRe matches .../worker-store/<N>/... or .../worker-store/<N>
// at end-of-path, with N as a non-negative integer. Capture group 1 is
// the index. Used against both LocalPath and ObjectKey so it works
// whether the file was backed up under files/ or absolute/.
var workerIndexRe = regexp.MustCompile(`(?:^|/)worker-store/(\d+)(?:/|$)`)

// isStorePath reports whether p is inside a master store/ directory
// (not worker-store/). We check the "/store/" segment but exclude any
// path that also matches worker-store/.
func isStorePath(p string) bool {
	norm := filepath.ToSlash(p)
	if workerIndexRe.MatchString(norm) {
		return false
	}
	return strings.Contains(norm, "/store/") || strings.HasSuffix(norm, "/store")
}

// workerIndexFor returns the worker index for p, or -1 if p is not a
// worker-store path.
func workerIndexFor(p string) int {
	norm := filepath.ToSlash(p)
	m := workerIndexRe.FindStringSubmatch(norm)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// selectFiles returns the subset of entries that matches sel.
func selectFiles(entries []backupFile, sel restoreSelector) []backupFile {
	if sel.isFull() {
		return entries
	}
	workerSet := make(map[int]struct{}, len(sel.workers))
	for _, w := range sel.workers {
		workerSet[w] = struct{}{}
	}
	out := make([]backupFile, 0, len(entries))
	for _, f := range entries {
		// Check both the local path and the object key so filters
		// work regardless of whether a file was backed up under
		// files/ (inside configDir) or absolute/ (outside it).
		candidates := []string{f.LocalPath, f.ObjectKey}

		match := false

		if sel.configOnly {
			isConfig := true
			for _, c := range candidates {
				if isStorePath(c) || workerIndexFor(c) >= 0 {
					isConfig = false
					break
				}
			}
			if isConfig {
				match = true
			}
		}
		if !match && sel.master {
			for _, c := range candidates {
				if isStorePath(c) {
					match = true
					break
				}
			}
		}
		if !match && (sel.workerAll || len(workerSet) > 0) {
			for _, c := range candidates {
				idx := workerIndexFor(c)
				if idx < 0 {
					continue
				}
				if sel.workerAll {
					match = true
					break
				}
				if _, ok := workerSet[idx]; ok {
					match = true
					break
				}
			}
		}
		if !match && len(sel.pathSubs) > 0 {
			for _, sub := range sel.pathSubs {
				if sub == "" {
					continue
				}
				if strings.Contains(f.LocalPath, sub) || strings.Contains(f.ObjectKey, sub) {
					match = true
					break
				}
			}
		}

		if match {
			out = append(out, f)
		}
	}
	return out
}

// resolvedFile pairs a manifest entry with its computed destination on
// the local filesystem (which may differ from bf.LocalPath after
// cross-host path remapping).
type resolvedFile struct {
	bf     backupFile
	dest   string
	mapped bool
}

func runRestore(b *utils.NodeBackupConfig, name string, sel restoreSelector, userPathMaps []string, force, dryRun bool) error {
	client, err := newS3Client(b)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}
	ctx := context.Background()

	bucketPrefix := normalizeBucketPrefix(b.BucketPrefix)
	prefix := strings.TrimSuffix(name, "/")
	mfKey := joinKey(bucketPrefix, prefix, manifestObjectKey)
	mf, err := downloadManifest(ctx, client, b.Bucket, mfKey)
	if err != nil {
		return fmt.Errorf("download manifest %s: %w", mfKey, err)
	}

	pm, dstConfigDir, err := buildPathMap(mf, userPathMaps)
	if err != nil {
		return fmt.Errorf("build path map: %w", err)
	}

	files := selectFiles(mf.Files, sel)
	fmt.Printf("Restoring backup %q (%d of %d files selected) created at %s\n",
		mf.ConfigName, len(files), len(mf.Files),
		mf.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	if note := crossOSNote(mf); note != "" {
		fmt.Println(note)
	}
	if len(files) == 0 {
		return fmt.Errorf("no files matched the selected filters (use --dry-run without filters to see what the backup contains)")
	}

	resolved := make([]resolvedFile, 0, len(files))
	var unmappedAbs []string
	for _, f := range files {
		dest, mapped := destPathFor(mf, &f, pm, dstConfigDir)
		resolved = append(resolved, resolvedFile{bf: f, dest: dest, mapped: mapped})
		if !mapped && strings.Contains(f.ObjectKey, "/absolute/") &&
			mf.HostOS != "" && mf.HostOS != runtime.GOOS {
			unmappedAbs = append(unmappedAbs, f.LocalPath)
		}
	}

	if len(unmappedAbs) > 0 {
		fmt.Fprintf(os.Stderr,
			"Warning: %d absolute-path file(s) from a %s backup could not be remapped to %s equivalents and will be written verbatim. Pass --path-map OLD=NEW to redirect them. Examples:\n",
			len(unmappedAbs), mf.HostOS, runtime.GOOS)
		shown := unmappedAbs
		if len(shown) > 5 {
			shown = shown[:5]
		}
		for _, p := range shown {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		if len(unmappedAbs) > len(shown) {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(unmappedAbs)-len(shown))
		}
	}

	if dryRun {
		for _, r := range resolved {
			marker := ""
			if r.bf.LocalPath != r.dest {
				marker = "  (remapped)"
			}
			fmt.Printf("  would download %s -> %s (%d bytes)%s\n",
				r.bf.ObjectKey, r.dest, r.bf.Size, marker)
		}
		// In dry-run, preview config rewrites too (without touching
		// disk) by showing what would change after a real restore.
		return nil
	}

	if err := downloadFiles(ctx, client, b.Bucket, resolved, force); err != nil {
		return err
	}

	// Post-restore: if we actually wrote a config.yml for this
	// backup, rewrite its embedded absolute paths to match the
	// destination host. Skipped silently when config.yml wasn't
	// restored in this invocation (e.g. --master only).
	if configRestored(resolved, dstConfigDir) {
		changed, rerr := rewriteRestoredConfig(dstConfigDir, pm)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not rewrite embedded paths in %s/config.yml: %v\n", dstConfigDir, rerr)
		} else if len(changed) > 0 {
			fmt.Printf("Rewrote %d embedded path(s) in %s/config.yml: %s\n",
				len(changed), dstConfigDir, strings.Join(changed, ", "))
		}
	}

	return nil
}

// configRestored reports whether the set of resolved files included
// config.yml for the destination config dir.
func configRestored(files []resolvedFile, dstConfigDir string) bool {
	target := filepath.Join(dstConfigDir, "config.yml")
	for _, r := range files {
		if r.dest == target {
			return true
		}
	}
	return false
}

func downloadManifest(ctx context.Context, client *s3.Client, bucket, key string) (*manifest, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, err
	}
	mf := &manifest{}
	if err := json.Unmarshal(data, mf); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return mf, nil
}

func downloadFiles(ctx context.Context, client *s3.Client, bucket string, entries []resolvedFile, force bool) error {
	type result struct {
		idx int
		err error
		msg string
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
			msg, err := downloadOne(ctx, client, bucket, &entries[i], force)
			results <- result{idx: i, err: err, msg: msg}
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
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s: %v\n", done, len(entries), entries[r.idx].dest, r.err)
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		fmt.Printf("  [%d/%d] %s %s\n", done, len(entries), r.msg, entries[r.idx].dest)
	}
	return firstErr
}

func downloadOne(ctx context.Context, client *s3.Client, bucket string, rf *resolvedFile, force bool) (string, error) {
	bf := &rf.bf
	dest := rf.dest
	if fi, err := os.Stat(dest); err == nil && fi.Size() == bf.Size && !force {
		return "skipped", nil
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(bf.ObjectKey),
	})
	if err != nil {
		return "", err
	}
	defer out.Body.Close()

	tmp := dest + ".qclient-restore.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, out.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return "restored", nil
}
