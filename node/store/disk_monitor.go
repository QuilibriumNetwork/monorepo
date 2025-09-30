package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

// DiskMonitor watches a partition for disk usage and alerts based on configured
// thresholds
//
// Usage:
//
// errCh := make(chan error, 1)
// // Create monitor with DB config and logger
// monitor := store.NewDiskMonitor(dbPath, dbConfig, logger, errCh)
//
// // Optionally customize check interval
// monitor = monitor.WithCheckInterval(30 * time.Second)
//
// // Start monitoring with context
// ctx, cancel := context.WithCancel(context.Background())
// defer cancel()
// monitor.Start(ctx)
//
// // Handle termination signals
//
//	go func() {
//			select {
//			case err := <-errCh:
//					log.Error("Disk monitor triggered shutdown", zap.Error(err))
//					cancel() // Cancel the context to stop monitor
//					// Initiate graceful shutdown
//			}
//	}()
const diskMonitorNamespace = "disk_monitor"

var (
	// Disk usage percentage metric
	diskUsagePercentage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: diskMonitorNamespace,
			Name:      "usage_percentage",
			Help:      "Current disk usage percentage for the monitored path",
		},
		[]string{"core_id", "path"},
	)

	// Disk space metrics in bytes
	diskTotalSpace = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: diskMonitorNamespace,
			Name:      "total_bytes",
			Help:      "Total disk space in bytes for the monitored path",
		},
		[]string{"core_id", "path"},
	)

	diskUsedSpace = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: diskMonitorNamespace,
			Name:      "used_bytes",
			Help:      "Used disk space in bytes for the monitored path",
		},
		[]string{"core_id", "path"},
	)

	diskFreeSpace = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: diskMonitorNamespace,
			Name:      "free_bytes",
			Help:      "Free disk space in bytes for the monitored path",
		},
		[]string{"core_id", "path"},
	)
)

func init() {
	// Register the metrics with Prometheus
	prometheus.MustRegister(diskUsagePercentage)
	prometheus.MustRegister(diskTotalSpace)
	prometheus.MustRegister(diskUsedSpace)
	prometheus.MustRegister(diskFreeSpace)
}

type DiskMonitor struct {
	path                string
	coreId              uint
	noticePercentage    int
	warnPercentage      int
	terminatePercentage int
	log                 *zap.Logger
	errCh               chan error
	checkInterval       time.Duration
}

// NewDiskMonitor creates a new disk monitor for the given path using thresholds
// from config
func NewDiskMonitor(
	coreId uint,
	cfg config.DBConfig,
	log *zap.Logger,
	errCh chan error,
) *DiskMonitor {
	var path string
	if coreId == 0 {
		path = cfg.Path
	} else {
		if len(cfg.WorkerPaths) != 0 {
			path = cfg.WorkerPaths[coreId-1]
		} else {
			path = fmt.Sprintf(cfg.WorkerPathPrefix, coreId)
		}
	}

	return &DiskMonitor{
		path:                path,
		coreId:              coreId,
		noticePercentage:    cfg.NoticePercentage,
		warnPercentage:      cfg.WarnPercentage,
		terminatePercentage: cfg.TerminatePercentage,
		log:                 log,
		errCh:               errCh,
		checkInterval:       time.Minute,
	}
}

// WithCheckInterval sets a custom interval for checking disk usage
func (d *DiskMonitor) WithCheckInterval(interval time.Duration) *DiskMonitor {
	d.checkInterval = interval
	return d
}

// getDiskStats calculates disk usage statistics for the partition containing path
// Returns usage percentage, total space, used space, free space, and error
func (d *DiskMonitor) getDiskStats() (int, uint64, uint64, uint64, error) {
	absPath, err := filepath.Abs(d.path)
	if err != nil {
		return 0, 0, 0, 0, errors.Wrap(err, "get disk stats")
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return 0, 0, 0, 0, errors.Wrap(
			fmt.Errorf("path does not exist: %s", absPath),
			"get disk stats",
		)
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(absPath, &stat); err != nil {
		return 0, 0, 0, 0, errors.Wrap(
			fmt.Errorf("failed to get disk stats: %w", err),
			"get disk stats",
		)
	}

	totalSpace := stat.Blocks * uint64(stat.Bsize)
	freeSpace := stat.Bfree * uint64(stat.Bsize)
	usedSpace := totalSpace - freeSpace

	// Avoid division by zero
	var usagePercentage int
	if totalSpace > 0 {
		usagePercentage = int((usedSpace * 100) / totalSpace)
	}

	return usagePercentage, totalSpace, usedSpace, freeSpace, nil
}

// Start begins monitoring disk usage in a separate goroutine
func (d *DiskMonitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(d.checkInterval)
		defer ticker.Stop()

		d.checkDiskUsage()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.checkDiskUsage()
			}
		}
	}()
}

func (d *DiskMonitor) checkDiskUsage() {
	usagePercentage, totalSpace, usedSpace, freeSpace, err := d.getDiskStats()
	if err != nil {
		d.log.Error(
			"Failed to check disk usage",
			zap.Error(err),
			zap.String("path", d.path),
		)
		return
	}

	// Update Prometheus metrics
	coreIdStr := strconv.FormatUint(uint64(d.coreId), 10)
	diskUsagePercentage.WithLabelValues(coreIdStr, d.path).Set(
		float64(usagePercentage),
	)
	diskTotalSpace.WithLabelValues(coreIdStr, d.path).Set(float64(totalSpace))
	diskUsedSpace.WithLabelValues(coreIdStr, d.path).Set(float64(usedSpace))
	diskFreeSpace.WithLabelValues(coreIdStr, d.path).Set(float64(freeSpace))

	// Handle the different threshold levels
	switch {
	case usagePercentage >= d.terminatePercentage:
		d.log.Error(
			"disk usage critical",
			zap.String("path", d.path),
			zap.Int("usage_percentage", usagePercentage),
			zap.Int("threshold", d.terminatePercentage),
			zap.Uint64("free_bytes", freeSpace),
			zap.Uint64("total_bytes", totalSpace),
		)

		if d.errCh != nil {
			d.errCh <- errors.Wrap(
				fmt.Errorf(
					"disk usage for %s reached critical threshold: %d%%",
					d.path,
					usagePercentage,
				),
				"check disk usage",
			)
		}
	case usagePercentage >= d.warnPercentage:
		d.log.Warn(
			"disk usage high",
			zap.String("path", d.path),
			zap.Int("usage_percentage", usagePercentage),
			zap.Int("threshold", d.warnPercentage),
			zap.Uint64("free_bytes", freeSpace),
			zap.Uint64("total_bytes", totalSpace),
		)
	case usagePercentage >= d.noticePercentage:
		d.log.Info(
			"disk usage notice",
			zap.String("path", d.path),
			zap.Int("usage_percentage", usagePercentage),
			zap.Int("threshold", d.noticePercentage),
			zap.Uint64("free_bytes", freeSpace),
			zap.Uint64("total_bytes", totalSpace),
		)
	}
}
