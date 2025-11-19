package worker

import (
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (w *WorkerManager) startPartitionReconciler() {
	if w.reconcilerInterval == 0 {
		w.reconcilerInterval = 30 * time.Second
	}

	if w.reconcilerStatPath == "" {
		w.reconcilerStatPath = "."
	}

	go func() {
		ticker := time.NewTicker(w.reconcilerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-w.ctx.Done():
				return
			case <-ticker.C:
				if err := reconcilePartitionAndPersist(w); err != nil {
					w.logger.Error("partition reconcile failed", zap.Error(err))
				}
			}
		}
	}()
}

func reconcilePartitionAndPersist(w *WorkerManager) error {
	total, avail, err := getPartitionUsage(w.reconcilerStatPath)
	if err != nil {
		return errors.Wrap(err, "get partition usage")
	}

	buffer := w.reconcilerBufferBytes
	if buffer == 0 && w.reconcilerBufferPercent > 0 {
		buffer = uint64(float64(total) * w.reconcilerBufferPercent)
	}

	if total == 0 {
		return errors.New("partition total size is zero")
	}

	usable := uint64(0)
	if avail > buffer {
		usable = avail - buffer
	} else {
		usable = 0
	}

	workers, err := w.store.RangeWorkers()
	if err != nil {
		return errors.Wrap(err, "range workers")
	}
	if len(workers) == 0 {
		return nil
	}

	perWorker := uint64(0)
	if len(workers) > 0 {
		perWorker = usable / uint64(len(workers))
	}

	txn, err := w.store.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "new transaction for reconcile")
	}

	var aggAvailable uint64
	for _, worker := range workers {
		if worker == nil {
			continue
		}
		if perWorker == 0 || worker.TotalStorage == 0 {
			worker.AvailableStorage = 0
		} else {
			if perWorker > uint64(worker.TotalStorage) {
				worker.AvailableStorage = worker.TotalStorage
			} else {
				worker.AvailableStorage = uint(perWorker)
			}
		}

		if err := w.store.PutWorker(txn, worker); err != nil {
			txn.Abort()
			return errors.Wrap(err, "put worker during reconcile")
		}

		aggAvailable += uint64(worker.AvailableStorage)
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		return errors.Wrap(err, "commit reconcile txn")
	}

	availableStorageGauge.Set(float64(aggAvailable))
	return nil
}

func getPartitionUsage(path string) (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, errors.Wrapf(err, "statfs %s", path)
	}

	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	avail := uint64(stat.Bavail) * uint64(stat.Bsize)
	return total, avail, nil
}
