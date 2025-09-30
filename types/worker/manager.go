package worker

import (
	"context"

	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type WorkerManager interface {
	Start(ctx context.Context) error
	Stop() error
	AllocateWorker(coreId uint, filter []byte) error
	DeallocateWorker(coreId uint) error
	GetWorkerIdByFilter(filter []byte) (uint, error)
	GetFilterByWorkerId(coreId uint) ([]byte, error)
	RegisterWorker(info *store.WorkerInfo) error
	ProposeAllocation(coreId uint, filter []byte) error
	RangeWorkers() ([]*store.WorkerInfo, error)
}
