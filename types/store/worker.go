package store

type WorkerInfo struct {
	CoreId                uint
	ListenMultiaddr       string
	StreamListenMultiaddr string
	Filter                []byte
	TotalStorage          uint
	AvailableStorage      uint
	Automatic             bool
	Allocated             bool
}

type WorkerStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	GetWorker(coreId uint) (*WorkerInfo, error)
	GetWorkerByFilter(filter []byte) (*WorkerInfo, error)
	PutWorker(txn Transaction, worker *WorkerInfo) error
	DeleteWorker(txn Transaction, coreId uint) error
	RangeWorkers() ([]*WorkerInfo, error)
}
