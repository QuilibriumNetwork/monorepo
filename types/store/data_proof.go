package store

type DataProofStore interface {
	NewTransaction() (Transaction, error)
}
