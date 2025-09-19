package store

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

// InboxStore defines the interface for a CRDT-based inbox repository.
// Messages are stored as a grow-only set with age-based truncation.
// Hub associations are stored as a 2P-Set that never gets truncated.
type InboxStore interface {
	// AddMessage adds a message to the grow-only message set
	AddMessage(msg *protobufs.InboxMessage) error

	// GetMessagesByFilter returns all messages for a filter
	GetMessagesByFilter(filter [3]byte) ([]*protobufs.InboxMessage, error)

	// GetMessagesByAddress returns all messages for a specific address within a
	// filter
	GetMessagesByAddress(filter [3]byte, address []byte) (
		[]*protobufs.InboxMessage,
		error,
	)

	// GetMessagesByTimeRange returns messages within a timestamp range
	GetMessagesByTimeRange(
		filter [3]byte,
		address []byte,
		fromTimestamp, toTimestamp uint64,
	) ([]*protobufs.InboxMessage, error)

	// ReapMessages removes messages older than the specified timestamp (age-based
	// truncation)
	ReapMessages(filter [3]byte, cutoffTimestamp uint64) error

	// AddHubInboxAssociation adds an association to the 2P-Set (never deleted)
	AddHubInboxAssociation(add *protobufs.HubAddInboxMessage) error

	// DeleteHubInboxAssociation marks an association as deleted in the 2P-Set
	DeleteHubInboxAssociation(delete *protobufs.HubDeleteInboxMessage) error

	// GetHubAssociations returns the current effective associations for a hub
	// (adds minus deletes in the 2P-Set)
	GetHubAssociations(filter [3]byte, hubAddress []byte) (
		*protobufs.HubResponse,
		error,
	)

	// GetAllHubAssociations returns all hub associations for the given filters
	GetAllHubAssociations(filters [][3]byte) ([]*protobufs.HubResponse, error)

	// GetHubAddHistory returns all add operations for CRDT synchronization
	GetHubAddHistory(filter [3]byte, hubAddress []byte) (
		[]*protobufs.HubAddInboxMessage,
		error,
	)

	// GetHubDeleteHistory returns all delete operations for CRDT synchronization
	GetHubDeleteHistory(filter [3]byte, hubAddress []byte) (
		[]*protobufs.HubDeleteInboxMessage,
		error,
	)

	// GetAllMessagesCRDT returns all messages for CRDT synchronization
	GetAllMessagesCRDT(filters [][3]byte) ([]*protobufs.InboxMessage, error)

	// GetAllHubsCRDT returns all hub CRDT data for synchronization
	GetAllHubsCRDT(filters [][3]byte) ([]*protobufs.HubResponse, error)
}
