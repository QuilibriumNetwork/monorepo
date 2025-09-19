package dispatch

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// DispatchService defines the interface for handling P2P dispatch messages and
// synchronization
type DispatchService interface {
	protobufs.DispatchServiceServer

	// SetResponsibleFilters updates the filters this node is responsible for
	SetResponsibleFilters(filters [][3]byte)

	// IsResponsibleForFilter checks if this node handles the given filter
	IsResponsibleForFilter(filter [3]byte) bool

	// AddInboxMessage adds a new message to an inbox (grow-only set)
	AddInboxMessage(ctx context.Context, msg *protobufs.InboxMessage) error

	// GetInboxMessages retrieves messages based on filter criteria
	GetInboxMessages(
		ctx context.Context,
		req *protobufs.InboxMessageRequest,
	) (*protobufs.InboxMessageResponse, error)

	// AddHubInboxAssociation adds a hub-inbox association (2P-Set add operation)
	AddHubInboxAssociation(
		ctx context.Context,
		msg *protobufs.HubAddInboxMessage,
	) error

	// DeleteHubInboxAssociation removes a hub-inbox association (2P-Set delete
	// operation)
	DeleteHubInboxAssociation(
		ctx context.Context,
		msg *protobufs.HubDeleteInboxMessage,
	) error

	// GetHub retrieves hub information including current associations
	GetHub(ctx context.Context, req *protobufs.HubRequest) (
		*protobufs.HubResponse,
		error,
	)

	// PutInboxMessage inserts a message
	PutInboxMessage(
		ctx context.Context,
		req *protobufs.InboxMessagePut,
	) (*emptypb.Empty, error)

	// Sync synchronizes dispatch information
	Sync(
		ctx context.Context,
		req *protobufs.DispatchSyncRequest,
	) (*protobufs.DispatchSyncResponse, error)

	// PutHub inserts hub information
	PutHub(
		ctx context.Context,
		req *protobufs.HubPut,
	) (*emptypb.Empty, error)

	// Start begins the background processes for the dispatch service
	Start()

	// Stop gracefully shuts down the dispatch service
	Stop()

	// SetReapInterval sets the interval between reap operations for messages
	SetReapInterval(interval time.Duration)

	// SetRetentionPeriod sets how long messages are retained before being reaped
	SetRetentionPeriod(period time.Duration)
}
