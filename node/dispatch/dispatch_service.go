package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	qkeys "source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/dispatch"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// Compile-time check that DispatchService implements the interface
var _ dispatch.DispatchService = (*DispatchService)(nil)
var _ protobufs.DispatchServiceServer = (*DispatchService)(nil)

const (
	// Default reap interval - how often to clean up old messages
	defaultReapInterval = 1 * time.Hour
	// Default message retention period - messages older than this will be reaped
	defaultRetentionPeriod = 7 * 24 * time.Hour
)

// Domain constants for signature verification
const (
	domainAdd    = "add"
	domainDelete = "delete"
)

// DispatchService handles P2P dispatch messages and CRDT-based synchronization
type DispatchService struct {
	protobufs.DispatchServiceServer

	store      store.InboxStore
	logger     *zap.Logger
	keyManager keys.KeyManager
	pubSub     p2p.PubSub
	mu         sync.RWMutex

	// Filters this node is responsible for
	responsibleFilters map[[3]byte]bool

	// Node's identity keys
	identityPrivateKey  []byte
	signedPrePrivateKey []byte
	identityPublicKey   []byte
	signedPrePublicKey  []byte

	// Background process control
	stopCh          chan struct{}
	stopOnce        sync.Once
	reapInterval    time.Duration
	retentionPeriod time.Duration
}

// NewDispatchService creates a new dispatch service instance
func NewDispatchService(
	store store.InboxStore,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
) *DispatchService {
	// Ensure keys are in place to run dispatch
	_, err := keyManager.GetAgreementKey("q-device-key")
	if err != nil {
		if !errors.Is(err, qkeys.KeyNotFoundErr) {
			panic(err)
		}

		_, err := keyManager.CreateAgreementKey(
			"q-device-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			panic(err)
		}
	}

	_, err = keyManager.GetAgreementKey("q-device-pre-key")
	if err != nil {
		if !errors.Is(err, qkeys.KeyNotFoundErr) {
			panic(err)
		}

		_, err := keyManager.CreateAgreementKey(
			"q-device-pre-key",
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			panic(err)
		}
	}

	identityKey, err := keyManager.GetRawKey("q-device-key")
	if err != nil {
		panic(err)
	}

	signedPreKey, err := keyManager.GetRawKey("q-device-pre-key")
	if err != nil {
		panic(err)
	}

	return &DispatchService{
		store:               store,
		logger:              logger,
		keyManager:          keyManager,
		pubSub:              pubSub,
		responsibleFilters:  make(map[[3]byte]bool),
		identityPrivateKey:  identityKey.PrivateKey,
		signedPrePrivateKey: signedPreKey.PrivateKey,
		identityPublicKey:   identityKey.PublicKey,
		signedPrePublicKey:  signedPreKey.PublicKey,
		stopCh:              make(chan struct{}),
		reapInterval:        defaultReapInterval,
		retentionPeriod:     defaultRetentionPeriod,
	}
}

// SetResponsibleFilters updates the filters this node is responsible for
func (d *DispatchService) SetResponsibleFilters(filters [][3]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.responsibleFilters = make(map[[3]byte]bool)
	for _, filter := range filters {
		d.responsibleFilters[filter] = true
	}
}

// IsResponsibleForFilter checks if this node handles the given filter
func (d *DispatchService) IsResponsibleForFilter(filter [3]byte) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.responsibleFilters[filter]
}

// AddInboxMessage adds a new message to an inbox (grow-only set)
func (d *DispatchService) AddInboxMessage(
	ctx context.Context,
	msg *protobufs.InboxMessage,
) error {
	if msg == nil {
		return errors.New("message is nil")
	}

	filter := up2p.GetBloomFilterIndices(msg.Address, 256, 3)

	// Check if we're responsible for this filter
	if !d.IsResponsibleForFilter([3]byte(filter)) {
		return errors.New("not responsible for filter")
	}

	return d.store.AddMessage(msg)
}

// getInboxMessages retrieves messages based on filter criteria
func (d *DispatchService) getInboxMessages(
	ctx context.Context,
	req *protobufs.InboxMessageRequest,
) (*protobufs.InboxMessageResponse, error) {
	if len(req.Filter) != 3 {
		return nil, errors.New("invalid filter length")
	}

	var filter [3]byte
	copy(filter[:], req.Filter)

	// Check if we're responsible for this filter
	if !d.IsResponsibleForFilter(filter) {
		return nil, errors.New("not responsible for filter")
	}

	var messages []*protobufs.InboxMessage
	var err error

	// Handle different request types
	if len(req.Address) > 0 && (req.FromTimestamp > 0 || req.ToTimestamp > 0) {
		// Time range query
		messages, err = d.store.GetMessagesByTimeRange(
			filter,
			req.Address,
			req.FromTimestamp,
			req.ToTimestamp,
		)
	} else if len(req.Address) > 0 {
		// Address-specific query
		messages, err = d.store.GetMessagesByAddress(filter, req.Address)
	} else {
		// All messages for filter
		messages, err = d.store.GetMessagesByFilter(filter)
	}

	if err != nil {
		return nil, errors.Wrap(err, "get messages")
	}

	// Filter by message ID if specified
	if len(req.MessageId) > 0 {
		var filtered []*protobufs.InboxMessage
		for _, msg := range messages {
			msgHash := sha256.Sum256(msg.Message)
			if bytes.Equal(msgHash[:], req.MessageId) {
				filtered = append(filtered, msg)
				break
			}
		}
		messages = filtered
	}

	return &protobufs.InboxMessageResponse{
		Messages: messages,
	}, nil
}

// AddHubInboxAssociation adds a hub-inbox association (2P-Set add operation)
func (d *DispatchService) AddHubInboxAssociation(
	ctx context.Context,
	msg *protobufs.HubAddInboxMessage,
) error {
	if msg == nil {
		return errors.New("add message is nil")
	}

	filter := up2p.GetBloomFilterIndices(msg.Address, 256, 3)

	// Check if we're responsible for this filter
	if !d.IsResponsibleForFilter([3]byte(filter)) {
		return errors.New("not responsible for filter")
	}

	// Verify signatures according to protobuf comments
	if err := d.verifyHubAddSignatures(msg); err != nil {
		return errors.Wrap(err, "signature verification failed")
	}

	return d.store.AddHubInboxAssociation(msg)
}

// DeleteHubInboxAssociation removes a hub-inbox association (2P-Set delete
// operation)
func (d *DispatchService) DeleteHubInboxAssociation(
	ctx context.Context,
	msg *protobufs.HubDeleteInboxMessage,
) error {
	if msg == nil {
		return errors.New("delete message is nil")
	}

	filter := up2p.GetBloomFilterIndices(msg.Address, 256, 3)

	// Check if we're responsible for this filter
	if !d.IsResponsibleForFilter([3]byte(filter)) {
		return errors.New("not responsible for filter")
	}

	// Verify signatures according to protobuf comments
	if err := d.verifyHubDeleteSignatures(msg); err != nil {
		return errors.Wrap(err, "signature verification failed")
	}

	return d.store.DeleteHubInboxAssociation(msg)
}

// getHub retrieves hub information including current associations
func (d *DispatchService) getHub(
	ctx context.Context,
	req *protobufs.HubRequest,
) (*protobufs.HubResponse, error) {
	if len(req.Filter) != 3 {
		return nil, errors.New("invalid filter length")
	}

	var filter [3]byte
	copy(filter[:], req.Filter)

	// Check if we're responsible for this filter
	if !d.IsResponsibleForFilter(filter) {
		return nil, errors.New("not responsible for filter")
	}

	return d.store.GetHubAssociations(filter, req.HubAddress)
}

// syncDispatch handles synchronization requests from peers
func (d *DispatchService) syncDispatch(
	ctx context.Context,
	req *protobufs.DispatchSyncRequest,
) (*protobufs.DispatchSyncResponse, error) {
	var responsibleFilters [][3]byte

	// Filter to only the filters we're responsible for
	for _, filterBytes := range req.Filters {
		if len(filterBytes) != 3 {
			continue
		}

		var filter [3]byte
		copy(filter[:], filterBytes)

		if d.IsResponsibleForFilter(filter) {
			responsibleFilters = append(responsibleFilters, filter)
		}
	}

	if len(responsibleFilters) == 0 {
		return &protobufs.DispatchSyncResponse{}, nil
	}

	// Get messages and hubs for synchronization
	messages, err := d.store.GetAllMessagesCRDT(responsibleFilters)
	if err != nil {
		return nil, errors.Wrap(err, "get messages for sync")
	}

	hubs, err := d.store.GetAllHubsCRDT(responsibleFilters)
	if err != nil {
		return nil, errors.Wrap(err, "get hubs for sync")
	}

	return &protobufs.DispatchSyncResponse{
		Messages: messages,
		Hubs:     hubs,
	}, nil
}

// PutInboxMessage implements the gRPC service method
func (d *DispatchService) PutInboxMessage(
	ctx context.Context,
	req *protobufs.InboxMessagePut,
) (*emptypb.Empty, error) {
	if err := d.AddInboxMessage(ctx, req.Message); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// GetInboxMessages implements the gRPC service method
func (d *DispatchService) GetInboxMessages(
	ctx context.Context,
	req *protobufs.InboxMessageRequest,
) (*protobufs.InboxMessageResponse, error) {
	return d.getInboxMessages(ctx, req)
}

// PutHub implements the gRPC service method
func (d *DispatchService) PutHub(
	ctx context.Context,
	req *protobufs.HubPut,
) (*emptypb.Empty, error) {
	if req.Add != nil {
		if err := d.AddHubInboxAssociation(ctx, req.Add); err != nil {
			return nil, err
		}
	}

	if req.Delete != nil {
		if err := d.DeleteHubInboxAssociation(ctx, req.Delete); err != nil {
			return nil, err
		}
	}

	return &emptypb.Empty{}, nil
}

// GetHub implements the gRPC service method
func (d *DispatchService) GetHub(
	ctx context.Context,
	req *protobufs.HubRequest,
) (*protobufs.HubResponse, error) {
	return d.getHub(ctx, req)
}

// Sync implements the gRPC service method
func (d *DispatchService) Sync(
	ctx context.Context,
	req *protobufs.DispatchSyncRequest,
) (*protobufs.DispatchSyncResponse, error) {
	return d.syncDispatch(ctx, req)
}

// Signature verification functions

// verifyHubAddSignatures verifies ed448 signatures for hub add operations
func (d *DispatchService) verifyHubAddSignatures(
	msg *protobufs.HubAddInboxMessage,
) error {
	// Construct message for hub signature: domain("add") || inbox_public_key
	hubMsg := append([]byte(domainAdd), msg.InboxPublicKey...)

	// Verify hub signature
	if !d.verifyEd448Signature(msg.HubPublicKey, hubMsg, msg.HubSignature) {
		return errors.New("invalid hub signature")
	}

	// Construct message for inbox signature: domain("add") || hub_public_key
	inboxMsg := append([]byte(domainAdd), msg.HubPublicKey...)

	// Verify inbox signature
	if !d.verifyEd448Signature(msg.InboxPublicKey, inboxMsg, msg.InboxSignature) {
		return errors.New("invalid inbox signature")
	}

	return nil
}

// verifyHubDeleteSignatures verifies ed448 signatures for hub delete operations
func (d *DispatchService) verifyHubDeleteSignatures(
	msg *protobufs.HubDeleteInboxMessage,
) error {
	// Construct message for hub signature: domain("delete") || inbox_public_key
	hubMsg := append([]byte(domainDelete), msg.InboxPublicKey...)

	// Verify hub signature
	if !d.verifyEd448Signature(msg.HubPublicKey, hubMsg, msg.HubSignature) {
		return errors.New("invalid hub signature")
	}

	// Construct message for inbox signature: domain("delete") || hub_public_key
	inboxMsg := append([]byte(domainDelete), msg.HubPublicKey...)

	// Verify inbox signature
	if !d.verifyEd448Signature(msg.InboxPublicKey, inboxMsg, msg.InboxSignature) {
		return errors.New("invalid inbox signature")
	}

	return nil
}

// verifyEd448Signature verifies an ed448 signature
func (d *DispatchService) verifyEd448Signature(
	publicKey, message, signature []byte,
) bool {
	// Ed448 public keys are 57 bytes, signatures are 114 bytes
	if len(publicKey) != 57 || len(signature) != 114 {
		return false
	}

	// Use the key manager to verify the signature
	valid, err := d.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		publicKey,
		message,
		signature,
		nil,
	)
	if err != nil {
		d.logger.Debug("signature verification failed", zap.Error(err))
		return false
	}

	return valid
}

// Start begins the background processes for the dispatch service
func (d *DispatchService) Start() {
	go d.reapLoop()
	d.logger.Info("dispatch service started")
}

// Stop gracefully shuts down the dispatch service
func (d *DispatchService) Stop() {
	d.stopOnce.Do(func() {
		// Signal stop to background processes
		close(d.stopCh)

		d.logger.Info("dispatch service stopped")
	})
}

// SetReapInterval sets the interval between reap operations for messages
func (d *DispatchService) SetReapInterval(interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reapInterval = interval
}

// SetRetentionPeriod sets how long messages are retained before being reaped
func (d *DispatchService) SetRetentionPeriod(period time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.retentionPeriod = period
}

// reapLoop runs the background process that periodically reaps old messages
func (d *DispatchService) reapLoop() {
	ticker := time.NewTicker(d.reapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.reapMessages()
		case <-d.stopCh:
			return
		}
	}
}

// reapMessages removes old messages from all responsible filters
func (d *DispatchService) reapMessages() {
	d.mu.RLock()
	filters := make([][3]byte, 0, len(d.responsibleFilters))
	for filter := range d.responsibleFilters {
		filters = append(filters, filter)
	}
	retentionPeriod := d.retentionPeriod
	d.mu.RUnlock()

	// Calculate cutoff timestamp
	cutoffTime := time.Now().Add(-retentionPeriod).UnixMilli()

	// Reap messages for each filter
	for _, filter := range filters {
		if err := d.store.ReapMessages(filter, uint64(cutoffTime)); err != nil {
			d.logger.Error(
				"failed to reap messages",
				zap.String("filter", hex.EncodeToString(filter[:])),
				zap.Error(err),
			)
		} else {
			d.logger.Debug(
				"reaped messages",
				zap.String("filter", hex.EncodeToString(filter[:])),
				zap.Int64("cutoffTimestamp", cutoffTime),
			)
		}
	}
}
