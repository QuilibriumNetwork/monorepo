package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sort"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

var _ store.InboxStore = (*PebbleInboxStore)(nil)

type PebbleInboxStore struct {
	db     store.KVDB
	logger *zap.Logger
}

func NewPebbleInboxStore(
	db store.KVDB,
	logger *zap.Logger,
) *PebbleInboxStore {
	return &PebbleInboxStore{
		db:     db,
		logger: logger,
	}
}

// Key construction functions for CRDT operations

// messageKey constructs key for message data in grow-only set:
// [INBOX][INBOX_MESSAGE] + filter + timestamp + address_hash + message_hash
func messageKey(msg *protobufs.InboxMessage) []byte {
	filter := up2p.GetBloomFilterIndices(msg.Address, 256, 3)
	slices.Sort(filter)
	msgHash := sha256.Sum256(msg.Message)
	addressHash := sha256.Sum256(msg.Address)

	key := []byte{INBOX, INBOX_MESSAGE}
	key = append(key, filter...)
	key = binary.BigEndian.AppendUint64(key, msg.Timestamp)
	key = append(key, addressHash[:]...)
	key = append(key, msgHash[:]...)
	return key
}

// messagesByFilterPrefix constructs prefix for ranging messages by filter
func messagesByFilterPrefix(filter []byte) []byte {
	key := []byte{INBOX, INBOX_MESSAGE}
	sorted := slices.Clone(filter)
	slices.Sort(sorted)

	key = append(key, sorted...)
	return key
}

// hubAddKey constructs key for hub add operations (2P-Set adds):
// [INBOX][INBOX_HUB_ADDS] + filter + hub_address_hash + hub_public_key +
// inbox_public_key
func hubAddKey(add *protobufs.HubAddInboxMessage) []byte {
	filter := up2p.GetBloomFilterIndices(add.Address, 256, 3)

	sorted := slices.Clone(filter)
	slices.Sort(sorted)
	key := []byte{INBOX, INBOX_HUB_ADDS}
	addressHash := sha256.Sum256(add.Address)

	key = append(key, sorted...)
	key = append(key, addressHash[:]...)
	key = append(key, add.HubPublicKey...)
	key = append(key, add.InboxPublicKey...)
	return key
}

// hubDeleteKey constructs key for hub delete operations (2P-Set deletes):
// [INBOX][INBOX_HUB_DELETES] + filter + hub_address_hash + hub_public_key +
// inbox_public_key
func hubDeleteKey(delete *protobufs.HubDeleteInboxMessage) []byte {
	filter := up2p.GetBloomFilterIndices(delete.Address, 256, 3)

	sorted := slices.Clone(filter)
	slices.Sort(sorted)
	key := []byte{INBOX, INBOX_HUB_DELETES}
	addressHash := sha256.Sum256(delete.Address)
	key = append(key, sorted...)
	key = append(key, addressHash[:]...)
	key = append(key, delete.HubPublicKey...)
	key = append(key, delete.InboxPublicKey...)
	return key
}

// hubAddsPrefix for ranging all add operations for a hub
// [INBOX][INBOX_HUB_ADDS] + filter + hub_address_hash
func hubAddsPrefix(filter []byte, hubAddress []byte) []byte {
	key := []byte{INBOX, INBOX_HUB_ADDS}

	sorted := slices.Clone(filter)
	slices.Sort(sorted)
	addrHash := sha256.Sum256(hubAddress)
	key = append(key, sorted...)
	key = append(key, addrHash[:]...)
	return key
}

// hubDeletesPrefix for ranging all delete operations for a hub
// [INBOX][INBOX_HUB_DELETES] + filter + hub_address_hash
func hubDeletesPrefix(filter []byte, hubAddress []byte) []byte {
	key := []byte{INBOX, INBOX_HUB_DELETES}

	sorted := slices.Clone(filter)
	slices.Sort(sorted)
	addrHash := sha256.Sum256(hubAddress)
	key = append(key, sorted...)
	key = append(key, addrHash[:]...)
	return key
}

// hubMaterializedKey constructs key for materialized hub state:
// [INBOX][INBOX_HUB_BY_ADDR] + filter + hub_address
func hubMaterializedKey(filter []byte, hubAddress []byte) []byte {
	key := []byte{INBOX, INBOX_HUB_BY_ADDR}

	sorted := slices.Clone(filter)
	slices.Sort(sorted)
	key = append(key, sorted...)
	key = append(key, hubAddress...)
	return key
}

// AddMessage adds a message to the grow-only message set
func (p *PebbleInboxStore) AddMessage(msg *protobufs.InboxMessage) error {
	if msg == nil {
		return errors.New("message is nil")
	}

	key := messageKey(msg)
	value, err := msg.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "serialize message")
	}

	if err := p.db.Set(key, value); err != nil {
		return errors.Wrap(err, "store message")
	}

	return nil
}

// GetMessagesByFilter returns all messages for a filter
func (p *PebbleInboxStore) GetMessagesByFilter(filter [3]byte) (
	[]*protobufs.InboxMessage,
	error,
) {
	prefix := messagesByFilterPrefix(filter[:])
	return p.scanMessages(prefix)
}

// GetMessagesByAddress returns all messages for a specific address within a
// filter
func (p *PebbleInboxStore) GetMessagesByAddress(
	filter [3]byte,
	address []byte,
) ([]*protobufs.InboxMessage, error) {
	// Get all messages for filter and filter by address
	messages, err := p.GetMessagesByFilter(filter)
	if err != nil {
		return nil, err
	}

	var filtered []*protobufs.InboxMessage
	for _, msg := range messages {
		if bytes.Equal(msg.Address, address) {
			filtered = append(filtered, msg)
		}
	}

	return filtered, nil
}

// GetMessagesByTimeRange returns messages within a timestamp range
func (p *PebbleInboxStore) GetMessagesByTimeRange(
	filter [3]byte,
	address []byte,
	fromTimestamp, toTimestamp uint64,
) ([]*protobufs.InboxMessage, error) {
	messages, err := p.GetMessagesByAddress(filter, address)
	if err != nil {
		return nil, err
	}

	var filtered []*protobufs.InboxMessage
	for _, msg := range messages {
		if msg.Timestamp >= fromTimestamp &&
			(toTimestamp == 0 || msg.Timestamp <= toTimestamp) {
			filtered = append(filtered, msg)
		}
	}

	return filtered, nil
}

// ReapMessages removes messages older than the specified timestamp (age-based
// truncation)
func (p *PebbleInboxStore) ReapMessages(
	filter [3]byte,
	cutoffTimestamp uint64,
) error {
	prefix := messagesByFilterPrefix(filter[:])
	upper := nextPrefix(prefix)
	iter, err := p.db.NewIter(prefix, upper)
	if err != nil {
		return errors.Wrap(err, "create iterator")
	}
	defer iter.Close()

	batch := p.db.NewBatch(false)
	defer batch.Abort()

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()

		// Extract timestamp from key:
		// [INBOX][INBOX_MESSAGE][filter][timestamp]...
		if len(key) < 1+1+3+8 {
			continue
		}

		timestampBytes := key[1+1+3 : 1+1+3+8]
		timestamp := binary.BigEndian.Uint64(timestampBytes)

		if timestamp < cutoffTimestamp {
			if err := batch.Delete(key); err != nil {
				return errors.Wrap(err, "delete old message")
			}
		}
	}

	return batch.Commit()
}

// AddHubInboxAssociation adds an association to the 2P-Set (never deleted)
func (p *PebbleInboxStore) AddHubInboxAssociation(
	add *protobufs.HubAddInboxMessage,
) error {
	if add == nil {
		return errors.New("add message is nil")
	}

	key := hubAddKey(add)
	value, err := add.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "serialize add message")
	}

	batch := p.db.NewBatch(false)
	defer batch.Abort()

	// Store the add operation (never deleted)
	if err := batch.Set(key, value); err != nil {
		return errors.Wrap(err, "store add operation")
	}

	// Update materialized view
	if err := p.updateMaterializedHub(batch, add.Address, add, nil); err != nil {
		return errors.Wrap(err, "update materialized view")
	}

	return batch.Commit()
}

// DeleteHubInboxAssociation marks an association as deleted in the 2P-Set
func (p *PebbleInboxStore) DeleteHubInboxAssociation(
	delete *protobufs.HubDeleteInboxMessage,
) error {
	if delete == nil {
		return errors.New("delete message is nil")
	}

	key := hubDeleteKey(delete)
	value, err := delete.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "serialize delete message")
	}

	batch := p.db.NewBatch(false)
	defer batch.Abort()

	// Store the delete operation (never deleted)
	if err := batch.Set(key, value); err != nil {
		return errors.Wrap(err, "store delete operation")
	}

	// Update materialized view
	if err := p.updateMaterializedHub(
		batch,
		delete.Address,
		nil,
		delete,
	); err != nil {
		return errors.Wrap(err, "update materialized view")
	}

	return batch.Commit()
}

// GetHubAssociations returns the current effective associations for a hub (adds
// minus deletes in the 2P-Set)
func (p *PebbleInboxStore) GetHubAssociations(
	filter [3]byte,
	hubAddress []byte,
) (*protobufs.HubResponse, error) {
	// Try materialized view first
	materializedKey := hubMaterializedKey(filter[:], hubAddress)
	if value, closer, err := p.db.Get(materializedKey); err == nil {
		defer closer.Close()

		response := &protobufs.HubResponse{}
		if err := proto.Unmarshal(value, response); err == nil {
			return response, nil
		}
	}

	// Fallback to computing from CRDT operations
	return p.computeHubAssociations(filter, hubAddress)
}

// computeHubAssociations computes current associations from CRDT operations
func (p *PebbleInboxStore) computeHubAssociations(
	filter [3]byte,
	hubAddress []byte,
) (*protobufs.HubResponse, error) {
	// Get all add operations
	adds, err := p.GetHubAddHistory(filter, hubAddress)
	if err != nil {
		return nil, err
	}

	// Get all delete operations
	deletes, err := p.GetHubDeleteHistory(filter, hubAddress)
	if err != nil {
		return nil, err
	}

	// Create a map to track effective associations
	associations := make(map[string]*protobufs.HubAddInboxMessage)
	deletions := make(map[string]bool)

	// Process all adds
	for _, add := range adds {
		key := string(add.InboxPublicKey) + string(add.HubPublicKey)
		associations[key] = add
	}

	// Process all deletes
	for _, delete := range deletes {
		key := string(delete.InboxPublicKey) + string(delete.HubPublicKey)
		deletions[key] = true
	}

	// Compute effective adds (adds that haven't been deleted)
	var effectiveAdds []*protobufs.HubAddInboxMessage
	var effectiveDeletes []*protobufs.HubDeleteInboxMessage

	for key, add := range associations {
		if deletions[key] {
			// Find the corresponding delete
			for _, delete := range deletes {
				deleteKey := string(delete.InboxPublicKey) + string(delete.HubPublicKey)
				if deleteKey == key {
					effectiveDeletes = append(effectiveDeletes, delete)
					break
				}
			}
		} else {
			effectiveAdds = append(effectiveAdds, add)
		}
	}

	return &protobufs.HubResponse{
		Adds:    effectiveAdds,
		Deletes: effectiveDeletes,
	}, nil
}

// updateMaterializedHub updates the materialized view for a hub
// IMPORTANT: This may be called while a batch has uncommitted writes. Since
// DB iterators won't see those yet, we include the pending op (if provided)
// in-memory so the materialized view reflects the state as-of this batch.
func (p *PebbleInboxStore) updateMaterializedHub(
	batch store.Transaction,
	hubAddress []byte,
	pendingAdd *protobufs.HubAddInboxMessage,
	pendingDelete *protobufs.HubDeleteInboxMessage,
) error {
	filter := up2p.GetBloomFilterIndices(hubAddress, 256, 3)
	// Build from history (committed) and then layer on the pending op.
	adds, err := p.GetHubAddHistory([3]byte(filter), hubAddress)
	if err != nil {
		return err
	}
	deletes, err := p.GetHubDeleteHistory([3]byte(filter), hubAddress)
	if err != nil {
		return err
	}

	// Apply the pending op (read-your-writes for the batch)
	if pendingAdd != nil {
		adds = append(adds, pendingAdd)
	}
	if pendingDelete != nil {
		deletes = append(deletes, pendingDelete)
	}

	// Compute effective state (adds minus deletes) deterministically
	type kd string
	keyAdd := func(a *protobufs.HubAddInboxMessage) kd {
		return kd(string(a.InboxPublicKey) + string(a.HubPublicKey))
	}
	keyDel := func(d *protobufs.HubDeleteInboxMessage) kd {
		return kd(string(d.InboxPublicKey) + string(d.HubPublicKey))
	}

	addMap := make(map[kd]*protobufs.HubAddInboxMessage, len(adds))
	delSet := make(map[kd]*protobufs.HubDeleteInboxMessage, len(deletes))

	for _, a := range adds {
		addMap[keyAdd(a)] = a
	}
	for _, d := range deletes {
		delSet[keyDel(d)] = d
	}

	var effAdds []*protobufs.HubAddInboxMessage
	var effDels []*protobufs.HubDeleteInboxMessage
	for k, a := range addMap {
		if del, ok := delSet[k]; ok {
			effDels = append(effDels, del)
		} else {
			effAdds = append(effAdds, a)
		}
	}

	response := &protobufs.HubResponse{Adds: effAdds, Deletes: effDels}

	materializedKey := hubMaterializedKey(filter, hubAddress)
	value, err := proto.Marshal(response)
	if err != nil {
		return errors.Wrap(err, "marshal hub response")
	}

	return batch.Set(materializedKey, value)
}

// GetAllHubAssociations returns all hub associations for the given filters
func (p *PebbleInboxStore) GetAllHubAssociations(filters [][3]byte) (
	[]*protobufs.HubResponse,
	error,
) {
	var allResponses []*protobufs.HubResponse

	for _, filter := range filters {
		prefix := []byte{INBOX, INBOX_HUB_BY_ADDR}
		prefix = append(prefix, filter[:]...)
		upper := nextPrefix(prefix)
		iter, err := p.db.NewIter(prefix, upper)
		if err != nil {
			return nil, errors.Wrap(err, "create materialized iterator")
		}

		for iter.First(); iter.Valid(); iter.Next() {
			value := iter.Value()
			response := &protobufs.HubResponse{}
			if err := proto.Unmarshal(value, response); err != nil {
				p.logger.Warn("failed to deserialize hub response", zap.Error(err))
				continue
			}
			allResponses = append(allResponses, response)
		}
		iter.Close()
	}

	return allResponses, nil
}

// GetHubAddHistory returns all add operations for CRDT synchronization
func (p *PebbleInboxStore) GetHubAddHistory(
	filter [3]byte,
	hubAddress []byte,
) ([]*protobufs.HubAddInboxMessage, error) {
	prefix := hubAddsPrefix(filter[:], hubAddress)
	upper := nextPrefix(prefix)
	iter, err := p.db.NewIter(prefix, upper)
	if err != nil {
		return nil, errors.Wrap(err, "create add iterator")
	}
	defer iter.Close()

	var adds []*protobufs.HubAddInboxMessage
	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		add := &protobufs.HubAddInboxMessage{}
		if err := add.FromCanonicalBytes(value); err != nil {
			return nil, errors.Wrap(err, "deserialize add message")
		}
		adds = append(adds, add)
	}

	return adds, nil
}

// GetHubDeleteHistory returns all delete operations for CRDT synchronization
func (p *PebbleInboxStore) GetHubDeleteHistory(
	filter [3]byte,
	hubAddress []byte,
) ([]*protobufs.HubDeleteInboxMessage, error) {
	prefix := hubDeletesPrefix(filter[:], hubAddress)
	upper := nextPrefix(prefix)
	iter, err := p.db.NewIter(prefix, upper)
	if err != nil {
		return nil, errors.Wrap(err, "create delete iterator")
	}
	defer iter.Close()

	var deletes []*protobufs.HubDeleteInboxMessage
	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		delete := &protobufs.HubDeleteInboxMessage{}
		if err := delete.FromCanonicalBytes(value); err != nil {
			return nil, errors.Wrap(err, "deserialize delete message")
		}
		deletes = append(deletes, delete)
	}

	return deletes, nil
}

// GetAllMessagesCRDT returns all messages for CRDT synchronization
func (p *PebbleInboxStore) GetAllMessagesCRDT(filters [][3]byte) (
	[]*protobufs.InboxMessage,
	error,
) {
	var allMessages []*protobufs.InboxMessage

	for _, filter := range filters {
		messages, err := p.GetMessagesByFilter(filter)
		if err != nil {
			return nil, err
		}
		allMessages = append(allMessages, messages...)
	}

	return allMessages, nil
}

// GetAllHubsCRDT returns all hub CRDT data for synchronization
func (p *PebbleInboxStore) GetAllHubsCRDT(filters [][3]byte) (
	[]*protobufs.HubResponse,
	error,
) {
	return p.GetAllHubAssociations(filters)
}

// scanMessages scans messages with the given prefix
func (p *PebbleInboxStore) scanMessages(prefix []byte) (
	[]*protobufs.InboxMessage,
	error,
) {
	upper := nextPrefix(prefix)
	iter, err := p.db.NewIter(prefix, upper)
	if err != nil {
		return nil, errors.Wrap(err, "create iterator")
	}
	defer iter.Close()

	var messages []*protobufs.InboxMessage
	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		msg := &protobufs.InboxMessage{}
		if err := msg.FromCanonicalBytes(value); err != nil {
			return nil, errors.Wrap(err, "deserialize message")
		}
		messages = append(messages, msg)
	}

	// Sort by timestamp
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	return messages, nil
}

// nextPrefix returns the smallest []byte that is strictly greater than
// all keys with the given prefix, suitable for use as an exclusive UpperBound.
// It treats the prefix as a big-endian integer and increments it by 1,
// truncating at the incremented byte.
//
// Example: []{0x01, 0x10, 0x00} -> []{0x01, 0x10, 0x01}
//
//	[]{0x01, 0x10, 0xFF} -> []{0x01, 0x11}
//
// Note: If every byte is 0xFF (extremely unlikely for our prefixes), we fall
// back to appending 0x00 to avoid returning nil in callers that require a
// value.
func nextPrefix(prefix []byte) []byte {
	out := append([]byte(nil), prefix...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != 0xFF {
			out[i]++
			return out[:i+1]
		}
	}
	// Overflow (all 0xFF) – practically unreachable with our prefixes. Return
	// prefix appended with 0x00 to satisfy non-nil upper-bound requirement.
	return append(out, 0x00)
}
