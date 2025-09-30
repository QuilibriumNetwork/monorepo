package provers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var _ consensus.ProverRegistry = (*ProverRegistry)(nil)

// ProverRegistry is the default implementation of ProverRegistry
type ProverRegistry struct {
	mu     sync.RWMutex
	logger *zap.Logger

	// Hypergraph instance for state queries
	hypergraph hypergraph.Hypergraph

	// Global prover trie
	globalTrie *tries.RollingFrecencyCritbitTrie

	// Per-shard prover tries, keyed by filter
	shardTries map[string]*tries.RollingFrecencyCritbitTrie

	// Prover info cache, keyed by address
	proverCache map[string]*consensus.ProverInfo

	// Filter cache, keyed by filter (as string) to sorted list of ProverInfo
	filterCache map[string][]*consensus.ProverInfo

	// Track which addresses are in which tries for efficient lookup
	addressToFilters map[string][]string

	// Current frame number
	currentFrame uint64

	// RDF reader
	rdfMultiprover *schema.RDFMultiprover
}

// NewProverRegistry creates a new prover registry with the given hypergraph
func NewProverRegistry(logger *zap.Logger, hg hypergraph.Hypergraph) (
	consensus.ProverRegistry,
	error,
) {
	logger.Debug("creating new prover registry")

	registry := &ProverRegistry{
		logger:           logger,
		hypergraph:       hg,
		globalTrie:       &tries.RollingFrecencyCritbitTrie{},
		shardTries:       make(map[string]*tries.RollingFrecencyCritbitTrie),
		proverCache:      make(map[string]*consensus.ProverInfo),
		filterCache:      make(map[string][]*consensus.ProverInfo),
		addressToFilters: make(map[string][]string),
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			hg.GetProver(),
		),
	}

	// Initialize from current hypergraph state
	logger.Debug("extracting initial global state from hypergraph")
	if err := registry.extractGlobalState(); err != nil {
		logger.Error("failed to extract global state", zap.Error(err))
		return nil, err
	}

	logger.Debug("prover registry created successfully")
	return registry, nil
}

// ProcessStateTransition implements ProverRegistry
func (r *ProverRegistry) ProcessStateTransition(
	state state.State,
	frameNumber uint64,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Debug(
		"processing state transition",
		zap.Uint64("frame_number", frameNumber),
		zap.Uint64("previous_frame", r.currentFrame),
	)

	r.currentFrame = frameNumber

	changes := state.Changeset()
	r.logger.Debug("processing changeset", zap.Int("changeCount", len(changes)))

	// Process each change
	for _, change := range changes {
		// Check if this is a change to a prover vertex under
		// GLOBAL_INTRINSIC_ADDRESS
		if len(change.Domain) == 32 && bytes.Equal(
			change.Domain,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		) {
			r.logger.Debug(
				"processing prover change",
				zap.String("address", fmt.Sprintf("%x", change.Address)),
				zap.Uint8("change_type", uint8(change.StateChange)),
			)

			if err := r.processProverChange(change, frameNumber); err != nil {
				r.logger.Debug(
					"failed to process prover change",
					zap.String("address", fmt.Sprintf("%x", change.Address)),
					zap.Error(err),
				)
				return errors.Wrap(err, "failed to process prover change")
			}
		}
		// For alt fee basis shards, your custom node will want to handle insertions
		// for alt shards here.
	}

	r.logger.Debug(
		"state transition processed successfully",
		zap.Uint64("frame_number", frameNumber),
	)
	return nil
}

// GetProverInfo implements ProverRegistry
func (r *ProverRegistry) GetProverInfo(
	address []byte,
) (*consensus.ProverInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting prover info",
		zap.String("address", fmt.Sprintf("%x", address)),
	)

	if info, exists := r.proverCache[string(address)]; exists {
		r.logger.Debug(
			"prover info found",
			zap.String("address", fmt.Sprintf("%x", address)),
			zap.String("public_key", fmt.Sprintf("%x", info.PublicKey)),
			zap.Uint8("status", uint8(info.Status)),
			zap.Int("allocation_count", len(info.Allocations)),
		)
		return info, nil
	}

	r.logger.Debug(
		"prover info not found",
		zap.String("address", fmt.Sprintf("%x", address)),
	)
	return nil, nil
}

// GetNextProver implements ProverRegistry
func (r *ProverRegistry) GetNextProver(
	input [32]byte,
	filter []byte,
) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting next prover",
		zap.String("input", fmt.Sprintf("%x", input)),
		zap.String("filter", fmt.Sprintf("%x", filter)),
	)

	var trie *tries.RollingFrecencyCritbitTrie
	if len(filter) == 0 {
		trie = r.globalTrie
		r.logger.Debug("using global trie")
	} else {
		if shardTrie, exists := r.shardTries[string(filter)]; exists {
			trie = shardTrie
			r.logger.Debug(
				"using shard trie",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
		} else {
			r.logger.Debug(
				"shard trie not found",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
			return nil, errors.Wrap(
				errors.New("shard trie not available"),
				"get next prover",
			)
		}
	}

	nearest := trie.FindNearest(input[:])
	if nearest.Key == nil {
		r.logger.Debug("no prover found in trie")
		return nil, errors.Wrap(
			errors.New("shard trie empty"),
			"get next prover",
		)
	}

	r.logger.Debug(
		"next prover found",
		zap.String("prover", fmt.Sprintf("%x", nearest.Key)),
	)
	return nearest.Key, nil
}

func (r *ProverRegistry) GetOrderedProvers(
	input [32]byte,
	filter []byte,
) ([][]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting ordered provers",
		zap.String("input", fmt.Sprintf("%x", input)),
		zap.String("filter", fmt.Sprintf("%x", filter)),
	)

	var trie *tries.RollingFrecencyCritbitTrie
	if len(filter) == 0 {
		trie = r.globalTrie
		r.logger.Debug("using global trie for ordered provers")
	} else {
		if shardTrie, exists := r.shardTries[string(filter)]; exists {
			trie = shardTrie
			r.logger.Debug(
				"using shard trie for ordered provers",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
		} else {
			r.logger.Debug(
				"shard trie not found for filter",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
			return nil, nil
		}
	}

	nearest := trie.FindNearestAndApproximateNeighbors(input[:])
	addresses := [][]byte{}
	for _, leaf := range nearest {
		addresses = append(addresses, leaf.Key)
	}

	r.logger.Debug("ordered provers retrieved", zap.Int("count", len(addresses)))
	return addresses, nil
}

// GetActiveProvers implements ProverRegistry
func (r *ProverRegistry) GetActiveProvers(
	filter []byte,
) ([]*consensus.ProverInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting active provers",
		zap.String("filter", fmt.Sprintf("%x", filter)),
	)

	result, err := r.getProversByStatusInternal(
		filter,
		consensus.ProverStatusActive,
	)
	if err != nil {
		r.logger.Debug("failed to get active provers", zap.Error(err))
		return nil, err
	}

	r.logger.Debug("active provers retrieved", zap.Int("count", len(result)))
	return result, nil
}

// GetProverCount implements ProverRegistry
func (r *ProverRegistry) GetProverCount(filter []byte) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting prover count",
		zap.String("filter", fmt.Sprintf("%x", filter)),
	)

	var trie *tries.RollingFrecencyCritbitTrie
	if len(filter) == 0 {
		trie = r.globalTrie
		r.logger.Debug("counting provers in global trie")
	} else {
		if shardTrie, exists := r.shardTries[string(filter)]; exists {
			trie = shardTrie
			r.logger.Debug(
				"counting provers in shard trie",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
		} else {
			r.logger.Debug(
				"shard trie not found, returning count 0",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
			return 0, nil
		}
	}

	count := len(trie.FindNearestAndApproximateNeighbors(make([]byte, 32)))
	r.logger.Debug("prover count retrieved", zap.Int("count", count))

	return count, nil
}

// GetProversByStatus implements ProverRegistry
func (r *ProverRegistry) GetProversByStatus(
	filter []byte,
	status consensus.ProverStatus,
) ([]*consensus.ProverInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug(
		"getting provers by status",
		zap.String("filter", fmt.Sprintf("%x", filter)),
		zap.Uint8("status", uint8(status)),
	)

	result, err := r.getProversByStatusInternal(filter, status)
	if err != nil {
		r.logger.Debug("failed to get provers by status", zap.Error(err))
		return nil, err
	}

	r.logger.Debug(
		"provers by status retrieved",
		zap.Uint8("status", uint8(status)),
		zap.Int("count", len(result)),
	)
	return result, nil
}

// UpdateProverActivity implements ProverRegistry
func (r *ProverRegistry) UpdateProverActivity(
	address []byte,
	filter []byte,
	frameNumber uint64,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Debug(
		"updating prover activity",
		zap.String("address", fmt.Sprintf("%x", address)),
		zap.Uint64("frame_number", frameNumber),
	)

	if info, exists := r.proverCache[string(address)]; exists {
		active := 0
		// Update last active frame for all active allocations
		for i := range info.Allocations {
			if info.Allocations[i].Status == consensus.ProverStatusActive {
				if bytes.Equal(
					info.Allocations[i].ConfirmationFilter,
					filter,
				) {
					info.Allocations[i].LastActiveFrameNumber = frameNumber
				}
				active++
			}
		}
		r.logger.Debug(
			"prover activity updated",
			zap.String("address", fmt.Sprintf("%x", address)),
			zap.Int("active_allocations", active),
		)
	} else {
		r.logger.Debug(
			"prover not found for activity update",
			zap.String("address", fmt.Sprintf("%x", address)),
		)
	}

	return nil
}

// Helper method to get provers by status, returns lexicographic order
func (r *ProverRegistry) getProversByStatusInternal(
	filter []byte,
	status consensus.ProverStatus,
) ([]*consensus.ProverInfo, error) {
	var result []*consensus.ProverInfo

	for _, info := range r.proverCache {
		for _, allocation := range info.Allocations {
			if allocation.Status == status && bytes.Equal(
				allocation.ConfirmationFilter,
				filter,
			) {
				result = append(result, info)
				break // Only add each prover once
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].Address, result[j].Address) == -1
	})

	return result, nil
}

// Helper method to add a prover to a trie
func (r *ProverRegistry) addProverToTrie(
	address []byte,
	publicKey []byte,
	filter []byte,
	frameNumber uint64,
) error {
	var trie *tries.RollingFrecencyCritbitTrie
	var filterStr string

	r.logger.Debug(
		"adding prover to trie",
		zap.String("address", fmt.Sprintf("%x", address)),
		zap.String("filter", fmt.Sprintf("%x", filter)),
		zap.Uint64("frame_number", frameNumber),
	)

	if len(filter) == 0 {
		trie = r.globalTrie
		filterStr = ""
		r.logger.Debug("adding to global trie")
	} else {
		filterStr = string(filter)
		if _, exists := r.shardTries[filterStr]; !exists {
			r.logger.Debug(
				"creating new shard trie",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
			r.shardTries[filterStr] = &tries.RollingFrecencyCritbitTrie{}
		}
		trie = r.shardTries[filterStr]
		r.logger.Debug(
			"adding to shard trie",
			zap.String("filter", fmt.Sprintf("%x", filter)),
		)
	}

	// Add to trie using address as key
	trie.Add(address, frameNumber)

	// Track which trie this address is in
	if filters, exists := r.addressToFilters[string(address)]; exists {
		// Check if filter is already tracked
		found := false
		for _, f := range filters {
			if f == filterStr {
				found = true
				break
			}
		}
		if !found {
			r.addressToFilters[string(address)] = append(filters, filterStr)
			r.logger.Debug(
				"added filter to address tracking",
				zap.String("address", fmt.Sprintf("%x", address)),
				zap.Int("filter_count", len(r.addressToFilters[string(address)])),
			)
		}
	} else {
		r.addressToFilters[string(address)] = []string{filterStr}
		r.logger.Debug(
			"created new address filter tracking",
			zap.String("address", fmt.Sprintf("%x", address)),
		)
	}

	return nil
}

// Helper method to remove a prover from a trie
func (r *ProverRegistry) removeProverFromTrie(
	address []byte,
	filter []byte,
) error {
	var trie *tries.RollingFrecencyCritbitTrie
	var filterStr string

	r.logger.Debug(
		"removing prover from trie",
		zap.String("address", fmt.Sprintf("%x", address)),
		zap.String("filter", fmt.Sprintf("%x", filter)),
	)

	if len(filter) == 0 {
		trie = r.globalTrie
		filterStr = ""
		r.logger.Debug("removing from global trie")
	} else {
		filterStr = string(filter)
		if shardTrie, exists := r.shardTries[filterStr]; exists {
			trie = shardTrie
			r.logger.Debug(
				"removing from shard trie",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
		} else {
			r.logger.Debug(
				"shard trie doesn't exist, nothing to remove",
				zap.String("filter", fmt.Sprintf("%x", filter)),
			)
			return nil
		}
	}

	// Remove from trie
	trie.Remove(address)

	// Update tracking
	if filters, exists := r.addressToFilters[string(address)]; exists {
		newFilters := []string{}
		for _, f := range filters {
			if f != filterStr {
				newFilters = append(newFilters, f)
			}
		}
		if len(newFilters) > 0 {
			r.addressToFilters[string(address)] = newFilters
			r.logger.Debug(
				"updated address filter tracking",
				zap.String("address", fmt.Sprintf("%x", address)),
				zap.Int("remaining_filters", len(newFilters)),
			)
		} else {
			delete(r.addressToFilters, string(address))
			r.logger.Debug(
				"removed address from filter tracking",
				zap.String("address", fmt.Sprintf("%x", address)),
			)
		}
	}

	return nil
}

// Refresh implements ProverRegistry
func (r *ProverRegistry) Refresh() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Debug("refreshing prover registry")

	// Clear existing state
	r.globalTrie = &tries.RollingFrecencyCritbitTrie{}
	r.shardTries = make(map[string]*tries.RollingFrecencyCritbitTrie)
	r.proverCache = make(map[string]*consensus.ProverInfo)
	r.filterCache = make(map[string][]*consensus.ProverInfo)
	r.addressToFilters = make(map[string][]string)

	r.logger.Debug("cleared existing registry state")

	// Re-extract from hypergraph
	if err := r.extractGlobalState(); err != nil {
		r.logger.Debug("failed to refresh registry", zap.Error(err))
		return err
	}

	r.logger.Debug("prover registry refreshed successfully")
	return nil
}

// extractGlobalState reads the current state from the hypergraph
func (r *ProverRegistry) extractGlobalState() error {
	// If no hypergraph is provided (e.g. in tests), skip extraction
	if r.hypergraph == nil {
		r.logger.Warn("no hypergraph provided to registry")
		return nil
	}

	// Use the new iterator to iterate over all vertices under
	// GLOBAL_INTRINSIC_ADDRESS
	iter := r.hypergraph.GetVertexDataIterator(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
	)
	defer iter.Close()

	proversFound := 0
	allocationsFound := 0

	// Iterate through all vertices
	for iter.First(); iter.Valid(); iter.Next() {
		// Get the vertex data
		data := iter.Value()
		if data == nil {
			// Vertex has been removed, skip it
			continue
		}

		// Get the key which is always 64 bytes (domain + data address)
		key := make([]byte, 64)
		copy(key, iter.Key())

		// Check if this is a Prover or ProverAllocation based on the schema
		typeName, err := r.rdfMultiprover.GetType(
			global.GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			data,
		)
		if err != nil {
			return errors.Wrap(err, "extract global state")
		}

		switch typeName {
		case "prover:Prover":
			// Extract the prover address (last 32 bytes of the iterator key)
			proverAddress := key[32:]

			publicKey, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"PublicKey",
				data,
			)
			if err != nil {
				continue
			}

			// This is a Prover vertex
			statusBytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"Status",
				data,
			)
			if err != nil || len(statusBytes) == 0 {
				continue
			}
			status := statusBytes[0]

			// Map internal status to our ProverStatus enum
			var mappedStatus consensus.ProverStatus
			switch status {
			case 0:
				mappedStatus = consensus.ProverStatusJoining
			case 1:
				mappedStatus = consensus.ProverStatusActive
			case 2:
				mappedStatus = consensus.ProverStatusPaused
			case 3:
				mappedStatus = consensus.ProverStatusLeaving
			case 4:
				// Skip left provers
				continue
			default:
				mappedStatus = consensus.ProverStatusUnknown
			}

			r.logger.Debug(
				"processing prover vertex",
				zap.String("address", fmt.Sprintf("%x", proverAddress)),
				zap.Uint8("status", uint8(mappedStatus)),
			)

			// Extract available storage
			var availableStorage uint64
			storageBytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"AvailableStorage",
				data,
			)
			if err == nil && len(storageBytes) >= 8 {
				availableStorage = binary.BigEndian.Uint64(storageBytes)
			}

			// Extract seniority
			var seniority uint64
			seniorityBytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"Seniority",
				data,
			)
			if err == nil && len(seniorityBytes) >= 8 {
				seniority = binary.BigEndian.Uint64(seniorityBytes)
			}

			// Extract delegate address
			delegateAddress, _ := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"DelegateAddress",
				data,
			)

			// Extract kick frame number
			var kickFrameNumber uint64
			kickFrameBytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"KickFrameNumber",
				data,
			)
			if err == nil && len(kickFrameBytes) >= 8 {
				kickFrameNumber = binary.BigEndian.Uint64(kickFrameBytes)
			}

			// Create or update ProverInfo
			proverInfo, exists := r.proverCache[string(proverAddress)]
			if !exists {
				proverInfo = &consensus.ProverInfo{
					PublicKey:        publicKey,
					Address:          proverAddress,
					Status:           mappedStatus,
					AvailableStorage: availableStorage,
					Seniority:        seniority,
					DelegateAddress:  delegateAddress,
					KickFrameNumber:  kickFrameNumber,
					Allocations:      []consensus.ProverAllocationInfo{},
				}
				r.proverCache[string(proverAddress)] = proverInfo
			} else {
				// Update existing prover info
				proverInfo.PublicKey = publicKey
				proverInfo.Status = mappedStatus
				proverInfo.AvailableStorage = availableStorage
				proverInfo.Seniority = seniority
				proverInfo.DelegateAddress = delegateAddress
				proverInfo.KickFrameNumber = kickFrameNumber

				for _, allocation := range proverInfo.Allocations {
					if allocation.Status == consensus.ProverStatusActive {
						if err := r.addProverToTrie(
							proverAddress,
							proverInfo.PublicKey,
							allocation.ConfirmationFilter,
							allocation.LastActiveFrameNumber,
						); err != nil {
							return errors.Wrap(err, "extract global state")
						}
					}

					info, ok := r.filterCache[string(allocation.ConfirmationFilter)]
					if !ok {
						r.filterCache[string(
							allocation.ConfirmationFilter,
						)] = []*consensus.ProverInfo{proverInfo}
					} else {
						index := sort.Search(len(info), func(i int) bool {
							return bytes.Compare(info[i].Address, proverAddress) >= 0
						})
						r.filterCache[string(
							allocation.ConfirmationFilter,
						)] = slices.Insert(info, index, proverInfo)
					}
				}
			}
			proversFound++
		case "allocation:ProverAllocation":
			// Try to read as ProverAllocation
			proverRef, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"Prover",
				data,
			)
			if err != nil || len(proverRef) == 0 {
				// Neither Prover nor ProverAllocation, skip
				continue
			}

			// This is a ProverAllocation vertex
			statusBytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"Status",
				data,
			)
			if err != nil || len(statusBytes) == 0 {
				continue
			}
			status := statusBytes[0]

			// Map allocation status
			var mappedStatus consensus.ProverStatus
			switch status {
			case 0:
				mappedStatus = consensus.ProverStatusJoining
			case 1:
				mappedStatus = consensus.ProverStatusActive
			case 2:
				mappedStatus = consensus.ProverStatusPaused
			case 3:
				mappedStatus = consensus.ProverStatusLeaving
			case 4:
				mappedStatus = consensus.ProverStatusRejected
			case 5:
				mappedStatus = consensus.ProverStatusKicked
			default:
				mappedStatus = consensus.ProverStatusUnknown
			}

			// Extract filters
			confirmationFilter, _ := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"ConfirmationFilter",
				data,
			)
			rejectionFilter, _ := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"RejectionFilter",
				data,
			)

			// Extract frame numbers
			var joinFrameNumber,
				leaveFrameNumber,
				pauseFrameNumber,
				resumeFrameNumber,
				kickFrameNumber,
				joinConfirmFrameNumber,
				joinRejectFrameNumber,
				leaveConfirmFrameNumber,
				leaveRejectFrameNumber,
				lastActiveFrameNumber uint64

			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"JoinFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				joinFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"LeaveFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				leaveFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"PauseFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				pauseFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"ResumeFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				resumeFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"KickFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				kickFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"JoinConfirmFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				joinConfirmFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"JoinRejectFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				joinRejectFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"LeaveConfirmFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				leaveConfirmFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"LeaveRejectFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				leaveRejectFrameNumber = binary.BigEndian.Uint64(bytes)
			}
			if bytes, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"LastActiveFrameNumber",
				data,
			); err == nil && len(bytes) >= 8 {
				lastActiveFrameNumber = binary.BigEndian.Uint64(bytes)
			}

			// Create allocation info
			allocationInfo := consensus.ProverAllocationInfo{
				Status:                  mappedStatus,
				ConfirmationFilter:      confirmationFilter,
				RejectionFilter:         rejectionFilter,
				JoinFrameNumber:         joinFrameNumber,
				LeaveFrameNumber:        leaveFrameNumber,
				PauseFrameNumber:        pauseFrameNumber,
				ResumeFrameNumber:       resumeFrameNumber,
				KickFrameNumber:         kickFrameNumber,
				JoinConfirmFrameNumber:  joinConfirmFrameNumber,
				JoinRejectFrameNumber:   joinRejectFrameNumber,
				LeaveConfirmFrameNumber: leaveConfirmFrameNumber,
				LeaveRejectFrameNumber:  leaveRejectFrameNumber,
				LastActiveFrameNumber:   lastActiveFrameNumber,
			}

			// Create or update ProverInfo
			proverInfo, exists := r.proverCache[string(proverRef)]
			if !exists {
				proverInfo = &consensus.ProverInfo{
					Address:     proverRef,
					Allocations: []consensus.ProverAllocationInfo{},
				}
				r.proverCache[string(proverRef)] = proverInfo
			}

			// Add this allocation to the prover
			r.proverCache[string(proverRef)].Allocations = append(
				r.proverCache[string(proverRef)].Allocations,
				allocationInfo,
			)
			info, ok := r.filterCache[string(allocationInfo.ConfirmationFilter)]
			if !ok {
				r.filterCache[string(
					allocationInfo.ConfirmationFilter,
				)] = []*consensus.ProverInfo{proverInfo}
			} else {
				index := sort.Search(len(info), func(i int) bool {
					return bytes.Compare(info[i].Address, proverRef) >= 0
				})
				r.filterCache[string(
					allocationInfo.ConfirmationFilter,
				)] = slices.Insert(info, index, proverInfo)
			}

			r.logger.Debug(
				"processing allocation vertex",
				zap.String("prover_ref", fmt.Sprintf("%x", proverRef)),
				zap.String("filter", fmt.Sprintf("%x", confirmationFilter)),
				zap.Uint8("status", uint8(mappedStatus)),
			)

			// If allocation is active and we can identify them, add to
			// filter-specific trie
			if mappedStatus == consensus.ProverStatusActive &&
				len(r.proverCache[string(proverRef)].PublicKey) != 0 {
				if err := r.addProverToTrie(
					proverRef,
					r.proverCache[string(proverRef)].PublicKey,
					confirmationFilter,
					lastActiveFrameNumber,
				); err != nil {
					return errors.Wrap(err, "extract global state")
				}
			}
			allocationsFound++
		default:
			r.logger.Debug("unknown vertex type", zap.String("type", typeName))
			return errors.Wrap(errors.New("invalid type"), "extract global state")
		}
	}

	r.logger.Debug(
		"global state extraction completed",
		zap.Int("provers_found", proversFound),
		zap.Int("allocations_found", allocationsFound),
		zap.Int("cached_provers", len(r.proverCache)),
		zap.Int("shard_tries", len(r.shardTries)),
	)

	return nil
}

// ExtractProversFromTransactions processes a list of transactions to discover
// prover addresses. This can be called during initial sync to discover active
// provers from recent transactions.
func (r *ProverRegistry) ExtractProversFromTransactions(
	transactions []state.StateChange,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Track unique addresses we've seen
	seenAddresses := make(map[string]bool)

	for _, tx := range transactions {
		// Check if this is a prover-related transaction under
		// GLOBAL_INTRINSIC_ADDRESS
		if len(tx.Domain) == 32 && bytes.Equal(
			tx.Domain,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		) {
			typeName, err := r.rdfMultiprover.GetType(
				global.GLOBAL_RDF_SCHEMA,
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				tx.Value.DataValue(),
			)
			if err != nil {
				r.logger.Debug(
					"failed to get type name",
					zap.String("address", fmt.Sprintf("%x", tx.Address)),
					zap.Error(err),
				)
			}
			if typeName == "prover:Prover" {
				if !seenAddresses[string(tx.Address)] {
					seenAddresses[string(tx.Address)] = true
					r.logger.Debug(
						"extracting prover from transaction",
						zap.String("address", fmt.Sprintf("%x", tx.Address)),
					)
					// Extract this prover's information
					if err := r.extractProverFromAddress(tx.Address); err != nil {
						// Log error but continue with other provers
						r.logger.Debug(
							"failed to extract prover from address",
							zap.String("address", fmt.Sprintf("%x", tx.Address)),
							zap.Error(err),
						)
						continue
					}
				}
			}
		}
		// For alt-provers, you'd want to cover insertions for your alt basis shard
		// here.
	}

	r.logger.Debug(
		"extracted provers from transactions",
		zap.Int("unique_provers_found", len(seenAddresses)),
	)

	return nil
}

// processProverChange processes a single state change for a prover
func (r *ProverRegistry) processProverChange(
	change state.StateChange,
	frameNumber uint64,
) error {
	// Extract the prover address from the change address
	proverAddress := change.Address

	switch change.StateChange {
	case state.CreateStateChangeEvent, state.UpdateStateChangeEvent:
		// A prover was created or updated
		if change.Value != nil && change.Value.DataValue() != nil {
			data := change.Value.DataValue()

			// Check if this is a Prover or ProverAllocation
			publicKey, err := r.rdfMultiprover.Get(
				global.GLOBAL_RDF_SCHEMA,
				"prover:Prover",
				"PublicKey",
				data,
			)

			if err == nil && len(publicKey) > 0 {
				// This is a Prover vertex
				statusBytes, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"prover:Prover",
					"Status",
					data,
				)
				if err != nil || len(statusBytes) == 0 {
					return nil // Skip if no status
				}
				status := statusBytes[0]

				// Map internal status to our ProverStatus enum
				var mappedStatus consensus.ProverStatus
				switch status {
				case 0:
					mappedStatus = consensus.ProverStatusJoining
				case 1:
					mappedStatus = consensus.ProverStatusActive
				case 2:
					mappedStatus = consensus.ProverStatusPaused
				case 3:
					mappedStatus = consensus.ProverStatusLeaving
				case 4:
					// Left status - remove from registry
					return r.removeProver(proverAddress)
				default:
					mappedStatus = consensus.ProverStatusUnknown
				}

				// Extract available storage
				var availableStorage uint64
				storageBytes, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"prover:Prover",
					"AvailableStorage",
					data,
				)
				if err == nil && len(storageBytes) >= 8 {
					availableStorage = binary.BigEndian.Uint64(storageBytes)
				}

				// Extract seniority
				var seniority uint64
				seniorityBytes, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"prover:Prover",
					"Seniority",
					data,
				)
				if err == nil && len(seniorityBytes) >= 8 {
					seniority = binary.BigEndian.Uint64(seniorityBytes)
				}

				// Extract delegate address
				delegateAddress, _ := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"prover:Prover",
					"DelegateAddress",
					data,
				)

				// Extract kick frame number
				var kickFrameNumber uint64
				kickFrameBytes, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"prover:Prover",
					"KickFrameNumber",
					data,
				)
				if err == nil && len(kickFrameBytes) >= 8 {
					kickFrameNumber = binary.BigEndian.Uint64(kickFrameBytes)
				}

				// Create or update ProverInfo
				proverInfo, exists := r.proverCache[string(proverAddress)]
				if !exists {
					proverInfo = &consensus.ProverInfo{
						PublicKey:        publicKey,
						Address:          proverAddress,
						Status:           mappedStatus,
						AvailableStorage: availableStorage,
						Seniority:        seniority,
						DelegateAddress:  delegateAddress,
						KickFrameNumber:  kickFrameNumber,
						Allocations:      []consensus.ProverAllocationInfo{},
					}
					r.proverCache[string(proverAddress)] = proverInfo
				} else {
					// Update existing prover info
					proverInfo.Status = mappedStatus
					proverInfo.AvailableStorage = availableStorage
					proverInfo.Seniority = seniority
					proverInfo.DelegateAddress = delegateAddress
					proverInfo.KickFrameNumber = kickFrameNumber
				}

				// If global prover is active, add to global trie
				if mappedStatus == consensus.ProverStatusActive {
					if err := r.addProverToTrie(
						proverAddress,
						publicKey,
						nil,
						frameNumber,
					); err != nil {
						return errors.Wrap(err, "failed to add prover to global trie")
					}
				} else {
					// Remove from global trie if not active
					if err := r.removeProverFromTrie(proverAddress, nil); err != nil {
						return errors.Wrap(err, "failed to remove prover from global trie")
					}
				}
			} else {
				// Try to read as ProverAllocation
				proverRef, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"allocation:ProverAllocation",
					"prover:Prover",
					data,
				)
				if err != nil || len(proverRef) == 0 {
					// Neither Prover nor ProverAllocation, skip
					return nil
				}

				// This is a ProverAllocation vertex
				statusBytes, err := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"allocation:ProverAllocation",
					"Status",
					data,
				)
				if err != nil || len(statusBytes) == 0 {
					return nil
				}
				status := statusBytes[0]

				// Map allocation status
				var mappedStatus consensus.ProverStatus
				switch status {
				case 0:
					mappedStatus = consensus.ProverStatusJoining
				case 1:
					mappedStatus = consensus.ProverStatusActive
				case 2:
					mappedStatus = consensus.ProverStatusPaused
				case 3:
					mappedStatus = consensus.ProverStatusLeaving
				case 4:
					mappedStatus = consensus.ProverStatusRejected
				case 5:
					mappedStatus = consensus.ProverStatusKicked
				default:
					mappedStatus = consensus.ProverStatusUnknown
				}

				r.logger.Debug(
					"processing allocation update",
					zap.String("prover_ref", fmt.Sprintf("%x", proverRef)),
					zap.Uint8("status", uint8(mappedStatus)),
				)

				// Extract filters
				confirmationFilter, _ := r.rdfMultiprover.Get(
					global.GLOBAL_RDF_SCHEMA,
					"allocation:ProverAllocation",
					"ConfirmationFilter",
					data,
				)

				// Find the prover this allocation belongs to
				if proverInfo, exists := r.proverCache[string(proverRef)]; exists {
					// Update tries based on allocation status
					if mappedStatus == consensus.ProverStatusActive &&
						len(confirmationFilter) > 0 {
						if err := r.addProverToTrie(
							proverRef,
							proverInfo.PublicKey,
							confirmationFilter,
							frameNumber,
						); err != nil {
							return errors.Wrap(err, "failed to add prover to filter trie")
						}
					} else {
						// Remove from filter trie if not active
						if err := r.removeProverFromTrie(
							proverRef,
							confirmationFilter,
						); err != nil {
							return errors.Wrap(
								err,
								"failed to remove prover from filter trie",
							)
						}
					}
				}
			}
		}

	case state.DeleteStateChangeEvent:
		// A prover was deleted
		return r.removeProver(proverAddress)
	}

	return nil
}

// removeProver removes a prover from all internal structures
func (r *ProverRegistry) removeProver(proverAddress []byte) error {
	r.logger.Debug(
		"removing prover from registry",
		zap.String("address", fmt.Sprintf("%x", proverAddress)),
	)

	// Get prover info to know which tries to remove from
	if info, exists := r.proverCache[string(proverAddress)]; exists {
		// Remove from all tries this prover is in
		// First remove from global trie if it's there
		if err := r.removeProverFromTrie(proverAddress, nil); err != nil {
			return errors.Wrap(err, "failed to remove from global trie")
		}

		// Then remove from all filter-specific tries based on allocations
		for _, allocation := range info.Allocations {
			if len(allocation.ConfirmationFilter) > 0 {
				if err := r.removeProverFromTrie(
					proverAddress,
					allocation.ConfirmationFilter,
				); err != nil {
					return errors.Wrap(err, "failed to remove from filter trie")
				}
			}
		}
	}

	// Remove from cache
	delete(r.proverCache, string(proverAddress))

	// Remove from address to filters mapping
	delete(r.addressToFilters, string(proverAddress))

	r.logger.Debug(
		"prover removed successfully",
		zap.String("address", fmt.Sprintf("%x", proverAddress)),
	)

	return nil
}

// extractProverFromAddress extracts a single prover's information from the
// hypergraph
func (r *ProverRegistry) extractProverFromAddress(
	proverAddress []byte,
) error {
	r.logger.Debug(
		"extracting prover from address",
		zap.String("address", fmt.Sprintf("%x", proverAddress)),
	)

	if r.hypergraph == nil {
		r.logger.Debug("no hypergraph available for extraction")
		return nil
	}

	// Create composite address: GLOBAL_INTRINSIC_ADDRESS + prover address
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], proverAddress)

	// Try to get the vertex data
	data, err := r.hypergraph.GetVertexData(fullAddress)
	if err != nil {
		// Prover doesn't exist
		r.logger.Debug(
			"prover vertex not found",
			zap.String("address", fmt.Sprintf("%x", proverAddress)),
		)
		return nil
	}

	// Extract public key
	publicKey, err := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"PublicKey",
		data,
	)
	if err != nil || len(publicKey) == 0 {
		return errors.Wrap(err, "failed to get public key")
	}

	// Extract status
	statusBytes, err := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"Status",
		data,
	)
	if err != nil || len(statusBytes) == 0 {
		return errors.Wrap(err, "failed to get status")
	}
	status := statusBytes[0]

	// Map internal status to our ProverStatus enum
	var mappedStatus consensus.ProverStatus
	switch status {
	case 0:
		mappedStatus = consensus.ProverStatusJoining
	case 1:
		mappedStatus = consensus.ProverStatusActive
	case 2:
		mappedStatus = consensus.ProverStatusPaused
	case 3:
		mappedStatus = consensus.ProverStatusLeaving
	case 4:
		// Skip left provers
		r.logger.Debug(
			"skipping left prover",
			zap.String("address", fmt.Sprintf("%x", proverAddress)),
		)
		return nil
	default:
		mappedStatus = consensus.ProverStatusUnknown
	}

	// Extract available storage
	var availableStorage uint64
	storageBytes, err := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"AvailableStorage",
		data,
	)
	if err == nil && len(storageBytes) >= 8 {
		availableStorage = binary.BigEndian.Uint64(storageBytes)
	}

	// Extract seniority
	var seniority uint64
	seniorityBytes, err := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"Seniority",
		data,
	)
	if err == nil && len(seniorityBytes) >= 8 {
		seniority = binary.BigEndian.Uint64(seniorityBytes)
	}

	// Extract delegate address
	delegateAddress, _ := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"DelegateAddress",
		data,
	)

	// Extract kick frame number
	var kickFrameNumber uint64
	kickFrameBytes, err := r.rdfMultiprover.Get(
		global.GLOBAL_RDF_SCHEMA,
		"prover:Prover",
		"KickFrameNumber",
		data,
	)
	if err == nil && len(kickFrameBytes) >= 8 {
		kickFrameNumber = binary.BigEndian.Uint64(kickFrameBytes)
	}

	r.logger.Debug(
		"extracted prover info",
		zap.String("address", fmt.Sprintf("%x", proverAddress)),
		zap.Uint8("status", uint8(mappedStatus)),
		zap.Uint64("available_storage", availableStorage),
		zap.Uint64("seniority", seniority),
	)

	// Create ProverInfo
	proverInfo := &consensus.ProverInfo{
		PublicKey:        publicKey,
		Address:          proverAddress,
		Status:           mappedStatus,
		AvailableStorage: availableStorage,
		Seniority:        seniority,
		DelegateAddress:  delegateAddress,
		KickFrameNumber:  kickFrameNumber,
		Allocations:      []consensus.ProverAllocationInfo{},
	}

	// Add to cache
	r.proverCache[string(proverAddress)] = proverInfo

	// Note: Allocations should be handled separately when iterating through
	// allocation vertices

	return nil
}

// GetAllActiveAppShardProvers implements ProverRegistry
func (r *ProverRegistry) GetAllActiveAppShardProvers() (
	[]*consensus.ProverInfo,
	error,
) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.Debug("getting all active app shard provers")

	var result []*consensus.ProverInfo

	// Iterate through all cached provers
	for _, proverInfo := range r.proverCache {
		// Check if this prover has any active allocations (app shard provers)
		hasActiveAllocation := false
		for _, allocation := range proverInfo.Allocations {
			if allocation.Status == consensus.ProverStatusActive &&
				len(allocation.ConfirmationFilter) > 0 {
				hasActiveAllocation = true
				break
			}
		}

		// Only include provers with active allocations
		if hasActiveAllocation {
			// Make a copy to avoid external modification
			proverCopy := &consensus.ProverInfo{
				PublicKey:        make([]byte, len(proverInfo.PublicKey)),
				Address:          make([]byte, len(proverInfo.Address)),
				Status:           proverInfo.Status,
				AvailableStorage: proverInfo.AvailableStorage,
				Seniority:        proverInfo.Seniority,
				DelegateAddress:  make([]byte, len(proverInfo.DelegateAddress)),
				KickFrameNumber:  proverInfo.KickFrameNumber,
				Allocations: make(
					[]consensus.ProverAllocationInfo,
					len(proverInfo.Allocations),
				),
			}
			copy(proverCopy.PublicKey, proverInfo.PublicKey)
			copy(proverCopy.Address, proverInfo.Address)
			copy(proverCopy.DelegateAddress, proverInfo.DelegateAddress)

			// Copy allocations
			for i, allocation := range proverInfo.Allocations {
				proverCopy.Allocations[i] = consensus.ProverAllocationInfo{
					Status: allocation.Status,
					ConfirmationFilter: make(
						[]byte,
						len(allocation.ConfirmationFilter),
					),
					RejectionFilter: make(
						[]byte,
						len(allocation.RejectionFilter),
					),
					JoinFrameNumber:         allocation.JoinFrameNumber,
					LeaveFrameNumber:        allocation.LeaveFrameNumber,
					PauseFrameNumber:        allocation.PauseFrameNumber,
					ResumeFrameNumber:       allocation.ResumeFrameNumber,
					KickFrameNumber:         allocation.KickFrameNumber,
					JoinConfirmFrameNumber:  allocation.JoinConfirmFrameNumber,
					JoinRejectFrameNumber:   allocation.JoinRejectFrameNumber,
					LeaveConfirmFrameNumber: allocation.LeaveConfirmFrameNumber,
					LeaveRejectFrameNumber:  allocation.LeaveRejectFrameNumber,
					LastActiveFrameNumber:   allocation.LastActiveFrameNumber,
				}
				copy(
					proverCopy.Allocations[i].ConfirmationFilter,
					allocation.ConfirmationFilter,
				)
				copy(
					proverCopy.Allocations[i].RejectionFilter,
					allocation.RejectionFilter,
				)
			}

			result = append(result, proverCopy)
		}
	}

	r.logger.Debug(
		"retrieved active app shard provers",
		zap.Int("count", len(result)),
	)

	return result, nil
}
