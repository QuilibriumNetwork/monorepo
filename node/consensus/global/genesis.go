package global

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"go.uber.org/zap"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	globalintrinsics "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// GenesisJson represents the structure of the mainnet genesis JSON
type GenesisJson struct {
	FrameNumber        uint64            `json:"frame_number"`
	Timestamp          int64             `json:"timestamp"`
	Difficulty         uint32            `json:"difficulty"`
	ParentSelector     string            `json:"parent_selector"`
	InitialCommitments map[string]string `json:"initial_commitments"`
	Output             string            `json:"output"`
	BeaconEd448Key     string            `json:"beacon_ed448_key"`
	BeaconBLS48581Key  string            `json:"beacon_bls48581_key"`
	ArchivePeers       map[string]string `json:"archive_peers"`
}

// TODO[2.1.1+]: Refactor out direct hypergraph access
func (e *GlobalConsensusEngine) initializeGenesis() *protobufs.GlobalFrame {
	e.logger.Info("initializing genesis frame for global consensus")

	var genesisFrame *protobufs.GlobalFrame

	// If on mainnet, load from release
	if e.config.P2P.Network == 0 {
		var lastErr error
		var genesisData GenesisJson = GenesisJson{}
		for attempt := 1; attempt <= 5; attempt++ {
			if err := func() error {
				resp, err := http.Get("https://releases.quilibrium.com/genesis.json")
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("http status %d", resp.StatusCode)
				}

				buf := bytes.NewBuffer(nil)
				_, err = io.Copy(buf, resp.Body)
				if err != nil {
					return err
				}

				err = json.Unmarshal(buf.Bytes(), &genesisData)
				if err != nil {
					return err
				}

				return nil
			}(); err != nil {
				lastErr = err
				// simple backoff: 200ms * attempt
				time.Sleep(time.Duration(200*attempt) * time.Millisecond)
				continue
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			e.logger.Error("failed to download genesis", zap.Error(lastErr))
			return nil
		}

		// Decode base64 encoded fields
		parentSelector, err := base64.StdEncoding.DecodeString(
			genesisData.ParentSelector,
		)
		if err != nil {
			e.logger.Error("failed to decode parent selector", zap.Error(err))
			return nil
		}

		output, err := base64.StdEncoding.DecodeString(genesisData.Output)
		if err != nil {
			e.logger.Error("failed to decode output", zap.Error(err))
			return nil
		}

		// Create genesis header with actual data
		genesisHeader := &protobufs.GlobalFrameHeader{
			FrameNumber:          genesisData.FrameNumber,
			ParentSelector:       parentSelector,
			Timestamp:            genesisData.Timestamp,
			Difficulty:           genesisData.Difficulty,
			GlobalCommitments:    make([][]byte, 256),
			ProverTreeCommitment: make([]byte, 64),
			Output:               output,
		}

		// Initialize all commitments with empty values first
		for i := range 256 {
			genesisHeader.GlobalCommitments[i] = make([]byte, 64)
		}

		commitments := make([]*tries.VectorCommitmentTree, 256)
		for i := range 256 {
			commitments[i] = &tries.VectorCommitmentTree{}
		}

		proverRoot := make([]byte, 64)

		// Parse and set initial commitments from JSON
		for hexKey, base64Value := range genesisData.InitialCommitments {
			// Decode hex key to get index
			keyBytes, err := hex.DecodeString(hexKey)
			if err != nil {
				e.logger.Error(
					"failed to decode commitment key",
					zap.String("key", hexKey),
					zap.Error(err),
				)
				continue
			}

			commitmentValue, err := base64.StdEncoding.DecodeString(base64Value)
			if err != nil {
				e.logger.Error(
					"failed to decode commitment value",
					zap.String("value", base64Value),
					zap.Error(err),
				)
				return nil
			}

			l1 := up2p.GetBloomFilterIndices(keyBytes, 256, 3)

			txn, err := e.clockStore.NewTransaction(false)
			if err != nil {
				panic(err)
			}

			for i := 0; i < 64; i++ {
				for j := 0; j < 64; j++ {
					err = e.shardsStore.PutAppShard(txn, store.ShardInfo{
						L1:   l1,
						L2:   keyBytes,
						Path: []uint32{uint32(i), uint32(j)},
					})
					e.logger.Error(
						"failed to place app shard",
						zap.String("value", base64Value),
						zap.Error(err),
					)
					txn.Abort()
					return nil
				}
			}

			for i := 0; i < 3; i++ {
				commitments[l1[i]].Insert(
					keyBytes,
					commitmentValue,
					nil,
					big.NewInt(int64(len(commitmentValue))),
				)
				commitments[l1[i]].Commit(e.inclusionProver, false)
			}
		}

		state := hgstate.NewHypergraphState(e.hypergraph)

		err = e.establishMainnetGenesisProvers(state, genesisData)
		if err != nil {
			e.logger.Error("failed to establish provers", zap.Error(err))
			return nil
		}

		err = state.Commit()
		if err != nil {
			e.logger.Error("failed to commit", zap.Error(err))
			return nil
		}

		roots := e.hypergraph.Commit()
		proverRoots := roots[tries.ShardKey{
			L1: [3]byte{},
			L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		}]

		proverRoot = proverRoots[0]

		genesisHeader.ProverTreeCommitment = proverRoot

		for i := 0; i < 256; i++ {
			genesisHeader.GlobalCommitments[i] = commitments[i].Commit(
				e.inclusionProver,
				false,
			)
		}

		// Establish an empty signature payload – this avoids panics on broken
		// header readers
		genesisHeader.PublicKeySignatureBls48581 =
			&protobufs.BLS48581AggregateSignature{
				Signature: make([]byte, 0),
				PublicKey: &protobufs.BLS48581G2PublicKey{
					KeyValue: make([]byte, 0),
				},
				Bitmask: make([]byte, 0),
			}

		genesisFrame = &protobufs.GlobalFrame{
			Header:   genesisHeader,
			Requests: []*protobufs.MessageBundle{},
		}
	} else {
		// For non-mainnet, use stub genesis
		genesisFrame = e.createStubGenesis()
	}

	// Compute frame ID and store the full frame
	frameIDBI, _ := poseidon.HashBytes(genesisFrame.Header.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	e.frameStoreMu.Lock()
	e.frameStore[string(frameID)] = genesisFrame
	e.frameStoreMu.Unlock()

	// Add to time reel
	if err := e.globalTimeReel.Insert(e.ctx, genesisFrame); err != nil {
		e.logger.Error("failed to add genesis frame to time reel", zap.Error(err))
		// Clean up on error
		e.frameStoreMu.Lock()
		delete(e.frameStore, string(frameID))
		e.frameStoreMu.Unlock()
	}

	e.proverRegistry.Refresh()

	e.logger.Info("initialized genesis frame for global consensus")
	return genesisFrame
}

// createStubGenesis creates a stub genesis frame for non-mainnet networks
func (e *GlobalConsensusEngine) createStubGenesis() *protobufs.GlobalFrame {
	e.logger.Warn("CREATING STUB GENESIS FOR TEST NETWORK")
	// Create a stub genesis frame
	genesisHeader := &protobufs.GlobalFrameHeader{
		FrameNumber:          0,
		ParentSelector:       make([]byte, 32),
		Timestamp:            time.Now().UnixMilli(),
		Difficulty:           e.config.Engine.Difficulty,
		GlobalCommitments:    make([][]byte, 256),
		ProverTreeCommitment: make([]byte, 64),
		Output:               make([]byte, 516),
	}

	for i := range 256 {
		genesisHeader.GlobalCommitments[i] = make([]byte, 64)
	}

	var proverPubKey []byte
	var err error
	if e.config.P2P.Network != 99 && e.config.Engine != nil &&
		e.config.Engine.GenesisSeed != "" {
		proverPubKey, err = hex.DecodeString(e.config.Engine.GenesisSeed)
		if err != nil {
			panic(err)
		}
	} else {
		proverKey, err := e.keyManager.GetSigningKey("q-prover-key")
		if err != nil {
			e.logger.Error(
				"failed to obtain prover bls48-581 key value",
				zap.Error(err),
			)
			return nil
		}
		proverPubKey = proverKey.Public().([]byte)
	}

	proverAddressBI, err := poseidon.HashBytes(proverPubKey)
	if err != nil || proverAddressBI == nil {
		e.logger.Error(
			"failed to calculate address value",
			zap.Error(err),
		)
		return nil
	}
	proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

	// Full address for the prover entry
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	var proverTree *tries.VectorCommitmentTree

	// Create new prover entry
	proverTree = &tries.VectorCommitmentTree{}

	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		e.inclusionProver,
	)
	// Store the public key
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"PublicKey",
		proverPubKey,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return nil
	}

	// Store status
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Status",
		[]byte{1},
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return nil
	}

	// Store available storage (initially 0)
	availableStorageBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(availableStorageBytes, 0)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"AvailableStorage",
		availableStorageBytes,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return nil
	}

	// Store seniority
	seniorityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seniorityBytes, 1000000000)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Seniority",
		seniorityBytes,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return nil
	}

	// Create prover vertex
	state := hgstate.NewHypergraphState(e.hypergraph)
	proverVertex := state.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(proverAddress),
		0,
		nil,
		proverTree,
	)

	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		proverAddress,
		hgstate.VertexAddsDiscriminator,
		0,
		proverVertex,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Create hyperedge for this prover
	hyperedgeAddress := [32]byte(proverAddress)
	hyperedge := hgcrdt.NewHyperedge(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		hyperedgeAddress,
	)

	// Create ProverAllocation entry for global

	// Calculate allocation address: poseidon.Hash(publicKey || filter)
	allocationAddressBI, err := poseidon.HashBytes(
		slices.Concat([]byte("PROVER_ALLOCATION"), proverPubKey, nil),
	)
	if err != nil {
		e.logger.Error("failed to calculate allocation address", zap.Error(err))
		return nil
	}
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

	// Create allocation tree
	allocationTree := &tries.VectorCommitmentTree{}

	// Store prover reference (using the prover vertex)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Prover",
		proverAddress,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Store allocation status
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Status",
		[]byte{1},
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Store confirmation filter
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"ConfirmationFilter",
		nil,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Store join frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, 0)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinFrameNumber",
		frameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Store join confirm frame number
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinConfirmFrameNumber",
		frameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Store last active frame number
	lastActiveFrameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lastActiveFrameNumberBytes, 244200)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LastActiveFrameNumber",
		lastActiveFrameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Create allocation vertex
	allocationVertex := state.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationAddress),
		0,
		nil,
		allocationTree,
	)

	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddress,
		hgstate.VertexAddsDiscriminator,
		0,
		allocationVertex,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	// Add allocation vertex to hyperedge
	allocationAtom := hgcrdt.NewVertex(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationAddress),
		allocationTree.Commit(e.inclusionProver, false),
		allocationTree.GetSize(),
	)
	hyperedge.AddExtrinsic(allocationAtom)

	// Update hyperedge
	hyperedgeState := state.NewHyperedgeAddMaterializedState(
		0,
		nil,
		hyperedge,
	)
	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hyperedgeAddress[:],
		hgstate.HyperedgeAddsDiscriminator,
		0,
		hyperedgeState,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return nil
	}

	err = state.Commit()
	if err != nil {
		e.logger.Error("failed to commit", zap.Error(err))
		return nil
	}

	roots := e.hypergraph.Commit()
	proverRoots := roots[tries.ShardKey{
		L1: [3]byte{},
		L2: intrinsics.GLOBAL_INTRINSIC_ADDRESS,
	}]

	proverRoot := proverRoots[0]

	genesisHeader.ProverTreeCommitment = proverRoot

	// Establish an empty signature payload – this avoids panics on broken
	// header readers
	genesisHeader.PublicKeySignatureBls48581 =
		&protobufs.BLS48581AggregateSignature{
			Signature: make([]byte, 0),
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: make([]byte, 0),
			},
			Bitmask: make([]byte, 0),
		}

	genesisFrame := &protobufs.GlobalFrame{
		Header: genesisHeader,
	}

	// Compute frame ID and store the full frame
	frameIDBI, _ := poseidon.HashBytes(genesisHeader.Output)
	frameID := frameIDBI.FillBytes(make([]byte, 32))
	e.frameStoreMu.Lock()
	e.frameStore[string(frameID)] = genesisFrame
	e.frameStoreMu.Unlock()

	// Add to time reel
	if err := e.globalTimeReel.Insert(e.ctx, genesisFrame); err != nil {
		e.logger.Error("failed to add genesis frame to time reel", zap.Error(err))
		// Clean up on error
		e.frameStoreMu.Lock()
		delete(e.frameStore, string(frameID))
		e.frameStoreMu.Unlock()
	}

	return genesisFrame
}

func (e *GlobalConsensusEngine) establishMainnetGenesisProvers(
	state *hgstate.HypergraphState,
	genesisData GenesisJson,
) error {
	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		e.inclusionProver,
	)

	// old to peer id, get seniority
	beaconEd448Key, err := base64.StdEncoding.DecodeString(
		genesisData.BeaconEd448Key,
	)
	if err != nil {
		e.logger.Error(
			"failed to decode beacon ed448 key value",
			zap.String("value", genesisData.BeaconEd448Key),
			zap.Error(err),
		)
		return err
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(beaconEd448Key)
	if err != nil {
		e.logger.Error(
			"failed to unmarshal beacon ed448 key value",
			zap.String("value", genesisData.BeaconEd448Key),
			zap.Error(err),
		)
		return err
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		e.logger.Error(
			"failed to construct peer id from ed448 key value",
			zap.String("value", genesisData.BeaconEd448Key),
			zap.Error(err),
		)
		return err
	}

	seniority := compat.GetAggregatedSeniority([]string{peerId.String()})
	e.logger.Debug(
		"establishing seniority for beacon from aggregated records",
		zap.String("seniority", seniority.String()),
	)

	publicKey, err := base64.StdEncoding.DecodeString(
		genesisData.BeaconBLS48581Key,
	)
	if err != nil {
		e.logger.Error(
			"failed to decode beacon bls48-581 key value",
			zap.String("value", genesisData.BeaconBLS48581Key),
			zap.Error(err),
		)
		return err
	}

	if err := e.addGenesisProver(
		rdfMultiprover,
		state,
		[]byte(peerId),
		publicKey,
		seniority.Uint64(),
		genesisData.FrameNumber,
	); err != nil {
		return err
	}

	for peerid, pubkeyhex := range genesisData.ArchivePeers {
		id, err := base58.Decode(peerid)
		if err != nil {
			return err
		}

		pubkey, err := hex.DecodeString(pubkeyhex)
		if err != nil {
			return err
		}

		if err := e.addGenesisProver(
			rdfMultiprover,
			state,
			id,
			pubkey,
			seniority.Uint64(),
			genesisData.FrameNumber,
		); err != nil {
			return err
		}
	}

	return nil
}

func (e *GlobalConsensusEngine) addGenesisProver(
	rdfMultiprover *schema.RDFMultiprover,
	state *hgstate.HypergraphState,
	peerId []byte,
	pubkey []byte,
	seniority uint64,
	frameNumber uint64,
) error {
	proverAddressBI, err := poseidon.HashBytes(pubkey)
	if err != nil || proverAddressBI == nil {
		e.logger.Error(
			"failed to calculate address value",
			zap.String("value", hex.EncodeToString(pubkey)),
			zap.Error(err),
		)
		return err
	}
	proverAddress := proverAddressBI.FillBytes(make([]byte, 32))

	// Full address for the prover entry
	proverFullAddress := [64]byte{}
	copy(proverFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(proverFullAddress[32:], proverAddress)

	// Create new prover entry
	proverTree := &tries.VectorCommitmentTree{}
	// Store the public key
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"PublicKey",
		pubkey,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return err
	}

	// Store status
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Status",
		[]byte{1},
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return err
	}

	// Store available storage (initially 0)
	availableStorageBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(availableStorageBytes, 0)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"AvailableStorage",
		availableStorageBytes,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return err
	}

	// Store seniority
	seniorityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seniorityBytes, seniority)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Seniority",
		seniorityBytes,
		proverTree,
	)
	if err != nil {
		e.logger.Error("failed to set rdf value", zap.Error(err))
		return err
	}

	// Create prover vertex
	proverVertex := state.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(proverAddress),
		frameNumber,
		nil,
		proverTree,
	)

	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		proverAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		proverVertex,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Create hyperedge for this prover
	hyperedgeAddress := [32]byte(proverAddress)
	hyperedge := hgcrdt.NewHyperedge(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		hyperedgeAddress,
	)

	// Create ProverAllocation entry for global

	// Calculate allocation address: poseidon.Hash(publicKey || filter)
	allocationAddressBI, err := poseidon.HashBytes(
		slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, nil),
	)
	if err != nil {
		e.logger.Error("failed to calculate allocation address", zap.Error(err))
		return err
	}
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

	// Create allocation tree
	allocationTree := &tries.VectorCommitmentTree{}

	// Store prover reference (using the prover vertex)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Prover",
		proverAddress,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Store allocation status
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Status",
		[]byte{1},
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Store confirmation filter
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"ConfirmationFilter",
		nil,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Store join frame number
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, 0)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinFrameNumber",
		frameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Store join confirm frame number
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinConfirmFrameNumber",
		frameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Store last active frame number
	lastActiveFrameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lastActiveFrameNumberBytes, 244200)
	err = rdfMultiprover.Set(
		globalintrinsics.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LastActiveFrameNumber",
		lastActiveFrameNumberBytes,
		allocationTree,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Create allocation vertex
	allocationVertex := state.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationAddress),
		frameNumber,
		nil,
		allocationTree,
	)

	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		allocationVertex,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	// Add allocation vertex to hyperedge
	allocationAtom := hgcrdt.NewVertex(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(allocationAddress),
		allocationTree.Commit(e.inclusionProver, false),
		allocationTree.GetSize(),
	)
	hyperedge.AddExtrinsic(allocationAtom)

	// Update hyperedge
	hyperedgeState := state.NewHyperedgeAddMaterializedState(
		frameNumber,
		nil,
		hyperedge,
	)
	err = state.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		hyperedgeAddress[:],
		hgstate.HyperedgeAddsDiscriminator,
		frameNumber,
		hyperedgeState,
	)
	if err != nil {
		e.logger.Error("failed to set state value", zap.Error(err))
		return err
	}

	return nil
}
