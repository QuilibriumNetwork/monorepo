package hypergraph

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"
	observability "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var RAW_HYPERGRAPH_PREFIX = []byte("q_hypergraph")
var HYPERGRAPH_BASE_DOMAIN [32]byte

func init() {
	hgDomainBI, err := poseidon.HashBytes(RAW_HYPERGRAPH_PREFIX)
	if err != nil {
		panic(err)
	}

	HYPERGRAPH_BASE_DOMAIN = [32]byte(hgDomainBI.FillBytes(make([]byte, 32)))
}

type HypergraphIntrinsic struct {
	lockedWrites        map[string]struct{}
	lockedReads         map[string]int
	lockedWritesMx      sync.RWMutex
	lockedReadsMx       sync.RWMutex
	domain              []byte
	hypergraph          hgcrdt.Hypergraph
	config              *HypergraphIntrinsicConfiguration
	consensusMetadata   *qcrypto.VectorCommitmentTree
	sumcheckInfo        *qcrypto.VectorCommitmentTree
	rdfHypergraphSchema string
	rdfMultiprover      *schema.RDFMultiprover
	keyManager          keys.KeyManager
	state               state.State
	inclusionProver     crypto.InclusionProver
	signer              crypto.Signer
	verenc              crypto.VerifiableEncryptor
}

// GetRDFSchema implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) GetRDFSchema() (
	map[string]map[string]*schema.RDFTag,
	error,
) {
	tags, err := h.rdfMultiprover.GetSchemaMap(h.rdfHypergraphSchema)
	return tags, errors.Wrap(err, "get rdf schema")
}

// Config returns the configuration - used for testing
func (h *HypergraphIntrinsic) Config() *HypergraphIntrinsicConfiguration {
	return h.config
}

// Hypergraph returns the hypergraph - used for testing
func (h *HypergraphIntrinsic) Hypergraph() hgcrdt.Hypergraph {
	return h.hypergraph
}

func LoadHypergraphIntrinsic(
	appAddress []byte,
	hypergraph hgcrdt.Hypergraph,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	signer crypto.Signer,
	verenc crypto.VerifiableEncryptor,
) (*HypergraphIntrinsic, error) {
	vertexAddress := slices.Concat(
		appAddress,
		hg.HYPERGRAPH_METADATA_ADDRESS,
	)

	// Ensure the vertex is present and has not been removed
	_, err := hypergraph.GetVertex([64]byte(vertexAddress))
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	tree, err := hypergraph.GetVertexData([64]byte(vertexAddress))
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	config, err := unpackAndVerifyHypergraphConfigurationMetadata(
		inclusionProver,
		tree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	consensusMetadata, err := unpackAndVerifyConsensusMetadata(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	sumcheckInfo, err := unpackAndVerifySumcheckInfo(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	rdfHypergraphSchema, err := unpackAndVerifyRdfHypergraphSchema(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph intrinsic")
	}

	return &HypergraphIntrinsic{
		lockedWrites:        make(map[string]struct{}),
		lockedReads:         make(map[string]int),
		hypergraph:          hypergraph,
		domain:              appAddress,
		config:              config,
		consensusMetadata:   consensusMetadata,
		sumcheckInfo:        sumcheckInfo,
		rdfHypergraphSchema: rdfHypergraphSchema,
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			hypergraph.GetProver(),
		),
		state:           hg.NewHypergraphState(hypergraph),
		keyManager:      keyManager,
		inclusionProver: inclusionProver,
		signer:          signer,
		verenc:          verenc,
	}, nil
}

func NewHypergraphIntrinsic(
	config *HypergraphIntrinsicConfiguration,
	hypergraph hgcrdt.Hypergraph,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	signer crypto.Signer,
	verenc crypto.VerifiableEncryptor,
) *HypergraphIntrinsic {
	return &HypergraphIntrinsic{
		config:       config,
		lockedWrites: make(map[string]struct{}),
		lockedReads:  make(map[string]int),
		hypergraph:   hypergraph,
		keyManager:   keyManager,
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			hypergraph.GetProver(),
		),
		inclusionProver: inclusionProver,
		signer:          signer,
		verenc:          verenc,
	}
}

type HypergraphIntrinsicConfiguration struct {
	// The Ed448 read public key, used for confirming verifiable encryption
	ReadPublicKey []byte
	// The Ed448 write public key, used for confirming operation validity
	WritePublicKey []byte
	// The BLS48-581 owner public key, used for administrative operations on the
	// configuration
	OwnerPublicKey []byte
}

// SumCheck implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) SumCheck() bool {
	return true
}

// Address implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Address() []byte {
	return h.domain
}

// Commit implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Commit() (state.State, error) {
	timer := prometheus.NewTimer(
		observability.CommitDuration.WithLabelValues("hypergraph"),
	)
	defer timer.ObserveDuration()

	if h.state == nil {
		observability.CommitErrors.WithLabelValues("hypergraph").Inc()
		return nil, errors.Wrap(errors.New("nothing to commit"), "commit")
	}

	if err := h.state.Commit(); err != nil {
		observability.CommitErrors.WithLabelValues("hypergraph").Inc()
		return h.state, errors.Wrap(err, "commit")
	}

	observability.CommitTotal.WithLabelValues("hypergraph").Inc()
	return h.state, nil
}

func newHypergraphConsensusMetadata(
	provers [][]byte,
) (*qcrypto.VectorCommitmentTree, error) {
	if len(provers) != 0 {
		return nil, errors.Wrap(
			errors.New(
				"hypergraph intrinsic may not accept a prover list for initialization",
			),
			"new hypergraph consensus metadata",
		)
	}

	return &qcrypto.VectorCommitmentTree{}, nil
}

func newHypergraphSumcheckInfo() (*qcrypto.VectorCommitmentTree, error) {
	return &qcrypto.VectorCommitmentTree{}, nil
}

func validateHypergraphConfiguration(
	config *HypergraphIntrinsicConfiguration,
) error {
	if len(config.ReadPublicKey) != 57 || len(config.WritePublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid key"),
			"validate hypergraph configuration",
		)
	}

	return nil
}

func newHypergraphConfigurationMetadata(
	config *HypergraphIntrinsicConfiguration,
) (*qcrypto.VectorCommitmentTree, error) {
	if err := validateHypergraphConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "hypergraph config")
	}

	tree := &qcrypto.VectorCommitmentTree{}

	// Store Read key (byte 0)
	if err := tree.Insert(
		[]byte{0 << 2},
		config.ReadPublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return nil, errors.Wrap(err, "hypergraph config")
	}

	// Store Write key (byte 0)
	if err := tree.Insert(
		[]byte{1 << 2},
		config.WritePublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return nil, errors.Wrap(err, "hypergraph config")
	}

	return tree, nil
}

func (h *HypergraphIntrinsic) newHypergraphRDFHypergraphSchema(
	contextData []byte,
) (string, error) {
	if len(contextData) == 0 {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new hypergraph rdf hypergraph schema",
		)
	}

	schemaDoc := string(contextData)
	data, err := h.rdfMultiprover.GetSchemaMap(schemaDoc)
	if err != nil {
		return "", errors.Wrap(err, "new hypergraph rdf hypergraph schema")
	}

	if data == nil {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new hypergraph rdf hypergraph schema",
		)
	}

	return schemaDoc, nil
}

// validateRDFSchemaUpdate ensures that the new schema only adds new classes and properties,
// never removing or modifying existing ones
func (h *HypergraphIntrinsic) validateRDFSchemaUpdate(oldSchema, newSchema string) error {
	// Parse both schemas
	oldTags, err := h.rdfMultiprover.GetSchemaMap(oldSchema)
	if err != nil {
		return errors.Wrap(err, "validate rdf schema update: parsing old schema")
	}

	newTags, err := h.rdfMultiprover.GetSchemaMap(newSchema)
	if err != nil {
		return errors.Wrap(err, "validate rdf schema update: parsing new schema")
	}

	// Check that all old classes still exist with the same properties
	for className, oldFields := range oldTags {
		newFields, exists := newTags[className]
		if !exists {
			return errors.Wrap(
				errors.New(fmt.Sprintf("class '%s' was removed", className)),
				"validate rdf schema update",
			)
		}

		// Check that all old fields in this class still exist with the same properties
		for fieldName, oldTag := range oldFields {
			newTag, exists := newFields[fieldName]
			if !exists {
				return errors.Wrap(
					errors.New(fmt.Sprintf(
						"field '%s' was removed from class '%s'",
						fieldName,
						className,
					)),
					"validate rdf schema update",
				)
			}

			// Compare all RDFTag properties to ensure they haven't changed
			if err := compareHypergraphRDFTags(oldTag, newTag, className, fieldName); err != nil {
				return errors.Wrap(err, "validate rdf schema update")
			}
		}
	}

	return nil
}

// compareHypergraphRDFTags compares two RDF tags to ensure they are identical
func compareHypergraphRDFTags(oldTag, newTag *schema.RDFTag, className, fieldName string) error {
	// Check Name
	if oldTag.Name != newTag.Name {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Name changed from '%s' to '%s'",
			className, fieldName, oldTag.Name, newTag.Name,
		))
	}

	// Check Extrinsic
	if oldTag.Extrinsic != newTag.Extrinsic {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Extrinsic changed from '%s' to '%s'",
			className, fieldName, oldTag.Extrinsic, newTag.Extrinsic,
		))
	}

	// Check Order
	if oldTag.Order != newTag.Order {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Order changed from %d to %d",
			className, fieldName, oldTag.Order, newTag.Order,
		))
	}

	// Check Size (pointer comparison)
	if (oldTag.Size == nil) != (newTag.Size == nil) {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Size presence changed",
			className, fieldName,
		))
	}
	if oldTag.Size != nil && newTag.Size != nil && *oldTag.Size != *newTag.Size {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Size changed from %d to %d",
			className, fieldName, *oldTag.Size, *newTag.Size,
		))
	}

	// Check Raw
	if oldTag.Raw != newTag.Raw {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' Raw changed from '%s' to '%s'",
			className, fieldName, oldTag.Raw, newTag.Raw,
		))
	}

	// Check RdfType
	if oldTag.RdfType != newTag.RdfType {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' RdfType changed from '%s' to '%s'",
			className, fieldName, oldTag.RdfType, newTag.RdfType,
		))
	}

	// Check FieldSize
	if oldTag.FieldSize != newTag.FieldSize {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' FieldSize changed from %d to %d",
			className, fieldName, oldTag.FieldSize, newTag.FieldSize,
		))
	}

	return nil
}

func unpackAndVerifyHypergraphConfigurationMetadata(
	inclusionProver crypto.InclusionProver,
	tree *qcrypto.VectorCommitmentTree,
) (*HypergraphIntrinsicConfiguration, error) {
	commitment := tree.Commit(inclusionProver, false)
	if len(commitment) == 0 {
		return nil, errors.Wrap(errors.New("invalid tree"), "unpack and verify")
	}

	// Get the configuration metadata from index 16
	hypergraphConfigurationMetadataBytes, err := tree.Get([]byte{16 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	hypergraphConfigurationMetadata, err := qcrypto.DeserializeNonLazyTree(
		hypergraphConfigurationMetadataBytes,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	config := &HypergraphIntrinsicConfiguration{}

	// Read Read key (byte 0)
	readKey, err := hypergraphConfigurationMetadata.Get([]byte{0 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.ReadPublicKey = readKey

	// Read Write key (byte 1)
	writeKey, err := hypergraphConfigurationMetadata.Get([]byte{1 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.WritePublicKey = writeKey

	if err := validateHypergraphConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	return config, nil
}

func unpackAndVerifyConsensusMetadata(tree *qcrypto.VectorCommitmentTree) (
	*qcrypto.VectorCommitmentTree,
	error,
) {
	return hg.UnpackConsensusMetadata(tree)
}

func unpackAndVerifyRdfHypergraphSchema(
	tree *qcrypto.VectorCommitmentTree,
) (string, error) {
	rdfSchema, err := hg.UnpackRdfHypergraphSchema(tree)
	if err != nil {
		return "", errors.Wrap(err, "unpack and verify")
	}

	return rdfSchema, nil
}

func unpackAndVerifySumcheckInfo(tree *qcrypto.VectorCommitmentTree) (
	*qcrypto.VectorCommitmentTree,
	error,
) {
	return hg.UnpackSumcheckInfo(tree)
}

// Deploy implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Deploy(
	domain [32]byte,
	provers [][]byte,
	creator []byte,
	fee *big.Int,
	contextData []byte,
	frameNumber uint64,
	hgstate state.State,
) (state.State, error) {
	if !bytes.Equal(domain[:], HYPERGRAPH_BASE_DOMAIN[:]) {
		vert, err := hgstate.Get(
			domain[:],
			hg.HYPERGRAPH_METADATA_ADDRESS,
			hg.VertexAddsDiscriminator,
		)
		if err != nil {
			return nil, errors.Wrap(
				state.ErrInvalidDomain,
				"deploy",
			)
		}

		if vert == nil {
			return nil, errors.Wrap(
				state.ErrInvalidDomain,
				"deploy",
			)
		}

		// Deserialize the update arguments
		updatePb := &protobufs.HypergraphUpdate{}
		err = updatePb.FromCanonicalBytes(contextData)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		if err := updatePb.Validate(); err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		deployArgs, err := HypergraphUpdateFromProtobuf(updatePb)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		updateWithoutSignature := proto.Clone(updatePb).(*protobufs.HypergraphUpdate)

		updateWithoutSignature.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		validSig, err := h.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			h.config.OwnerPublicKey,
			message,
			updatePb.PublicKeySignatureBls48581.Signature,
			slices.Concat(domain[:], []byte("HYPERGRAPH_UPDATE")),
		)
		if err != nil || !validSig {
			return nil, errors.Wrap(errors.New("invalid signature"), "deploy")
		}

		vertexAddress := slices.Concat(
			h.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
		)

		// Ensure the vertex is present and has not been removed
		_, err = h.hypergraph.GetVertex([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		prior, err := h.hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		tree, err := h.hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		// Retrieve the existing RDF schema from the tree
		existingRDFSchema, err := unpackAndVerifyRdfHypergraphSchema(tree)
		if err != nil {
			// It's ok if there's no existing schema
			existingRDFSchema = ""
		}

		// Update configuration if provided
		if deployArgs.Config != nil {
			configTree, err := newHypergraphConfigurationMetadata(
				deployArgs.Config,
			)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			commit := configTree.Commit(h.inclusionProver, false)

			out, err := qcrypto.SerializeNonLazyTree(configTree)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			err = tree.Insert([]byte{16 << 2}, out, commit, configTree.GetSize())
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}
		}

		// Update RDF schema if provided
		if len(deployArgs.RDFSchema) > 0 {
			newSchemaDoc := string(deployArgs.RDFSchema)

			// Validate that the new schema is valid
			_, err := h.rdfMultiprover.GetSchemaMap(newSchemaDoc)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			// Validate that the update only adds new classes/properties, never
			// removes
			if existingRDFSchema != "" {
				err = h.validateRDFSchemaUpdate(existingRDFSchema, newSchemaDoc)
				if err != nil {
					return nil, errors.Wrap(err, "deploy")
				}
			}

			// Store the RDF schema in the tree
			err = tree.Insert(
				[]byte{3 << 2},
				deployArgs.RDFSchema,
				nil,
				big.NewInt(int64(len(deployArgs.RDFSchema))),
			)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			h.rdfHypergraphSchema = newSchemaDoc
		} else {
			// Keep the existing schema if no update is provided
			h.rdfHypergraphSchema = existingRDFSchema
		}

		err = hgstate.Set(
			h.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
			hg.VertexAddsDiscriminator,
			frameNumber,
			hgstate.(*hg.HypergraphState).NewVertexAddMaterializedState(
				[32]byte(h.Address()),
				[32]byte(hg.HYPERGRAPH_METADATA_ADDRESS),
				frameNumber,
				prior,
				tree,
			),
		)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		h.state = hgstate

		return hgstate, nil
	}

	initialConsensusMetadata, err := newHypergraphConsensusMetadata(
		provers,
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	initialSumcheckInfo, err := newHypergraphSumcheckInfo()
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	additionalData := make([]*qcrypto.VectorCommitmentTree, 14)
	additionalData[13], err = newHypergraphConfigurationMetadata(
		h.config,
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	hypergraphDomainBI, err := poseidon.HashBytes(
		slices.Concat(
			RAW_HYPERGRAPH_PREFIX,
			additionalData[13].Commit(h.hypergraph.GetProver(), false),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	hypergraphDomain := hypergraphDomainBI.FillBytes(make([]byte, 32))

	rdfHypergraphSchema, err := h.newHypergraphRDFHypergraphSchema(contextData)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	h.domain = hypergraphDomain

	if err := hgstate.Init(
		hypergraphDomain,
		initialConsensusMetadata,
		initialSumcheckInfo,
		rdfHypergraphSchema,
		additionalData,
		HYPERGRAPH_BASE_DOMAIN[:],
	); err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	h.state = hgstate

	return h.state, nil
}

// Validate implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Validate(
	frameNumber uint64,
	input []byte,
) error {
	timer := prometheus.NewTimer(
		observability.ValidateDuration.WithLabelValues("hypergraph"),
	)
	defer timer.ObserveDuration()

	// Check the type prefix to determine operation type
	if len(input) < 4 {
		observability.ValidateErrors.WithLabelValues(
			"hypergraph",
			"invalid_input",
		).Inc()
		return errors.Wrap(
			errors.New("input too short to determine type"),
			"validate",
		)
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	switch typePrefix {
	case protobufs.VertexAddType:
		pbVertexAdd := &protobufs.VertexAdd{}
		if err := pbVertexAdd.FromCanonicalBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_add",
			).Inc()
			return errors.Wrap(err, "validate")
		}
		vertexAdd, err := VertexAddFromProtobuf(
			pbVertexAdd,
			h.inclusionProver,
			h.keyManager,
			h.signer,
			h.verenc,
			h.config,
		)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_add",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the vertex add operation
		valid, err := vertexAdd.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_add",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_add",
			).Inc()
			return errors.Wrap(errors.New("invalid vertex add"), "validate")
		}

		observability.ValidateTotal.WithLabelValues("hypergraph", "vertex_add").Inc()
		return nil

	case protobufs.VertexRemoveType:
		vertexRemove := &VertexRemove{}
		if err := vertexRemove.FromBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_remove",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the vertex remove operation
		valid, err := vertexRemove.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_remove",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"vertex_remove",
			).Inc()
			return errors.Wrap(errors.New("invalid vertex remove"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"hypergraph",
			"vertex_remove",
		).Inc()
		return nil

	case protobufs.HyperedgeAddType:
		hyperedgeAdd := &HyperedgeAdd{}
		if err := hyperedgeAdd.FromBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_add",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the hyperedge add operation
		valid, err := hyperedgeAdd.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_add",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_add",
			).Inc()
			return errors.Wrap(errors.New("invalid hyperedge add"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"hypergraph",
			"hyperedge_add",
		).Inc()
		return nil

	case protobufs.HyperedgeRemoveType:
		hyperedgeRemove := &HyperedgeRemove{}
		if err := hyperedgeRemove.FromBytes(input); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_remove",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the hyperedge remove operation
		valid, err := hyperedgeRemove.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_remove",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"hypergraph",
				"hyperedge_remove",
			).Inc()
			return errors.Wrap(errors.New("invalid hyperedge remove"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"hypergraph",
			"hyperedge_remove",
		).Inc()
		return nil

	default:
		observability.ValidateErrors.WithLabelValues(
			"hypergraph",
			"unknown_type",
		).Inc()
		return errors.Wrap(
			fmt.Errorf("unknown hypergraph operation type: %d", typePrefix),
			"validate",
		)
	}
}

// InvokeStep implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) InvokeStep(
	frameNumber uint64,
	input []byte,
	feePaid *big.Int,
	feeMultiplier *big.Int,
	state state.State,
) (state.State, error) {
	timer := prometheus.NewTimer(
		observability.InvokeStepDuration.WithLabelValues("hypergraph"),
	)
	defer timer.ObserveDuration()

	// Check if state is a HypergraphState
	hypergraphState, ok := state.(*hg.HypergraphState)
	if !ok {
		observability.InvokeStepErrors.WithLabelValues(
			"hypergraph",
			"invalid_state",
		).Inc()
		return nil, errors.Wrap(errors.New("invalid state type"), "invoke step")
	}

	// Check type prefix to determine request type
	if len(input) < 4 {
		observability.InvokeStepErrors.WithLabelValues(
			"hypergraph",
			"invalid_input",
		).Inc()
		return nil, errors.Wrap(errors.New("invalid input length"), "invoke step")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	// Create the appropriate operation based on the type
	var op intrinsics.IntrinsicOperation
	var opName string

	// Determine which type of request this is based on type prefix
	switch typePrefix {
	case protobufs.VertexAddType:
		opName = "vertex_add"
		// Parse VertexAdd directly from input
		pbVertexAdd := &protobufs.VertexAdd{}
		if err := pbVertexAdd.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		// Convert from protobuf to intrinsics type
		vertexAdd, err := VertexAddFromProtobuf(
			pbVertexAdd,
			h.inclusionProver,
			h.keyManager,
			h.signer,
			h.verenc,
			h.config,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		op = vertexAdd

	case protobufs.VertexRemoveType:
		opName = "vertex_remove"
		// Parse VertexRemove directly from input
		pbVertexRemove := &protobufs.VertexRemove{}
		if err := pbVertexRemove.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		// Convert from protobuf to intrinsics type
		vertexRemove, err := VertexRemoveFromProtobuf(
			pbVertexRemove,
			h.keyManager,
			h.signer,
			h.config,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		op = vertexRemove

	case protobufs.HyperedgeAddType:
		opName = "hyperedge_add"
		// Parse HyperedgeAdd directly from input
		pbHyperedgeAdd := &protobufs.HyperedgeAdd{}
		if err := pbHyperedgeAdd.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		// Convert from protobuf to intrinsics type
		hyperedgeAdd, err := HyperedgeAddFromProtobuf(
			pbHyperedgeAdd,
			h.inclusionProver,
			h.keyManager,
			h.signer,
			h.config,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		op = hyperedgeAdd

	case protobufs.HyperedgeRemoveType:
		opName = "hyperedge_remove"
		// Parse HyperedgeRemove directly from input
		pbHyperedgeRemove := &protobufs.HyperedgeRemove{}
		if err := pbHyperedgeRemove.FromCanonicalBytes(input); err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		// Convert from protobuf to intrinsics type
		hyperedgeRemove, err := HyperedgeRemoveFromProtobuf(
			pbHyperedgeRemove,
			h.keyManager,
			h.signer,
			h.config,
		)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		op = hyperedgeRemove

	default:
		observability.InvokeStepErrors.WithLabelValues(
			"hypergraph",
			"unknown_type",
		).Inc()
		return nil, errors.Wrap(
			errors.New("unknown hypergraph request type"),
			"invoke step",
		)
	}

	// Add operation-specific timer
	opTimer := prometheus.NewTimer(
		observability.OperationDuration.WithLabelValues("hypergraph", opName),
	)
	defer opTimer.ObserveDuration()

	// Verify the operation
	valid, err := op.Verify(frameNumber)
	if err != nil {
		observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
		return nil, errors.Wrap(err, "invoke step")
	}
	if !valid {
		observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
		return nil, errors.Wrap(
			errors.New("operation verification failed"),
			"invoke step",
		)
	}

	// Get cost of the operation
	cost, err := op.GetCost()
	if err != nil {
		observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
		return nil, errors.Wrap(err, "invoke step")
	}

	// Check if fee is sufficient
	if feePaid.Cmp(new(big.Int).Mul(cost, feeMultiplier)) < 0 {
		observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
		return nil, errors.Wrap(
			fmt.Errorf(
				"insufficient fee: %s < %s",
				feePaid,
				new(big.Int).Mul(cost, feeMultiplier),
			),
			"invoke step",
		)
	}

	// Materialize the operation to update the state
	matTimer := prometheus.NewTimer(
		observability.MaterializeDuration.WithLabelValues("hypergraph"),
	)
	h.state, err = op.Materialize(frameNumber, hypergraphState)
	matTimer.ObserveDuration()
	if err != nil {
		observability.InvokeStepErrors.WithLabelValues("hypergraph", opName).Inc()
		return nil, errors.Wrap(err, "invoke step")
	}

	observability.InvokeStepTotal.WithLabelValues("hypergraph", opName).Inc()
	return h.state, nil
}

// Lock implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Lock(
	writeAddresses [][]byte,
	readAddresses [][]byte,
) error {
	h.lockedReadsMx.Lock()
	h.lockedWritesMx.Lock()
	defer h.lockedReadsMx.Unlock()
	defer h.lockedWritesMx.Unlock()

	if h.lockedReads == nil {
		h.lockedReads = make(map[string]int)
	}

	if h.lockedWrites == nil {
		h.lockedWrites = make(map[string]struct{})
	}

	for _, address := range writeAddresses {
		if _, ok := h.lockedWrites[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
		if _, ok := h.lockedReads[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for reading", address),
				"lock",
			)
		}
	}

	for _, address := range readAddresses {
		if _, ok := h.lockedWrites[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
	}

	for _, address := range writeAddresses {
		h.lockedWrites[string(address)] = struct{}{}
		h.lockedReads[string(address)] = h.lockedReads[string(address)] + 1
	}

	for _, address := range readAddresses {
		h.lockedReads[string(address)] = h.lockedReads[string(address)] + 1
	}

	return nil
}

// Unlock implements intrinsics.Intrinsic.
func (h *HypergraphIntrinsic) Unlock(
	writeAddresses [][]byte,
	readAddresses [][]byte,
) error {
	h.lockedReadsMx.Lock()
	h.lockedWritesMx.Lock()
	defer h.lockedReadsMx.Unlock()
	defer h.lockedWritesMx.Unlock()

	if h.lockedReads == nil {
		h.lockedReads = make(map[string]int)
	}

	if h.lockedWrites == nil {
		h.lockedWrites = make(map[string]struct{})
	}

	alteredWriteLocks := make(map[string]struct{})
	for k, v := range h.lockedWrites {
		alteredWriteLocks[k] = v
	}

	for _, address := range writeAddresses {
		delete(alteredWriteLocks, string(address))
	}

	for _, address := range readAddresses {
		if _, ok := alteredWriteLocks[string(address)]; ok {
			return errors.Wrap(
				fmt.Errorf("address %x is still locked for writing", address),
				"unlock",
			)
		}
	}

	for _, address := range writeAddresses {
		delete(h.lockedWrites, string(address))
		i, ok := h.lockedReads[string(address)]
		if ok {
			if i <= 1 {
				delete(h.lockedReads, string(address))
			} else {
				h.lockedReads[string(address)] = i - 1
			}
		}
	}

	for _, address := range readAddresses {
		i, ok := h.lockedReads[string(address)]
		if ok {
			if i <= 1 {
				delete(h.lockedReads, string(address))
			} else {
				h.lockedReads[string(address)] = i - 1
			}
		}
	}

	return nil
}

var _ intrinsics.Intrinsic = (*HypergraphIntrinsic)(nil)
