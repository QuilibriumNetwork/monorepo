package compute

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
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var COMPUTE_INTRINSIC_DOMAIN = [32]byte(bytes.Repeat([]byte{0xcc}, 32))

type ComputeIntrinsic struct {
	domain              [32]byte
	hypergraph          hgcrdt.Hypergraph
	inclusionProver     crypto.InclusionProver
	bulletproofProver   crypto.BulletproofProver
	verEnc              crypto.VerifiableEncryptor
	decafConstructor    crypto.DecafConstructor
	keyManager          keys.KeyManager
	lockedWrites        map[string]struct{}
	lockedReads         map[string]int
	lockedWritesMx      sync.RWMutex
	lockedReadsMx       sync.RWMutex
	config              *ComputeIntrinsicConfiguration
	consensusMetadata   *qcrypto.VectorCommitmentTree
	sumcheckInfo        *qcrypto.VectorCommitmentTree
	rdfMultiprover      *schema.RDFMultiprover
	rdfHypergraphSchema string
	state               state.State
	compiler            compiler.CircuitCompiler
}

type ComputeIntrinsicConfiguration struct {
	// The Ed448 read public key, used for confirming verifiable encryption
	ReadPublicKey []byte
	// The Ed448 write public key, used for confirming operation validity
	WritePublicKey []byte
	// The BLS48-581 public key, used for administrative purposes on the domain
	OwnerPublicKey []byte
}

// Config returns the configuration - used for testing
func (c *ComputeIntrinsic) Config() *ComputeIntrinsicConfiguration {
	return c.config
}

// GetRDFSchema implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) GetRDFSchema() (
	map[string]map[string]*schema.RDFTag,
	error,
) {
	tags, err := c.rdfMultiprover.GetSchemaMap(c.rdfHypergraphSchema)
	return tags, errors.Wrap(err, "get rdf schema")
}

// SumCheck implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) SumCheck() bool {
	return true
}

// Address implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) Address() []byte {
	return c.domain[:]
}

// Commit implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) Commit() (state.State, error) {
	// Start timing
	timer := prometheus.NewTimer(
		observability.CommitDuration.WithLabelValues("compute"),
	)
	defer timer.ObserveDuration()

	if c.state == nil {
		observability.CommitErrors.WithLabelValues("compute").Inc()
		return nil, errors.Wrap(errors.New("nothing to commit"), "commit")
	}

	err := c.state.Commit()
	if err != nil {
		observability.CommitErrors.WithLabelValues("compute").Inc()
		return c.state, errors.Wrap(err, "commit")
	}

	observability.CommitTotal.WithLabelValues("compute").Inc()
	return c.state, nil
}

func (c *ComputeIntrinsic) newComputeRDFHypergraphSchema(
	contextData []byte,
) (string, error) {
	if len(contextData) == 0 {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new compute rdf hypergraph schema",
		)
	}

	schemaDoc := string(contextData)
	data, err := c.rdfMultiprover.GetSchemaMap(schemaDoc)
	if err != nil {
		return "", errors.Wrap(err, "new compute rdf hypergraph schema")
	}

	if data == nil {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new compute rdf hypergraph schema",
		)
	}

	return schemaDoc, nil
}

// validateRDFSchemaUpdate ensures that the new schema only adds new classes and
// properties, never removing or modifying existing ones
func (c *ComputeIntrinsic) validateRDFSchemaUpdate(
	oldSchema, newSchema string,
) error {
	// Parse both schemas
	oldTags, err := c.rdfMultiprover.GetSchemaMap(oldSchema)
	if err != nil {
		return errors.Wrap(err, "validate rdf schema update")
	}

	newTags, err := c.rdfMultiprover.GetSchemaMap(newSchema)
	if err != nil {
		return errors.Wrap(err, "validate rdf schema update")
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

		// Check that all old fields in this class still exist with the same
		// properties
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
			if err := compareRDFTags(
				oldTag,
				newTag,
				className,
				fieldName,
			); err != nil {
				return errors.Wrap(err, "validate rdf schema update")
			}
		}
	}

	return nil
}

// compareRDFTags compares two RDF tags to ensure they are identical
func compareRDFTags(
	oldTag, newTag *schema.RDFTag,
	className, fieldName string,
) error {
	// Check Name
	if oldTag.Name != newTag.Name {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' name changed from '%s' to '%s'",
			className, fieldName, oldTag.Name, newTag.Name,
		))
	}

	// Check Extrinsic
	if oldTag.Extrinsic != newTag.Extrinsic {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' extrinsic changed from '%s' to '%s'",
			className, fieldName, oldTag.Extrinsic, newTag.Extrinsic,
		))
	}

	// Check Order
	if oldTag.Order != newTag.Order {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' order changed from %d to %d",
			className, fieldName, oldTag.Order, newTag.Order,
		))
	}

	// Check Size (pointer comparison)
	if (oldTag.Size == nil) != (newTag.Size == nil) {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' size presence changed",
			className, fieldName,
		))
	}
	if oldTag.Size != nil && newTag.Size != nil && *oldTag.Size != *newTag.Size {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' size changed from %d to %d",
			className, fieldName, *oldTag.Size, *newTag.Size,
		))
	}

	// Check Raw
	if oldTag.Raw != newTag.Raw {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' raw changed from '%s' to '%s'",
			className, fieldName, oldTag.Raw, newTag.Raw,
		))
	}

	// Check RdfType
	if oldTag.RdfType != newTag.RdfType {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' rdf type changed from '%s' to '%s'",
			className, fieldName, oldTag.RdfType, newTag.RdfType,
		))
	}

	// Check FieldSize
	if oldTag.FieldSize != newTag.FieldSize {
		return errors.New(fmt.Sprintf(
			"field '%s.%s' field size changed from %d to %d",
			className, fieldName, oldTag.FieldSize, newTag.FieldSize,
		))
	}

	return nil
}

func validateComputeConfiguration(
	config *ComputeIntrinsicConfiguration,
) error {
	if len(config.ReadPublicKey) != 57 || len(config.WritePublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid key"),
			"validate compute configuration",
		)
	}

	return nil
}

func newComputeConfigurationMetadata(
	config *ComputeIntrinsicConfiguration,
) (*qcrypto.VectorCommitmentTree, error) {
	if err := validateComputeConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "compute config")
	}

	tree := &qcrypto.VectorCommitmentTree{}

	// Store Read key (byte 0)
	if err := tree.Insert(
		[]byte{0 << 2},
		config.ReadPublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return nil, errors.Wrap(err, "compute config")
	}

	// Store Write key (byte 1)
	if err := tree.Insert(
		[]byte{1 << 2},
		config.WritePublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return nil, errors.Wrap(err, "compute config")
	}

	return tree, nil
}

func unpackAndVerifyComputeConfigurationMetadata(
	inclusionProver crypto.InclusionProver,
	tree *qcrypto.VectorCommitmentTree,
) (*ComputeIntrinsicConfiguration, error) {
	commitment := tree.Commit(inclusionProver, false)
	if len(commitment) == 0 {
		return nil, errors.Wrap(errors.New("invalid tree"), "unpack and verify")
	}

	// Get the configuration metadata from index 16
	computeConfigurationMetadataBytes, err := tree.Get([]byte{16 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	computeConfigurationMetadata, err := qcrypto.DeserializeNonLazyTree(
		computeConfigurationMetadataBytes,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	config := &ComputeIntrinsicConfiguration{}

	// Read Read key (byte 0)
	readKey, err := computeConfigurationMetadata.Get([]byte{0 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.ReadPublicKey = readKey

	// Read Write key (byte 1)
	writeKey, err := computeConfigurationMetadata.Get([]byte{1 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.WritePublicKey = writeKey

	if err := validateComputeConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	return config, nil
}

// Deploy implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) Deploy(
	domain [32]byte,
	provers [][]byte,
	creator []byte,
	fee *big.Int,
	contextData []byte,
	frameNumber uint64,
	hgstate state.State,
) (state.State, error) {
	if !bytes.Equal(domain[:], COMPUTE_INTRINSIC_DOMAIN[:]) {
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
		updatePb := &protobufs.ComputeUpdate{}
		err = updatePb.FromCanonicalBytes(contextData)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		deployArgs, err := ComputeUpdateFromProtobuf(updatePb)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		if err := updatePb.Validate(); err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		updateWithoutSignature := proto.Clone(updatePb).(*protobufs.ComputeUpdate)

		updateWithoutSignature.PublicKeySignatureBls48581 = nil
		message, err := updateWithoutSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		validSig, err := c.keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			c.config.OwnerPublicKey,
			message,
			updatePb.PublicKeySignatureBls48581.Signature,
			slices.Concat(domain[:], []byte("COMPUTE_UPDATE")),
		)
		if err != nil || !validSig {
			return nil, errors.Wrap(errors.New("invalid signature"), "deploy")
		}

		vertexAddress := slices.Concat(
			c.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
		)

		// Ensure the vertex is present and has not been removed
		_, err = c.hypergraph.GetVertex([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		prior, err := c.hypergraph.GetVertexData([64]byte(vertexAddress))
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		tree, err := c.hypergraph.GetVertexData([64]byte(vertexAddress))
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
			configTree, err := newComputeConfigurationMetadata(
				deployArgs.Config,
			)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			commit := configTree.Commit(c.inclusionProver, false)

			out, err := tries.SerializeNonLazyTree(configTree)
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
			_, err := c.rdfMultiprover.GetSchemaMap(newSchemaDoc)
			if err != nil {
				return nil, errors.Wrap(err, "deploy")
			}

			// Validate that the update only adds new classes/properties, never
			// removes
			if existingRDFSchema != "" {
				err = c.validateRDFSchemaUpdate(existingRDFSchema, newSchemaDoc)
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

			c.rdfHypergraphSchema = newSchemaDoc
		} else {
			// Keep the existing schema if no update is provided
			c.rdfHypergraphSchema = existingRDFSchema
		}

		err = hgstate.Set(
			c.Address(),
			hg.HYPERGRAPH_METADATA_ADDRESS,
			hg.VertexAddsDiscriminator,
			frameNumber,
			hgstate.(*hg.HypergraphState).NewVertexAddMaterializedState(
				[32]byte(c.Address()),
				[32]byte(hg.HYPERGRAPH_METADATA_ADDRESS),
				frameNumber,
				prior,
				tree,
			),
		)
		if err != nil {
			return nil, errors.Wrap(err, "deploy")
		}

		c.state = hgstate

		return hgstate, nil
	}

	// Initialize consensus metadata
	consensusMetadata := &qcrypto.VectorCommitmentTree{}

	// Initialize sumcheck info
	sumcheckInfo := &qcrypto.VectorCommitmentTree{}

	// Create additional data array with configuration
	additionalData := make([]*qcrypto.VectorCommitmentTree, 14)
	var err error
	additionalData[13], err = newComputeConfigurationMetadata(c.config)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	// Generate compute domain - include config commitment in domain generation
	computeDomainBI, err := poseidon.HashBytes(
		slices.Concat(
			COMPUTE_INTRINSIC_DOMAIN[:],
			additionalData[13].Commit(c.hypergraph.GetProver(), false),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	computeDomain := computeDomainBI.FillBytes(make([]byte, 32))

	rdfHypergraphSchema, err := c.newComputeRDFHypergraphSchema(contextData)
	if err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	// Initialize the state
	if err := hgstate.Init(
		computeDomain,
		consensusMetadata,
		sumcheckInfo,
		rdfHypergraphSchema,
		additionalData,
		COMPUTE_INTRINSIC_DOMAIN[:],
	); err != nil {
		return nil, errors.Wrap(err, "deploy")
	}

	c.state = hgstate

	copy(c.domain[:], computeDomain)
	c.consensusMetadata = consensusMetadata
	c.sumcheckInfo = sumcheckInfo
	c.rdfHypergraphSchema = rdfHypergraphSchema

	return c.state, nil
}

// Validate implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) Validate(
	frameNumber uint64,
	input []byte,
) error {
	timer := prometheus.NewTimer(
		observability.ValidateDuration.WithLabelValues("compute"),
	)
	defer timer.ObserveDuration()

	// Check the type prefix to determine operation type
	if len(input) < 4 {
		observability.ValidateErrors.WithLabelValues(
			"compute",
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
	case protobufs.CodeDeploymentType:
		codeDeployment := &CodeDeployment{}
		if err := codeDeployment.FromBytes(input, c.compiler); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the code deployment
		valid, err := codeDeployment.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return errors.Wrap(errors.New("invalid code deployment"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()
		return nil

	case protobufs.CodeExecuteType:
		codeExecute := &CodeExecute{}
		if err := codeExecute.FromBytes(
			input,
			c.hypergraph,
			c.bulletproofProver,
			c.inclusionProver,
			c.verEnc,
			c.decafConstructor,
			c.keyManager,
			c.rdfMultiprover,
		); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the code execution
		valid, err := codeExecute.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return errors.Wrap(errors.New("invalid code execute"), "validate")
		}

		observability.ValidateTotal.WithLabelValues("compute", "code_execute").Inc()
		return nil

	case protobufs.CodeFinalizeType:
		codeFinalize := &CodeFinalize{}
		if err := codeFinalize.FromBytes(
			input,
			c.domain,
			c.hypergraph,
			c.bulletproofProver,
			c.inclusionProver,
			c.verEnc,
			c.keyManager,
			c.config,
			nil,
		); err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		// Validate the code finalization
		valid, err := codeFinalize.Verify(frameNumber)
		if err != nil {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return errors.Wrap(err, "validate")
		}

		if !valid {
			observability.ValidateErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return errors.Wrap(errors.New("invalid code finalize"), "validate")
		}

		observability.ValidateTotal.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()
		return nil

	default:
		observability.ValidateErrors.WithLabelValues(
			"compute",
			"unknown_type",
		).Inc()
		return errors.Wrap(
			fmt.Errorf("unknown compute operation type: %d", typePrefix),
			"validate",
		)
	}
}

// InvokeStep implements intrinsics.Intrinsic.
func (c *ComputeIntrinsic) InvokeStep(
	frameNumber uint64,
	input []byte,
	feePaid *big.Int,
	feeMultiplier *big.Int,
	state state.State,
) (state.State, error) {
	// Start timing
	timer := prometheus.NewTimer(
		observability.InvokeStepDuration.WithLabelValues("compute"),
	)
	defer timer.ObserveDuration()

	// Check the type prefix to determine operation type
	if len(input) < 4 {
		observability.InvokeStepTotal.WithLabelValues(
			"compute",
			"invoke_step",
			"error",
		).Inc()
		return nil, errors.Wrap(
			errors.New("input too short to determine type"),
			"invoke step",
		)
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	switch typePrefix {
	case protobufs.CodeDeploymentType: // CodeDeployment
		operationTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"compute",
				"code_deployment",
			),
		)
		defer operationTimer.ObserveDuration()
		observability.OperationCount.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()

		var codeDeployment CodeDeployment
		if err := codeDeployment.FromBytes(input, c.compiler); err != nil {
			observability.InvokeStepTotal.WithLabelValues(
				"compute",
				"code_deployment",
				"error",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Verify the code deployment
		valid, err := codeDeployment.Verify(frameNumber)
		if err != nil {
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepTotal.WithLabelValues(
				"compute",
				"code_deployment",
				"error",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid code deployment"),
				"invoke step",
			)
		}

		// Get cost of the operation
		cost, err := codeDeployment.GetCost()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Check if fee is sufficient
		if feePaid.Cmp(new(big.Int).Mul(cost, feeMultiplier)) < 0 {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return nil, errors.Wrap(
				fmt.Errorf(
					"insufficient fee: %s < %s",
					feePaid,
					new(big.Int).Mul(cost, feeMultiplier),
				),
				"invoke step",
			)
		}

		// Materialize the state
		materializeTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("compute"),
		)
		// Use c.state if state parameter is nil
		stateToUse := state
		if stateToUse == nil {
			stateToUse = c.state
		}
		c.state, err = codeDeployment.Materialize(frameNumber, stateToUse)
		materializeTimer.ObserveDuration()
		if err != nil {
			observability.MaterializeTotal.WithLabelValues(
				"compute",
				"error",
			).Inc()
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_deployment",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		observability.MaterializeTotal.WithLabelValues("compute", "success").Inc()

		observability.InvokeStepTotal.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()
		return c.state, nil

	case protobufs.CodeExecuteType: // CodeExecute
		operationTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"compute",
				"code_execute",
			),
		)
		defer operationTimer.ObserveDuration()
		observability.OperationCount.WithLabelValues(
			"compute",
			"code_execute",
		).Inc()

		var codeExecute CodeExecute
		if err := codeExecute.FromBytes(
			input,
			c.hypergraph,
			c.bulletproofProver,
			c.inclusionProver,
			c.verEnc,
			c.decafConstructor,
			c.keyManager,
			c.rdfMultiprover,
		); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Verify the code execution
		valid, err := codeExecute.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid code execution"),
				"invoke step",
			)
		}

		// Get cost of the operation
		cost, err := codeExecute.GetCost()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Check if fee is sufficient
		if feePaid.Cmp(new(big.Int).Mul(cost, feeMultiplier)) < 0 {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(
				fmt.Errorf(
					"insufficient fee: %s < %s",
					feePaid,
					new(big.Int).Mul(cost, feeMultiplier),
				),
				"invoke step",
			)
		}

		// Materialize the state
		materializeTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("compute"),
		)
		// Use c.state if state parameter is nil
		stateToUse := state
		if stateToUse == nil {
			stateToUse = c.state
		}
		c.state, err = codeExecute.Materialize(frameNumber, stateToUse)
		materializeTimer.ObserveDuration()
		if err != nil {
			observability.MaterializeTotal.WithLabelValues("compute", "error").Inc()
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_execute",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		observability.MaterializeTotal.WithLabelValues("compute", "success").Inc()

		observability.InvokeStepTotal.WithLabelValues(
			"compute",
			"code_execute",
		).Inc()
		return c.state, nil

	case protobufs.CodeFinalizeType: // CodeFinalize
		operationTimer := prometheus.NewTimer(
			observability.OperationDuration.WithLabelValues(
				"compute",
				"code_finalize",
			),
		)
		defer operationTimer.ObserveDuration()
		observability.OperationCount.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()

		var codeFinalize CodeFinalize
		if err := codeFinalize.FromBytes(
			input,
			c.domain,
			c.hypergraph,
			c.bulletproofProver,
			c.inclusionProver,
			c.verEnc,
			c.keyManager,
			c.config,
			nil,
		); err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Verify the finalization
		valid, err := codeFinalize.Verify(frameNumber)
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		if !valid {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(
				errors.New("invalid code finalization"),
				"invoke step",
			)
		}

		// Get cost of the operation
		cost, err := codeFinalize.GetCost()
		if err != nil {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}

		// Check if fee is sufficient
		if feePaid.Cmp(new(big.Int).Mul(cost, feeMultiplier)) < 0 {
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(
				fmt.Errorf(
					"insufficient fee: %s < %s",
					feePaid,
					new(big.Int).Mul(cost, feeMultiplier),
				),
				"invoke step",
			)
		}

		// Materialize the state
		materializeTimer := prometheus.NewTimer(
			observability.MaterializeDuration.WithLabelValues("compute"),
		)
		// Use c.state if state parameter is nil
		stateToUse := state
		if stateToUse == nil {
			stateToUse = c.state
		}
		c.state, err = codeFinalize.Materialize(frameNumber, stateToUse)
		materializeTimer.ObserveDuration()
		if err != nil {
			observability.MaterializeTotal.WithLabelValues("compute", "error").Inc()
			observability.InvokeStepErrors.WithLabelValues(
				"compute",
				"code_finalize",
			).Inc()
			return nil, errors.Wrap(err, "invoke step")
		}
		observability.MaterializeTotal.WithLabelValues("compute", "success").Inc()

		observability.InvokeStepTotal.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()
		return c.state, nil

	default:
		observability.InvokeStepErrors.WithLabelValues(
			"compute",
			"unknown",
		).Inc()
		return nil, errors.Wrap(
			fmt.Errorf("unknown operation type: %d", typePrefix),
			"invoke step",
		)
	}
}

// Lock implements intrinsics.Intrinsic.
func (a *ComputeIntrinsic) Lock(
	frameNumber uint64,
	input []byte,
) ([][]byte, error) {
	a.lockedReadsMx.Lock()
	a.lockedWritesMx.Lock()
	defer a.lockedReadsMx.Unlock()
	defer a.lockedWritesMx.Unlock()

	if a.lockedReads == nil {
		a.lockedReads = make(map[string]int)
	}

	if a.lockedWrites == nil {
		a.lockedWrites = make(map[string]struct{})
	}

	// Check type prefix to determine request type
	if len(input) < 4 {
		observability.LockErrors.WithLabelValues(
			"compute",
			"invalid_input",
		).Inc()
		return nil, errors.Wrap(errors.New("input too short"), "lock")
	}

	// Read the type prefix
	typePrefix := binary.BigEndian.Uint32(input[:4])

	var reads, writes [][]byte
	var err error

	// Handle each type based on type prefix
	switch typePrefix {
	case protobufs.CodeDeploymentType:
		reads, writes, err = a.tryLockCodeDeployment(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()

	case protobufs.CodeExecuteType:
		reads, writes, err = a.tryLockCodeExecute(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues("compute", "code_execute").Inc()

	case protobufs.CodeFinalizeType:
		reads, writes, err = a.tryLockCodeFinalize(frameNumber, input)
		if err != nil {
			return nil, err
		}

		observability.LockTotal.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()

	default:
		observability.LockErrors.WithLabelValues(
			"compute",
			"unknown_type",
		).Inc()
		return nil, errors.Wrap(
			errors.New("unknown compute request type"),
			"lock",
		)
	}

	for _, address := range writes {
		if _, ok := a.lockedWrites[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
		if _, ok := a.lockedReads[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for reading", address),
				"lock",
			)
		}
	}

	for _, address := range reads {
		if _, ok := a.lockedWrites[string(address)]; ok {
			return nil, errors.Wrap(
				fmt.Errorf("address %x is already locked for writing", address),
				"lock",
			)
		}
	}

	set := map[string]struct{}{}

	for _, address := range writes {
		a.lockedWrites[string(address)] = struct{}{}
		a.lockedReads[string(address)] = a.lockedReads[string(address)] + 1
		set[string(address)] = struct{}{}
	}

	for _, address := range reads {
		a.lockedReads[string(address)] = a.lockedReads[string(address)] + 1
		set[string(address)] = struct{}{}
	}

	result := [][]byte{}
	for a := range set {
		result = append(result, []byte(a))
	}

	return result, nil
}

// Unlock implements intrinsics.Intrinsic.
func (a *ComputeIntrinsic) Unlock() error {
	a.lockedReadsMx.Lock()
	a.lockedWritesMx.Lock()
	defer a.lockedReadsMx.Unlock()
	defer a.lockedWritesMx.Unlock()

	a.lockedReads = make(map[string]int)
	a.lockedWrites = make(map[string]struct{})

	return nil
}

// NewComputeIntrinsic creates a new compute intrinsic instance
func NewComputeIntrinsic(
	config *ComputeIntrinsicConfiguration,
	hypergraph hgcrdt.Hypergraph,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyManager keys.KeyManager,
	compiler compiler.CircuitCompiler,
) (*ComputeIntrinsic, error) {
	return &ComputeIntrinsic{
		config:            config,
		hypergraph:        hypergraph,
		inclusionProver:   inclusionProver,
		bulletproofProver: bulletproofProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		keyManager:        keyManager,
		compiler:          compiler,
		lockedWrites:      make(map[string]struct{}),
		lockedReads:       make(map[string]int),
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			inclusionProver,
		),
		state: nil,
	}, nil
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

// LoadComputeIntrinsic loads an existing compute intrinsic from hypergraph
// state
func LoadComputeIntrinsic(
	appAddress []byte,
	hypergraph hgcrdt.Hypergraph,
	state state.State,
	inclusionProver crypto.InclusionProver,
	bulletproofProver crypto.BulletproofProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyManager keys.KeyManager,
	compiler compiler.CircuitCompiler,
) (*ComputeIntrinsic, error) {
	vertexAddress := slices.Concat(
		appAddress,
		hg.HYPERGRAPH_METADATA_ADDRESS,
	)

	hgState := state.(*hg.HypergraphState)

	// Ensure the vertex is present and has not been removed
	data, err := hgState.Get(
		vertexAddress[:32],
		vertexAddress[32:],
		hg.VertexAddsDiscriminator,
	)
	if err != nil {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	tree, ok := data.(*tries.VectorCommitmentTree)
	if !ok {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	config, err := unpackAndVerifyComputeConfigurationMetadata(
		inclusionProver,
		tree,
	)
	if err != nil {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	consensusMetadata, err := hg.UnpackConsensusMetadata(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	sumcheckInfo, err := hg.UnpackSumcheckInfo(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	rdfHypergraphSchema, err := unpackAndVerifyRdfHypergraphSchema(tree)
	if err != nil {
		return nil, errors.Wrap(err, "load compute intrinsic")
	}

	return &ComputeIntrinsic{
		domain:              [32]byte(appAddress),
		hypergraph:          hypergraph,
		inclusionProver:     inclusionProver,
		bulletproofProver:   bulletproofProver,
		verEnc:              verEnc,
		decafConstructor:    decafConstructor,
		config:              config,
		compiler:            compiler,
		lockedWrites:        make(map[string]struct{}),
		lockedReads:         make(map[string]int),
		consensusMetadata:   consensusMetadata,
		sumcheckInfo:        sumcheckInfo,
		state:               hg.NewHypergraphState(hypergraph),
		keyManager:          keyManager,
		rdfHypergraphSchema: rdfHypergraphSchema,
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			inclusionProver,
		),
	}, nil
}

// ComputeDeploy represents the arguments for deploying a compute intrinsic
type ComputeDeploy struct {
	Config    *ComputeIntrinsicConfiguration
	RDFSchema []byte
}

// ComputeUpdate represents the arguments for updating a compute intrinsic
type ComputeUpdate struct {
	Config         *ComputeIntrinsicConfiguration
	RDFSchema      []byte
	OwnerSignature *protobufs.BLS48581AggregateSignature
}

func (c *ComputeIntrinsic) tryLockCodeDeployment(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	codeDeployment := &CodeDeployment{}
	if err := codeDeployment.FromBytes(input, c.compiler); err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := codeDeployment.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := codeDeployment.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_deployment",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

func (c *ComputeIntrinsic) tryLockCodeExecute(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	codeExecute := &CodeExecute{}
	if err := codeExecute.FromBytes(
		input,
		c.hypergraph,
		c.bulletproofProver,
		c.inclusionProver,
		c.verEnc,
		c.decafConstructor,
		c.keyManager,
		c.rdfMultiprover,
	); err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_execute",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := codeExecute.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_execute",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := codeExecute.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_execute",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

func (c *ComputeIntrinsic) tryLockCodeFinalize(
	frameNumber uint64,
	input []byte,
) (
	[][]byte,
	[][]byte,
	error,
) {
	codeFinalize := &CodeFinalize{}
	if err := codeFinalize.FromBytes(
		input,
		c.domain,
		c.hypergraph,
		c.bulletproofProver,
		c.inclusionProver,
		c.verEnc,
		c.keyManager,
		c.config,
		nil,
	); err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	reads, err := codeFinalize.GetReadAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	writes, err := codeFinalize.GetWriteAddresses(frameNumber)
	if err != nil {
		observability.LockErrors.WithLabelValues(
			"compute",
			"code_finalize",
		).Inc()
		return nil, nil, errors.Wrap(err, "lock")
	}

	return reads, writes, nil
}

var _ intrinsics.Intrinsic = (*ComputeIntrinsic)(nil)
