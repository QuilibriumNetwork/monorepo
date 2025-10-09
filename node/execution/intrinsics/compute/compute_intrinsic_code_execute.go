package compute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"

	"github.com/pkg/errors"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

const MaxOperationsLimit = 100

type ExecutionContext uint8

const (
	ExecutionContextIntrinsic ExecutionContext = iota
	ExecutionContextHypergraph
	ExecutionContextExtrinsic
)

type Application struct {
	Address          []byte
	ExecutionContext ExecutionContext
}

type ExecutionDependency struct {
	Identifier []byte
	ReadSet    [][]byte // Addresses read by this operation
	WriteSet   [][]byte // Addresses written by this operation
	Stage      uint32   // Execution stage after DAG analysis
}

type ExecuteOperation struct {
	Application  Application
	Identifier   []byte
	Dependencies [][]byte
}

// ExecutionDAG represents the directed acyclic graph of execution operations
type ExecutionDAG struct {
	Operations map[string]*ExecutionNode
	Stages     [][]string // Operations grouped by execution stage
}

// ExecutionNode represents a node in the execution DAG
type ExecutionNode struct {
	Operation    *ExecuteOperation
	Dependencies map[string]*ExecutionNode
	Dependents   map[string]*ExecutionNode
	Stage        uint32
	Visited      bool
	InProgress   bool
	// TODO(2.2): reserved for multiphasic locking
	ReadSet  [][]byte
	WriteSet [][]byte
}

type CodeExecute struct {
	ProofOfPayment    [2][]byte
	Domain            [32]byte
	Rendezvous        [32]byte
	ExecuteOperations []*ExecuteOperation

	hypergraph        hypergraph.Hypergraph
	bulletproofProver crypto.BulletproofProver
	inclusionProver   crypto.InclusionProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	keyManager        keys.KeyManager
	rdfMultiprover    *schema.RDFMultiprover
	payerPublicKey    []byte
	secretKey         []byte
}

func NewCodeExecute(
	domain [32]byte,
	payerPublicKey []byte,
	secretKey []byte,
	rendezvous [32]byte,
	operations []*ExecuteOperation,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyManager keys.KeyManager,
) *CodeExecute {
	return &CodeExecute{
		Domain:            domain,
		ProofOfPayment:    [2][]byte{},
		Rendezvous:        rendezvous,
		ExecuteOperations: operations,
		hypergraph:        hypergraph,
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		keyManager:        keyManager,
		payerPublicKey:    payerPublicKey,
		secretKey:         secretKey,
		rdfMultiprover: schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			inclusionProver,
		),
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (c *CodeExecute) GetCost() (*big.Int, error) {
	totalCost := int64(0)

	for _, op := range c.ExecuteOperations {
		switch op.Application.ExecutionContext {
		case ExecutionContextIntrinsic:
			// Map specific intrinsic addresses to their costs
			addressCost := map[string]int64{
				"00010101": 4736, // KZG_VERIFY_BLS48581
				"00010201": 7168, // BULLETPROOF_RANGE_VERIFY_DECAF448
				"00010301": 64,   // BULLETPROOF_SUM_VERIFY_DECAF448
				"00010401": 64,   // SECP256K1_ECDSA_VERIFY
				"00010501": 64,   // ED25519_EDDSA_VERIFY
				"00010601": 114,  // ED448_EDDSA_VERIFY
				"00010701": 112,  // DECAF448_SCHNORR_VERIFY
				"00010801": 64,   // SECP256R1_ECDSA_VERIFY
			}

			// Convert address to hex string for lookup
			if len(op.Application.Address) >= 4 {
				addressHex := fmt.Sprintf(
					"%08X",
					binary.BigEndian.Uint32(op.Application.Address[:4]),
				)
				cost, ok := addressCost[addressHex]
				if !ok {
					return nil, errors.Wrap(
						errors.Errorf(
							"unknown intrinsic address: %x",
							op.Application.Address,
						),
						"get cost",
					)
				}
				totalCost += cost
			} else {
				return nil, errors.Wrap(
					errors.New("invalid intrinsic address length"),
					"get cost",
				)
			}

		case ExecutionContextHypergraph:
			// Check if address matches one of the hypergraph discriminators
			if bytes.Equal(op.Application.Address, hg.VertexAddsDiscriminator) ||
				bytes.Equal(op.Application.Address, hg.VertexRemovesDiscriminator) ||
				bytes.Equal(op.Application.Address, hg.HyperedgeAddsDiscriminator) ||
				bytes.Equal(op.Application.Address, hg.HyperedgeRemovesDiscriminator) {
				totalCost += 32
			} else {
				return nil, errors.Wrap(
					errors.Errorf(
						"unknown hypergraph address: %x",
						op.Application.Address,
					),
					"get cost",
				)
			}

		case ExecutionContextExtrinsic:
			// Fetch the circuit data from the deployed code
			if len(op.Application.Address) != 32 {
				return nil, errors.Wrap(
					errors.New("invalid extrinsic address length"),
					"get cost",
				)
			}

			// Construct the 64-byte key: domain (32 bytes) + address (32 bytes)
			key := [64]byte{}
			copy(key[:32], c.Domain[:])
			copy(key[32:], op.Application.Address)

			// Fetch the deployed circuit data
			circuitData, err := c.hypergraph.GetVertexData(key)
			if err != nil {
				return nil, errors.Wrap(err, "get cost")
			}

			// Add the size of the circuit data to the cost
			if circuitData != nil {
				// Get the circuit bytes from the VectorCommitmentTree
				circuitBytes, err := circuitData.Get([]byte{0 << 2})
				if err != nil {
					return nil, errors.Wrap(err, "get cost")
				}
				if len(circuitBytes) > 0 {
					totalCost += int64(len(circuitBytes))
				}
			}

		default:
			return nil, errors.Wrap(
				errors.Errorf(
					"unknown execution context: %v",
					op.Application.ExecutionContext,
				),
				"get cost",
			)
		}
	}

	return big.NewInt(totalCost), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (c *CodeExecute) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraph, ok := state.(*hg.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state type"), "materialize")
	}

	// Build and validate the execution DAG
	dag, err := c.buildExecutionDAG()
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Create a tree to store the execution data
	execTree := &qcrypto.VectorCommitmentTree{}

	// Store the rendezvous at index 0
	if err := execTree.Insert(
		[]byte{0 << 2}, // Index 0
		c.Rendezvous[:],
		nil,
		big.NewInt(32),
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store the DAG structure at index 1
	dagBytes, err := c.serializeDAG(dag)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	if err := execTree.Insert(
		[]byte{1 << 2}, // Index 1
		dagBytes,
		nil,
		big.NewInt(int64(len(dagBytes))),
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store execution stages at index 2
	stagesBytes, err := c.serializeStages(dag)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	if err := execTree.Insert(
		[]byte{2 << 2}, // Index 2
		stagesBytes,
		nil,
		big.NewInt(int64(len(stagesBytes))),
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store operation details starting at index 3
	for i, op := range c.ExecuteOperations {
		opBytes, err := c.serializeOperation(op, dag)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
		if err := execTree.Insert(
			[]byte{byte((i + 3) << 2)}, // Index 3+
			opBytes,
			nil,
			big.NewInt(int64(len(opBytes))),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	// Create results state
	value := hypergraph.NewVertexAddMaterializedState(
		c.Domain,
		c.Rendezvous,
		frameNumber,
		nil,
		execTree,
	)

	// Store results
	err = hypergraph.Set(
		c.Domain[:],
		c.Rendezvous[:],
		hg.VertexAddsDiscriminator,
		frameNumber,
		value,
	)

	return hypergraph, nil
}

// Prove implements intrinsics.IntrinsicOperation.
func (c *CodeExecute) Prove(frameNumber uint64) error {
	if bytes.Equal(c.payerPublicKey, make([]byte, 56)) {
		return nil
	}

	// For alt fee basis:
	c.ProofOfPayment[0] = c.payerPublicKey
	c.ProofOfPayment[1] = c.bulletproofProver.SimpleSign(
		c.secretKey,
		c.Rendezvous[:],
	)

	return nil
}

func (c *CodeExecute) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (c *CodeExecute) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return [][]byte{slices.Concat(
		c.Domain[:],
		c.Rendezvous[:],
	)}, nil
}

// Verify implements intrinsics.IntrinsicOperation.
func (c *CodeExecute) Verify(frameNumber uint64) (bool, error) {
	if !bytes.Equal(c.ProofOfPayment[0], make([]byte, 56)) {
		if !c.bulletproofProver.SimpleVerify(
			c.Rendezvous[:],
			c.ProofOfPayment[1],
			c.ProofOfPayment[0],
		) {
			return false, errors.Wrap(
				errors.New("invalid signature"),
				"verify",
			)
		}
	}

	_, err := c.buildExecutionDAG()
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	return true, nil
}

// buildExecutionDAG constructs and validates the execution DAG from operations
func (c *CodeExecute) buildExecutionDAG() (*ExecutionDAG, error) {
	// Validate that we have at least one operation
	if len(c.ExecuteOperations) == 0 {
		return nil, errors.New("empty operations list")
	}

	// Validate operations count limit
	if len(c.ExecuteOperations) > MaxOperationsLimit {
		return nil, errors.Errorf(
			"operations count %d exceeds limit %d",
			len(c.ExecuteOperations),
			MaxOperationsLimit,
		)
	}

	dag := &ExecutionDAG{
		Operations: make(map[string]*ExecutionNode),
		Stages:     [][]string{},
	}

	// First pass: create nodes for all operations
	for _, op := range c.ExecuteOperations {
		idStr := string(op.Identifier)
		if _, exists := dag.Operations[idStr]; exists {
			return nil, errors.New("duplicate operation identifier")
		}

		dag.Operations[idStr] = &ExecutionNode{
			Operation:    op,
			Dependencies: make(map[string]*ExecutionNode),
			Dependents:   make(map[string]*ExecutionNode),
			Stage:        0,
			Visited:      false,
			InProgress:   false,
		}
	}

	// Second pass: build dependency relationships
	for _, op := range c.ExecuteOperations {
		idStr := string(op.Identifier)
		node := dag.Operations[idStr]

		for _, depID := range op.Dependencies {
			depStr := string(depID)
			depNode, exists := dag.Operations[depStr]
			if !exists {
				return nil, errors.Errorf(
					"dependency %x not found for operation %x",
					depID,
					op.Identifier,
				)
			}

			// Add bidirectional dependency links
			node.Dependencies[depStr] = depNode
			depNode.Dependents[idStr] = node
		}
	}

	// Validate DAG (check for cycles)
	if err := dag.validateNoCycles(); err != nil {
		return nil, errors.Wrap(err, "invalid DAG")
	}

	// Compute execution stages
	if err := dag.computeStages(); err != nil {
		return nil, errors.Wrap(err, "failed to compute stages")
	}

	// Analyze conflicts and optimize stages for parallel execution
	if err := dag.analyzeConflicts(c); err != nil {
		return nil, errors.Wrap(err, "failed to analyze conflicts")
	}

	return dag, nil
}

// validateNoCycles performs DFS to detect cycles in the DAG
func (dag *ExecutionDAG) validateNoCycles() error {
	// Use a separate visited map for cycle detection
	visited := make(map[string]bool)

	for id, node := range dag.Operations {
		if err := dag.detectCycle(
			node, visited, make(map[string]bool),
		); err != nil {
			return errors.Errorf("cycle detected involving operation %s", id)
		}
	}
	return nil
}

// detectCycle uses DFS with a recursion stack to detect cycles
func (dag *ExecutionDAG) detectCycle(
	node *ExecutionNode,
	visited map[string]bool,
	recStack map[string]bool,
) error {
	idStr := string(node.Operation.Identifier)

	if recStack[idStr] {
		return errors.New("cycle detected")
	}

	if visited[idStr] {
		return nil
	}

	visited[idStr] = true
	recStack[idStr] = true

	for _, dep := range node.Dependencies {
		if err := dag.detectCycle(dep, visited, recStack); err != nil {
			return err
		}
	}

	recStack[idStr] = false
	return nil
}

// computeStages assigns execution stages using topological sort
func (dag *ExecutionDAG) computeStages() error {
	// Reset visited flags
	for _, node := range dag.Operations {
		node.Visited = false
	}

	// Find all nodes with no dependencies (stage 0)
	var currentStage []string
	for id, node := range dag.Operations {
		if len(node.Dependencies) == 0 {
			node.Stage = 0
			currentStage = append(currentStage, id)
		}
	}

	if len(currentStage) == 0 && len(dag.Operations) > 0 {
		return errors.New("no operations without dependencies found")
	}

	stage := uint32(0)
	processedCount := 0

	// Process stages
	for len(currentStage) > 0 {
		dag.Stages = append(dag.Stages, currentStage)
		processedCount += len(currentStage)

		// Mark all nodes in current stage as visited first
		for _, id := range currentStage {
			dag.Operations[id].Visited = true
		}

		nextStage := []string{}
		for _, id := range currentStage {
			node := dag.Operations[id]

			// Check all dependents
			for depID, dependent := range node.Dependents {
				// Skip if already scheduled
				if dependent.Visited {
					continue
				}

				// Check if all dependencies of this dependent are processed
				allDepsProcessed := true
				maxDepStage := uint32(0)

				for _, dep := range dependent.Dependencies {
					if !dep.Visited {
						allDepsProcessed = false
						break
					}
					if dep.Stage > maxDepStage {
						maxDepStage = dep.Stage
					}
				}

				if allDepsProcessed {
					dependent.Stage = maxDepStage + 1
					// Check if not already in nextStage to avoid duplicates
					inNextStage := false
					for _, id := range nextStage {
						if id == depID {
							inNextStage = true
							break
						}
					}
					if !inNextStage {
						nextStage = append(nextStage, depID)
					}
				}
			}
		}

		currentStage = nextStage
		stage++
	}
	if processedCount != len(dag.Operations) {
		return errors.New(
			"not all operations were processed - possible disconnected graph",
		)
	}

	return nil
}

// analyzeConflicts detects read/write conflicts and optimizes stage assignment
func (dag *ExecutionDAG) analyzeConflicts(c *CodeExecute) error {
	// First, populate read/write sets for each operation
	for _, node := range dag.Operations {
		if err := node.extractAccessSets(c); err != nil {
			return errors.Wrap(err, "failed to extract access sets")
		}
	}

	// Re-optimize stages considering conflicts
	return dag.optimizeStagesWithConflicts()
}

// extractAccessSets determines the read and write sets for an operation
func (node *ExecutionNode) extractAccessSets(c *CodeExecute) error {
	// Initialize empty sets
	node.ReadSet = [][]byte{}
	node.WriteSet = [][]byte{}

	// Based on execution context, determine access patterns
	// TODO(2.2): Multiphasic locking
	switch node.Operation.Application.ExecutionContext {
	case ExecutionContextIntrinsic:
		// For intrinsic operations, analyze based on the specific application
		return node.extractIntrinsicAccessSets(c)

	case ExecutionContextHypergraph:
		// Hypergraph operations directly manipulate hypergraph state
		return node.extractHypergraphAccessSets(c)

	case ExecutionContextExtrinsic:
		// For deployed code, analyze the circuit's access patterns
		return node.extractExtrinsicAccessSets(c)

	default:
		return errors.New("unknown execution context")
	}
}

// extractIntrinsicAccessSets handles access patterns for intrinsic operations
func (node *ExecutionNode) extractIntrinsicAccessSets(c *CodeExecute) error {
	// TODO(2.2): Multiphasic locking

	return nil
}

// extractHypergraphAccessSets handles access patterns for hypergraph operations
func (node *ExecutionNode) extractHypergraphAccessSets(c *CodeExecute) error {
	// TODO(2.2): Multiphasic locking will add more conditions

	// Hypergraph operations directly manipulate graph structure
	// They may:
	// - Add vertices (write to new addresses)
	// - Add hyperedges (write to relationship addresses)
	// - Query vertices/hyperedges (read from addresses)

	// The operation address indicates the target of the hypergraph operation
	targetAddress := node.Operation.Application.Address

	// For hypergraph operations, we need to consider:
	// 1. The target vertex/hyperedge being operated on
	// 2. Any related vertices that might be affected

	// Conservative approach: assume both read and write
	node.ReadSet = append(node.ReadSet, targetAddress)
	node.WriteSet = append(node.WriteSet, targetAddress)

	return nil
}

// extractExtrinsicAccessSets handles access patterns for deployed code
func (node *ExecutionNode) extractExtrinsicAccessSets(c *CodeExecute) error {
	// TODO(2.2): Multiphasic locking for MetaVM
	codeAddress := node.Operation.Application.Address

	node.ReadSet = append(node.ReadSet, codeAddress)

	return nil
}

// optimizeStagesWithConflicts re-assigns stages considering conflicts
func (dag *ExecutionDAG) optimizeStagesWithConflicts() error {
	// Create a new stage assignment that respects both dependencies and conflicts
	newStages := [][]string{}
	processed := make(map[string]bool)

	// Helper function to check if two operations conflict
	hasConflict := func(node1, node2 *ExecutionNode) bool {
		// Check write-write conflicts
		for _, addr1 := range node1.WriteSet {
			for _, addr2 := range node2.WriteSet {
				if bytes.Equal(addr1, addr2) {
					return true
				}
			}
		}

		// Check read-write conflicts
		for _, addr1 := range node1.ReadSet {
			for _, addr2 := range node2.WriteSet {
				if bytes.Equal(addr1, addr2) {
					return true
				}
			}
		}

		// Check write-read conflicts
		for _, addr1 := range node1.WriteSet {
			for _, addr2 := range node2.ReadSet {
				if bytes.Equal(addr1, addr2) {
					return true
				}
			}
		}

		return false
	}

	// Process operations stage by stage
	for stageNum := uint32(0); stageNum < uint32(len(dag.Stages)); stageNum++ {
		currentStageOps := []string{}

		// Find all operations that can be executed at this stage
		for id, node := range dag.Operations {
			if processed[id] {
				continue
			}

			// Check if all dependencies are satisfied
			canExecute := true
			for _, dep := range node.Dependencies {
				if !processed[string(dep.Operation.Identifier)] {
					canExecute = false
					break
				}
			}

			if !canExecute {
				continue
			}

			// Check for conflicts with operations already in current stage
			hasConflictInStage := false
			for _, existingOpID := range currentStageOps {
				existingNode := dag.Operations[existingOpID]
				if hasConflict(node, existingNode) {
					hasConflictInStage = true
					break
				}
			}

			if !hasConflictInStage {
				currentStageOps = append(currentStageOps, id)
				node.Stage = stageNum
			}
		}

		if len(currentStageOps) > 0 {
			newStages = append(newStages, currentStageOps)
			for _, id := range currentStageOps {
				processed[id] = true
			}
		}
	}

	// Verify all operations were processed
	if len(processed) != len(dag.Operations) {
		// Some operations couldn't be scheduled due to conflicts
		// Add remaining operations in individual stages
		for id, node := range dag.Operations {
			if !processed[id] {
				node.Stage = uint32(len(newStages))
				newStages = append(newStages, []string{id})
				processed[id] = true
			}
		}
	}

	dag.Stages = newStages
	return nil
}

// serializeDAG converts the DAG structure to bytes for storage
func (c *CodeExecute) serializeDAG(dag *ExecutionDAG) ([]byte, error) {
	// Simple serialization: encode number of operations and their relationships
	var buf bytes.Buffer

	// Write number of operations
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(dag.Operations)),
	); err != nil {
		return nil, err
	}

	// Write each operation's dependencies
	for id, node := range dag.Operations {
		// Write operation ID length and ID
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(id)),
		); err != nil {
			return nil, err
		}
		buf.Write([]byte(id))

		// Write number of dependencies
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(node.Dependencies)),
		); err != nil {
			return nil, err
		}

		// Write each dependency ID
		for depID := range node.Dependencies {
			if err := binary.Write(
				&buf,
				binary.BigEndian,
				uint32(len(depID)),
			); err != nil {
				return nil, err
			}
			buf.Write([]byte(depID))
		}
	}

	return buf.Bytes(), nil
}

// serializeStages converts the execution stages to bytes for storage
func (c *CodeExecute) serializeStages(dag *ExecutionDAG) ([]byte, error) {
	var buf bytes.Buffer

	// Write number of stages
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(dag.Stages)),
	); err != nil {
		return nil, err
	}

	// Write each stage
	for _, stage := range dag.Stages {
		// Write number of operations in stage
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(stage)),
		); err != nil {
			return nil, err
		}

		// Write each operation ID in stage
		for _, opID := range stage {
			if err := binary.Write(
				&buf,
				binary.BigEndian,
				uint32(len(opID)),
			); err != nil {
				return nil, err
			}
			buf.Write([]byte(opID))
		}
	}

	return buf.Bytes(), nil
}

// serializeOperation converts an operation and its metadata to bytes for
// storage
func (c *CodeExecute) serializeOperation(
	op *ExecuteOperation,
	dag *ExecutionDAG,
) ([]byte, error) {
	var buf bytes.Buffer

	// Write application address
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(op.Application.Address)),
	); err != nil {
		return nil, err
	}
	buf.Write(op.Application.Address)

	// Write execution context
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint8(op.Application.ExecutionContext),
	); err != nil {
		return nil, err
	}

	// Write operation identifier
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(op.Identifier)),
	); err != nil {
		return nil, err
	}
	buf.Write(op.Identifier)

	// Get node metadata
	node := dag.Operations[string(op.Identifier)]

	// Write stage number
	if err := binary.Write(&buf, binary.BigEndian, node.Stage); err != nil {
		return nil, err
	}

	// Write read set
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(node.ReadSet)),
	); err != nil {
		return nil, err
	}
	for _, addr := range node.ReadSet {
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(addr)),
		); err != nil {
			return nil, err
		}
		buf.Write(addr)
	}

	// Write write set
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(node.WriteSet)),
	); err != nil {
		return nil, err
	}
	for _, addr := range node.WriteSet {
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(addr)),
		); err != nil {
			return nil, err
		}
		buf.Write(addr)
	}

	return buf.Bytes(), nil
}

var _ intrinsics.IntrinsicOperation = (*CodeExecute)(nil)
