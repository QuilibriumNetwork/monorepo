package schema

import (
	"bytes"
	"crypto/sha512"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// RDFMultiprover provides RDF-based multiproof operations
type RDFMultiprover struct {
	parser          RDFParser
	inclusionProver crypto.InclusionProver

	// Cache for parsed RDF documents
	// First map key is document, second is class name, third is property name
	documentCache map[string]map[string]map[string]*RDFTag
	cacheMutex    sync.RWMutex
}

// NewRDFMultiprover creates a new RDFMultiprover instance
func NewRDFMultiprover(
	parser RDFParser,
	inclusionProver crypto.InclusionProver,
) *RDFMultiprover {
	return &RDFMultiprover{
		parser:          parser,
		inclusionProver: inclusionProver,
		documentCache:   make(map[string]map[string]map[string]*RDFTag),
	}
}

// getOrParseDocument retrieves a parsed document from cache or parses it
func (m *RDFMultiprover) getOrParseDocument(
	document string,
) (map[string]map[string]*RDFTag, error) {
	// Check cache first
	m.cacheMutex.RLock()
	if tags, ok := m.documentCache[document]; ok {
		m.cacheMutex.RUnlock()
		return tags, nil
	}
	m.cacheMutex.RUnlock()

	// Parse document
	tags, err := m.parser.GetTagsByClass(document)
	if err != nil {
		return nil, errors.Wrap(err, "get or parse document")
	}

	// Cache the result
	m.cacheMutex.Lock()
	m.documentCache[document] = tags
	m.cacheMutex.Unlock()

	return tags, nil
}

func (m *RDFMultiprover) GetType(
	document string,
	domain []byte,
	tree *qcrypto.VectorCommitmentTree,
) (string, error) {
	// Parse RDF document to get field and class names
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return "", errors.Wrap(err, "get type")
	}

	typeHash, err := tree.Get(bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		return "", errors.Wrap(err, "get type")
	}

	for k := range tagsByClass {
		typeBI, err := poseidon.HashBytes(
			slices.Concat(domain, []byte(k)),
		)

		if err != nil {
			return "", errors.Wrap(err, "get type")
		}

		typeBytes := typeBI.FillBytes(make([]byte, 32))
		if bytes.Equal(typeHash, typeBytes) {
			return k, nil
		}
	}

	return "", errors.Wrap(errors.New("type not found"), "get type")
}

// ProveWithType generates a multiproof for the specified fields with an
// optional type index. Fields can be specified as "ClassName.FieldName" or
// just "FieldName" if there's only one class or no ambiguity.
func (m *RDFMultiprover) ProveWithType(
	document string,
	fields []string,
	tree *qcrypto.VectorCommitmentTree,
	typeIndex *uint64,
) (crypto.Multiproof, error) {
	// Parse RDF document to get field ordering
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)
	polySize := GetPolySizeForMaxOrder(maxOrder)

	// Get tree commitment and polynomial
	commit := tree.Root.Commit(m.inclusionProver, false)
	poly := tree.Root.(*qcrypto.VectorCommitmentBranchNode).GetPolynomial()

	// Build indices from field names
	indices := make([]uint64, 0, len(fields)+1)
	commits := make([][]byte, 0, len(fields)+1)
	polys := make([][]byte, 0, len(fields)+1)

	for _, field := range fields {
		var tag *RDFTag
		var found bool

		// Check if field is in "Class.Field" format
		parts := strings.Split(field, ".")
		if len(parts) == 2 {
			// Class-qualified field
			className := parts[0]
			fieldName := parts[1]
			if classTags, ok := tagsByClass[className]; ok {
				tag, found = classTags[fieldName]
			}
		} else {
			// Unqualified field - search all classes in deterministic order
			for className := range tagsByClass {
				classTags := tagsByClass[className]
				if t, ok := classTags[field]; ok {
					if found {
						return nil, errors.Wrap(
							errors.Errorf(
								"ambiguous field %s found in multiple classes",
								field,
							),
							"prove with type",
						)
					}
					tag = t
					found = true
				}
			}
		}

		if !found {
			return nil, errors.Errorf("field %s not found in RDF schema", field)
		}

		// Validate order value
		if tag.Order > MaxOrderThreeByte {
			return nil, errors.Errorf(
				"order value %d exceeds maximum allowed value of %d",
				tag.Order,
				MaxOrderThreeByte,
			)
		}

		// Indices are order values (not shifted - that's handled at the tree level)
		indices = append(indices, uint64(tag.Order))
		commits = append(commits, commit)
		polys = append(polys, poly)
	}

	// Add type index if provided
	if typeIndex != nil {
		indices = append(indices, *typeIndex)
		commits = append(commits, commit)
		polys = append(polys, poly)
	}

	// Generate multiproof
	multiproof := m.inclusionProver.ProveMultiple(
		commits,
		polys,
		indices,
		polySize,
	)

	return multiproof, nil
}

// Prove generates a multiproof for the specified fields without type index
func (m *RDFMultiprover) Prove(
	document string,
	fields []string,
	tree *qcrypto.VectorCommitmentTree,
) (crypto.Multiproof, error) {
	// No type index by default - pass nil
	return m.ProveWithType(document, fields, tree, nil)
}

// VerifyWithType verifies a multiproof for the specified fields with an
// optional type index. Fields can be specified as "ClassName.FieldName" or
// just "FieldName" if there's only one class or no ambiguity.
func (m *RDFMultiprover) VerifyWithType(
	document string,
	fields []string,
	keys [][]byte,
	commit []byte,
	proof []byte,
	data [][]byte,
	typeIndex *uint64,
	typeData []byte,
) (bool, error) {
	// Parse RDF document to get field ordering
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return false, errors.Wrap(err, "verify with type")
	}

	// Validate inputs
	if len(fields) != len(data) {
		return false, errors.Wrap(
			errors.New("fields and data length mismatch"),
			"verify with type",
		)
	}
	if len(keys) > 0 && len(keys) != len(fields) {
		return false, errors.Wrap(
			errors.New("keys and fields length mismatch"),
			"verify with type",
		)
	}

	// Build indices and evaluations
	indices := make([]uint64, 0, len(fields)+1)
	commits := make([][]byte, 0, len(fields)+1)
	evaluations := make([][]byte, 0, len(fields)+1)

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)
	polySize := GetPolySizeForMaxOrder(maxOrder)

	for i, field := range fields {
		var tag *RDFTag
		var found bool

		// Check if field is in "Class.Field" format
		parts := strings.Split(field, ".")
		if len(parts) == 2 {
			// Class-qualified field
			className := parts[0]
			fieldName := parts[1]
			if classTags, ok := tagsByClass[className]; ok {
				tag, found = classTags[fieldName]
			}
		} else {
			// Unqualified field - search all classes
			for _, classTags := range tagsByClass {
				if t, ok := classTags[field]; ok {
					if found {
						return false, errors.Wrap(
							errors.Errorf(
								"ambiguous field %s found in multiple classes",
								field,
							),
							"verify with type",
						)
					}
					tag = t
					found = true
				}
			}
		}

		if !found {
			return false, errors.Wrap(
				errors.Errorf("field %s not found in RDF schema", field),
				"verify with type",
			)
		}

		// Calculate evaluation
		h := sha512.New()
		h.Write([]byte{0})

		if len(keys) > 0 && keys[i] != nil {
			h.Write(keys[i])
		} else {
			// Use flexible order encoding
			key, err := OrderToKey(tag.Order, maxOrder)
			if err != nil {
				return false, errors.Wrap(err, "verify")
			}
			h.Write(key)
		}

		h.Write(data[i])
		evaluation := h.Sum(nil)

		indices = append(indices, uint64(tag.Order))
		commits = append(commits, commit)
		evaluations = append(evaluations, evaluation)
	}

	// Add type verification if provided
	if typeIndex != nil && typeData != nil {
		h := sha512.New()
		h.Write([]byte{0})
		h.Write(bytes.Repeat([]byte{0xff}, 32))
		h.Write(typeData)
		evaluation := h.Sum(nil)

		indices = append(indices, *typeIndex)
		commits = append(commits, commit)
		evaluations = append(evaluations, evaluation)
	}

	// Deserialize multiproof
	mp := m.inclusionProver.NewMultiproof()
	if err := mp.FromBytes(proof); err != nil {
		return false, errors.Wrap(err, "verify")
	}

	// Verify multiproof
	valid := m.inclusionProver.VerifyMultiple(
		commits,
		evaluations,
		indices,
		polySize,
		mp.GetMulticommitment(),
		mp.GetProof(),
	)

	return valid, nil
}

// Verify verifies a multiproof for the specified fields without type index
func (m *RDFMultiprover) Verify(
	document string,
	fields []string,
	keys [][]byte,
	commit []byte,
	proof []byte,
	data [][]byte,
) (bool, error) {
	// For backward compatibility, assume no type data if using simple Verify
	return m.VerifyWithType(document, fields, keys, commit, proof, data, nil, nil)
}

// Get retrieves a field value from the tree using RDF ordering
func (m *RDFMultiprover) Get(
	document string,
	rdfClass string,
	field string,
	tree *qcrypto.VectorCommitmentTree,
) ([]byte, error) {
	// Parse RDF document to get field ordering
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return nil, errors.Wrap(err, "get")
	}

	// Find the class
	classTags, ok := tagsByClass[rdfClass]
	if !ok {
		return nil, errors.Wrap(
			errors.Errorf("class %s not found in RDF schema", rdfClass),
			"get",
		)
	}

	// Find the field
	tag, ok := classTags[field]
	if !ok {
		return nil, errors.Wrap(
			errors.Errorf("field %s not found in class %s", field, rdfClass),
			"get",
		)
	}

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)

	// Get value from tree using flexible order encoding
	key, err := OrderToKey(tag.Order, maxOrder)
	if err != nil {
		return nil, errors.Wrap(err, "get")
	}
	value, err := tree.Get(key)
	if err != nil {
		return nil, errors.Wrap(err, "get")
	}

	return value, nil
}

// ClearCache clears the document cache
func (m *RDFMultiprover) ClearCache() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	m.documentCache = make(map[string]map[string]map[string]*RDFTag)
}

// GetFieldOrder returns the order value for a specific field
func (m *RDFMultiprover) GetFieldOrder(
	document string,
	rdfClass string,
	field string,
) (int, int, error) {
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return -1, -1, errors.Wrap(err, "get field order")
	}

	classTags, ok := tagsByClass[rdfClass]
	if !ok {
		return -1, -1, errors.Errorf("class %s not found in RDF schema", rdfClass)
	}

	tag, ok := classTags[field]
	if !ok {
		return -1, -1, errors.Errorf(
			"field %s not found in class %s", field, rdfClass,
		)
	}

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)

	return tag.Order, maxOrder, nil
}

// GetFieldKey returns the key bytes for a specific field using flexible
// encoding
func (m *RDFMultiprover) GetFieldKey(
	document string,
	rdfClass string,
	field string,
) ([]byte, error) {
	order, maxOrder, err := m.GetFieldOrder(document, rdfClass, field)
	if err != nil {
		return nil, err
	}

	return OrderToKey(order, maxOrder)
}

// Set stores a field value in the tree using RDF ordering
func (m *RDFMultiprover) Set(
	document string,
	domain []byte,
	rdfClass string,
	field string,
	value []byte,
	tree *qcrypto.VectorCommitmentTree,
) error {
	// Parse RDF document to get field ordering
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return errors.Wrap(err, "set")
	}

	typeHash, err := tree.Get(bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		typeBI, err := poseidon.HashBytes(
			slices.Concat(domain, []byte(rdfClass)),
		)

		if err != nil {
			return errors.Wrap(err, "set")
		}

		typeBytes := typeBI.FillBytes(make([]byte, 32))
		err = tree.Insert(
			bytes.Repeat([]byte{0xff}, 32),
			typeBytes,
			nil,
			big.NewInt(32),
		)
		if err != nil {
			return errors.Wrap(err, "set")
		}
		typeHash = typeBytes
	} else {
		typeBI, err := poseidon.HashBytes(
			slices.Concat(domain, []byte(rdfClass)),
		)

		if err != nil {
			return errors.Wrap(err, "set")
		}

		typeBytes := typeBI.FillBytes(make([]byte, 32))
		if !bytes.Equal(typeHash, typeBytes) {
			return errors.Wrap(errors.New("invalid type for existing tree"), "set")
		}
	}

	// Find the class
	classTags, ok := tagsByClass[rdfClass]
	if !ok {
		return errors.Wrap(
			errors.Errorf("class %s not found in RDF schema", rdfClass),
			"set",
		)
	}

	// Find the field
	tag, ok := classTags[field]
	if !ok {
		return errors.Wrap(
			errors.Errorf("field %s not found in class %s", field, rdfClass),
			"set",
		)
	}

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)

	// Set value in tree using flexible order encoding
	key, err := OrderToKey(tag.Order, maxOrder)
	if err != nil {
		return errors.Wrap(err, "set")
	}
	err = tree.Insert(key, value, nil, big.NewInt(int64(len(value))))
	if err != nil {
		return errors.Wrap(err, "set")
	}

	return nil
}

// GetSchemaMap returns the parsed schema map for a document
func (m *RDFMultiprover) GetSchemaMap(
	document string,
) (map[string]map[string]*RDFTag, error) {
	schemaMap, err := m.getOrParseDocument(document)
	if err != nil {
		return nil, errors.Wrap(err, "get schema map")
	}

	return maps.Clone(schemaMap), nil
}

// Validate confirms only the indexes of the tree specified in the schema
// (the order values) are set, and that the values set are correct for the
// types.
func (m *RDFMultiprover) Validate(
	document string,
	domain []byte,
	tree *qcrypto.VectorCommitmentTree,
) (bool, error) {
	return m.ValidateWithOptions(document, domain, tree, false)
}

// ValidateWithOptions confirms only the indexes of the tree specified in the
// schema (the order values) are set. If skipTypeVerification is false, it also
// validates that the values set are correct for the types. If
// skipTypeVerification is true, it only checks for unexpected indices (useful
// for VerEnc data).
func (m *RDFMultiprover) ValidateWithOptions(
	document string,
	domain []byte,
	tree *qcrypto.VectorCommitmentTree,
	skipTypeVerification bool,
) (bool, error) {
	// Parse RDF document to get field ordering and types
	tagsByClass, err := m.getOrParseDocument(document)
	if err != nil {
		return false, errors.Wrap(err, "validate")
	}

	// Collect all expected indexes from the schema
	expectedIndexes := make(map[string]struct{})
	fieldsByKey := make(map[string]*RDFTag)

	// Determine the maximum order value to select appropriate polynomial size
	maxOrder := GetMaxOrderForDocument(tagsByClass)

	for _, classTags := range tagsByClass {
		for _, tag := range classTags {
			key, err := OrderToKey(tag.Order, maxOrder)
			if err != nil {
				return false, errors.Wrap(err, "validate")
			}
			keyStr := string(key)
			expectedIndexes[keyStr] = struct{}{}
			fieldsByKey[keyStr] = tag
		}
	}

	// Get all leaves from the tree
	leaves := qcrypto.GetAllPreloadedLeaves(tree.Root)

	// Check that only expected indexes are present
	for _, leaf := range leaves {
		keyStr := string(leaf.Key)

		// Handle the special type key (0xff...ff)
		if bytes.Equal(leaf.Key, bytes.Repeat([]byte{0xff}, 32)) {
			// Validate that the type hash matches one of the class names
			foundValidType := false
			for className := range tagsByClass {
				// Hash the class name with domain
				typeBI, err := poseidon.HashBytes(
					slices.Concat(domain, []byte(className)),
				)
				if err != nil {
					return false, errors.Wrap(err, "validate type hash")
				}

				typeBytes := typeBI.FillBytes(make([]byte, 32))
				if bytes.Equal(leaf.Value, typeBytes) {
					foundValidType = true
					break
				}
			}

			if !foundValidType {
				return false, errors.Wrap(
					errors.New("type key contains invalid class type"),
					"validate with options",
				)
			}
			continue
		}

		// Check if this key is expected
		if _, expected := expectedIndexes[keyStr]; !expected {
			return false, errors.Wrap(
				errors.Errorf("unexpected index in tree: %x", leaf.Key),
				"validate with options",
			)
		}

		// Validate the value based on type (if not skipping type verification)
		if !skipTypeVerification {
			tag := fieldsByKey[keyStr]
			if tag != nil {
				// Get the field information from the original schema parsing
				// We need to check the RdfType to validate the value
				if err := validateValue(leaf.Value, tag); err != nil {
					return false, errors.Wrap(
						errors.Wrapf(err, "invalid value at index %x", leaf.Key),
						"validate with options",
					)
				}
			}
		}

		// Mark this index as seen
		delete(expectedIndexes, keyStr)
	}

	return true, nil
}

// validateValue checks if a value is valid for the given RDF type
func validateValue(value []byte, tag *RDFTag) error {
	// Validate based on RDF type
	switch tag.RdfType {
	case QCLUint:
		// Unsigned integers - use FieldSize for validation
		if tag.FieldSize > 0 {
			expectedSize := int(tag.FieldSize)
			if len(value) != expectedSize {
				return errors.Errorf(
					"Uint field: expected size %d, got %d",
					expectedSize,
					len(value),
				)
			}
		} else {
			// If no size specified, check common sizes
			if len(value) != 4 && len(value) != 8 {
				return errors.New("Uint field without size must be 4 or 8 bytes")
			}
		}

	case QCLInt:
		// Signed integers - use FieldSize for validation
		if tag.FieldSize > 0 {
			expectedSize := int(tag.FieldSize)
			if len(value) != expectedSize {
				return errors.Errorf(
					"Int field: expected size %d, got %d",
					expectedSize,
					len(value),
				)
			}
		} else {
			// If no size specified, check common sizes
			if len(value) != 4 && len(value) != 8 {
				return errors.New("Int field without size must be 4 or 8 bytes")
			}
		}

	case QCLByteArray:
		// Byte arrays must have exact size
		if tag.FieldSize == 0 {
			return errors.New("ByteArray field must have size specified")
		}
		expectedSize := int(tag.FieldSize)
		if len(value) != expectedSize {
			return errors.Errorf(
				"ByteArray field: expected size %d, got %d",
				expectedSize,
				len(value),
			)
		}

	case QCLBoolean:
		// Bool must be exactly 1 byte
		if len(value) != 1 {
			return errors.Errorf(
				"Bool field must be exactly 1 byte, got %d",
				len(value),
			)
		}
		// Value must be 0 or 1 (or any non-zero for true)
		// We'll accept any value as valid since any non-zero is true

	case QCLString:
		// Strings must have exact size
		if tag.FieldSize == 0 {
			return errors.New("String field must have size specified")
		}
		expectedSize := int(tag.FieldSize)
		if len(value) != expectedSize {
			return errors.Errorf(
				"String field: expected size %d, got %d",
				expectedSize,
				len(value),
			)
		}

	case QCLStruct:
		// Struct fields (including extrinsic) must be 32 bytes
		if len(value) != 32 {
			return errors.Errorf(
				"Struct field must be exactly 32 bytes, got %d",
				len(value),
			)
		}

	default:
		// Unknown type - only validate size if specified
		if tag.FieldSize > 0 {
			expectedSize := int(tag.FieldSize)
			if len(value) != expectedSize {
				return errors.Errorf(
					"expected size %d, got %d",
					expectedSize,
					len(value),
				)
			}
		}
	}

	// Additional validation for extrinsic fields
	if tag.Extrinsic != "" && len(value) != 32 {
		return errors.New("extrinsic fields must be 32 bytes")
	}

	return nil
}
