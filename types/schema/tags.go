package schema

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// RDFTag represents a parsed RDF struct tag
type RDFTag struct {
	// The RDF name (first value, namespaced)
	Name string
	// Value of extrinsic key (only for hypergraph.Extrinsic)
	Extrinsic string
	// Order for serialization (0-indexed, -1 if not specified)
	Order int
	// Size in raw bytes (required for slices, strings, *big.Int)
	Size *int
	// The raw tag value
	Raw string
	// RDF type (e.g., "Uint", "Int", "ByteArray", "Bool", "String", "Struct")
	RdfType string
	// Field size in bytes (for validation, may differ from Size which is for tag
	// display)
	FieldSize uint32
}

// ParseRDFTag parses an rdf struct tag
func ParseRDFTag(tag string) (*RDFTag, error) {
	if tag == "" {
		return nil, errors.Wrap(
			errors.New("empty rdf tag"),
			"parse rdf tag",
		)
	}

	parts := strings.Split(tag, ",")
	if len(parts) == 0 {
		return nil, errors.Wrap(
			errors.New("invalid rdf tag format"),
			"parse rdf tag",
		)
	}

	// First part must be the RDF name
	rdfTag := &RDFTag{
		Name:  strings.TrimSpace(parts[0]),
		Order: -1,
		Raw:   tag,
	}

	if rdfTag.Name == "" {
		return nil, errors.Wrap(
			errors.New("rdf name cannot be empty"),
			"parse rdf tag",
		)
	}

	// Parse key-value pairs
	for i := 1; i < len(parts); i++ {
		kv := strings.SplitN(strings.TrimSpace(parts[i]), "=", 2)
		if len(kv) != 2 {
			return nil, errors.Wrap(
				errors.Errorf("invalid key-value pair: %s", parts[i]),
				"parse rdf tag",
			)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "extrinsic":
			rdfTag.Extrinsic = value
		case "order":
			order, err := strconv.Atoi(value)
			if err != nil {
				return nil, errors.Wrap(
					errors.Wrap(err, "invalid order value"),
					"parse rdf tag",
				)
			}
			if order < 0 {
				return nil, errors.Wrap(
					errors.New("order must be non-negative"),
					"parse rdf tag",
				)
			}
			rdfTag.Order = order
		case "size":
			size, err := strconv.Atoi(value)
			if err != nil {
				return nil, errors.Wrap(
					errors.Wrap(err, "invalid size value"),
					"parse rdf tag",
				)
			}
			if size <= 0 {
				return nil, errors.Wrap(
					errors.New("size must be positive"),
					"parse rdf tag",
				)
			}
			rdfTag.Size = &size
		default:
			return nil, errors.Wrap(
				errors.Errorf("unknown tag key: %s", key),
				"parse rdf tag",
			)
		}
	}

	return rdfTag, nil
}

// ValidateStructTags validates all RDF tags in a struct and returns parsed tags
func ValidateStructTags(structType reflect.Type) (map[string]*RDFTag, error) {
	if structType.Kind() != reflect.Struct {
		return nil, errors.Wrap(
			errors.New("provided type is not a struct"),
			"validate struct tags",
		)
	}

	tags := make(map[string]*RDFTag)
	orders := make(map[int]string) // To check for duplicate orders

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tagValue := field.Tag.Get("rdf")

		if tagValue == "" {
			continue
		}

		tag, err := ParseRDFTag(tagValue)
		if err != nil {
			return nil, errors.Wrap(
				errors.Wrapf(err, "field %s", field.Name),
				"validate struct tags",
			)
		}

		if err := validateFieldType(field.Type, tag); err != nil {
			return nil, errors.Wrap(
				errors.Wrapf(err, "field %s", field.Name),
				"validate struct tags",
			)
		}

		// Check for duplicate orders
		if tag.Order >= 0 {
			if existingField, exists := orders[tag.Order]; exists {
				return nil, errors.Wrap(
					errors.Errorf(
						"duplicate order %d for fields %s and %s",
						tag.Order,
						existingField,
						field.Name,
					),
					"validate struct tags",
				)
			}
			orders[tag.Order] = field.Name
		}

		tags[field.Name] = tag
	}

	// Count fields with and without explicit order
	fieldsWithOrder := 0
	fieldsWithoutOrder := 0
	for _, tag := range tags {
		if tag.Order >= 0 {
			fieldsWithOrder++
		} else {
			fieldsWithoutOrder++
		}
	}

	// Validate that all fields have consistent ordering
	if fieldsWithOrder > 0 && fieldsWithoutOrder > 0 {
		return nil, errors.Wrap(
			errors.New(
				"order must be specified for all fields with rdf tags or none at all",
			),
			"validate struct tags",
		)
	}

	// If all fields have explicit order, validate completeness
	if fieldsWithOrder == len(tags) && fieldsWithOrder > 0 {
		// Check that orders form a complete sequence starting from 0
		for i := 0; i < fieldsWithOrder; i++ {
			if _, exists := orders[i]; !exists {
				return nil, errors.Wrap(
					errors.Errorf(
						"missing order %d in sequence (orders must be monotonic from 0)",
						i,
					),
					"validate struct tags",
				)
			}
		}
	}

	return tags, nil
}

// validateFieldType validates that a field type is allowed and tag constraints
// are met
func validateFieldType(fieldType reflect.Type, tag *RDFTag) error {
	// Handle pointer types
	if fieldType.Kind() == reflect.Ptr {
		// Only *big.Int is allowed as pointer type
		if fieldType.Elem().PkgPath() == "math/big" &&
			fieldType.Elem().Name() == "Int" {
			if tag.Size == nil {
				return errors.New("size must be specified for *big.Int fields")
			}
			return nil
		}
		return errors.Errorf(
			"pointer types not allowed except *big.Int, got %s",
			fieldType,
		)
	}

	// Check if it's hypergraph.Extrinsic
	if fieldType.PkgPath() == "source.quilibrium.com/quilibrium/monorepo/types/hypergraph" &&
		fieldType.Name() == "Extrinsic" {
		if tag.Extrinsic == "" {
			return errors.New(
				"extrinsic key must be specified for hypergraph.Extrinsic fields",
			)
		}
		if tag.Size != nil {
			return errors.New(
				"size must not be specified for hypergraph.Extrinsic fields",
			)
		}
		return nil
	}

	// Check extrinsic constraint
	if tag.Extrinsic != "" {
		return errors.New(
			"extrinsic key can only be specified for hypergraph.Extrinsic fields",
		)
	}

	// Validate primitive types and size constraints
	switch fieldType.Kind() {
	case reflect.Bool:
		// Bool is allowed, size is determined by type (1 byte)
		if tag.Size != nil && *tag.Size != 1 {
			return errors.New("size for bool must be 1 if specified")
		}
	case reflect.Int8, reflect.Uint8:
		// 8-bit integers, size is 1 byte
		if tag.Size != nil && *tag.Size != 1 {
			return errors.New("size for int8/uint8 must be 1 if specified")
		}
	case reflect.Int16, reflect.Uint16:
		// 16-bit integers, size is 2 bytes
		if tag.Size != nil && *tag.Size != 2 {
			return errors.New("size for int16/uint16 must be 2 if specified")
		}
	case reflect.Int32, reflect.Uint32:
		// 32-bit types, size is 4 bytes
		if tag.Size != nil && *tag.Size != 4 {
			return errors.New("size for 32-bit types must be 4 if specified")
		}
	case reflect.Int64, reflect.Uint64:
		// 64-bit types, size is 8 bytes
		if tag.Size != nil && *tag.Size != 8 {
			return errors.New("size for 64-bit types must be 8 if specified")
		}
	case reflect.Int, reflect.Uint:
		// Platform-dependent int/uint
		if tag.Size == nil {
			return errors.New("size must be specified for int/uint fields")
		}
		if *tag.Size != 4 && *tag.Size != 8 {
			return errors.New("size for int/uint must be 4 or 8")
		}
	case reflect.String:
		if tag.Size == nil {
			return errors.New("size must be specified for string fields")
		}
	case reflect.Slice:
		if tag.Size == nil {
			return errors.New("size must be specified for slice fields")
		}
		// Only byte slices are allowed
		if fieldType.Elem().Kind() != reflect.Uint8 {
			return errors.Errorf("only []byte slices are allowed, got %s", fieldType)
		}
	case reflect.Array:
		// Arrays are allowed for fixed-size byte arrays
		if fieldType.Elem().Kind() != reflect.Uint8 {
			return errors.Errorf("only byte arrays are allowed, got %s", fieldType)
		}
		// For arrays, size should match the array length
		if tag.Size != nil && *tag.Size != fieldType.Len() {
			return errors.Errorf(
				"size for array must match array length (%d)",
				fieldType.Len(),
			)
		}
	default:
		return errors.Errorf("unsupported field type: %s", fieldType.Kind())
	}

	return nil
}

// GetFieldOrder returns the ordered list of field names based on their order
// tags
func GetFieldOrder(
	tags map[string]*RDFTag,
	structType reflect.Type,
) []string {
	// Collect all fields with RDF tags
	var fields []string
	fieldOrders := make(map[string]int)
	hasExplicitOrder := false

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if tag, exists := tags[field.Name]; exists {
			fields = append(fields, field.Name)
			if tag.Order >= 0 {
				fieldOrders[field.Name] = tag.Order
				hasExplicitOrder = true
			} else {
				// Use struct field index as default order
				fieldOrders[field.Name] = i
			}
		}
	}

	// Sort fields by order
	sortedFields := make([]string, len(fields))
	copy(sortedFields, fields)

	if hasExplicitOrder {
		// Sort by explicit order
		for i := 0; i < len(sortedFields); i++ {
			for j := i + 1; j < len(sortedFields); j++ {
				if fieldOrders[sortedFields[i]] > fieldOrders[sortedFields[j]] {
					sortedFields[i], sortedFields[j] = sortedFields[j], sortedFields[i]
				}
			}
		}
	}

	return sortedFields
}

// GetFieldSize returns the size in bytes for a field
func GetFieldSize(fieldType reflect.Type, tag *RDFTag) (int, error) {
	// If size is explicitly specified, use it
	if tag.Size != nil {
		return *tag.Size, nil
	}

	// Handle pointer types
	if fieldType.Kind() == reflect.Ptr &&
		fieldType.Elem().PkgPath() == "math/big" &&
		fieldType.Elem().Name() == "Int" {
		return 0, errors.Wrap(
			errors.New("size must be specified for *big.Int"),
			"get field size",
		)
	}

	// Handle hypergraph.Extrinsic
	if fieldType.PkgPath() == "source.quilibrium.com/quilibrium/monorepo/types/hypergraph" &&
		fieldType.Name() == "Extrinsic" {
		return 32, nil // Fixed size for Extrinsic
	}

	// Calculate size based on type
	switch fieldType.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Uint8:
		return 1, nil
	case reflect.Int16, reflect.Uint16:
		return 2, nil
	case reflect.Int32, reflect.Uint32:
		return 4, nil
	case reflect.Int64, reflect.Uint64:
		return 8, nil
	case reflect.Array:
		if fieldType.Elem().Kind() == reflect.Uint8 {
			return fieldType.Len(), nil
		}
	}

	return 0, errors.Wrap(
		errors.Errorf("cannot determine size for type %s", fieldType),
		"get field size",
	)
}

func ValidateStruct(v interface{}) error {
	structType := reflect.TypeOf(v)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	_, err := ValidateStructTags(structType)
	return errors.Wrap(err, "validate struct")
}
