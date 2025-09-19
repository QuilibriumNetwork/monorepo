package schema

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
)

func TestRDFGetTagsMethod(t *testing.T) {
	// Sample RDF document
	rdfDocument := `
@prefix mint: <https://types.quilibrium.com/mint/> .
@prefix account: <https://types.quilibrium.com/account/> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

mint:MintRequest a rdfs:Class .

mint:Quantity a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 0 ;
    rdfs:range mint:MintRequest ;
    rdfs:comment "The amount to mint" .

mint:DestinationAccount a rdfs:Property ;
    rdfs:domain account:Account ;
    qcl:order 1 ;
    rdfs:range mint:MintRequest ;
    rdfs:comment "The account receiving the minted tokens" .

mint:Data a rdfs:Property ;
    rdfs:domain qcl:ByteArray ;
    qcl:size 128 ;
    qcl:order 2 ;
    rdfs:range mint:MintRequest .

mint:Name a rdfs:Property ;
    rdfs:domain qcl:String ;
    qcl:size 64 ;
    qcl:order 3 ;
    rdfs:range mint:MintRequest .
`

	parser := &TurtleRDFParser{}

	// Get tags using the new method
	tags, err := parser.GetTags(rdfDocument)
	require.NoError(t, err)

	// Verify we got the expected tags
	assert.Len(t, tags, 4, "Expected 4 tags")

	// Check Quantity field
	quantityTag := tags["Quantity"]
	require.NotNil(t, quantityTag)
	assert.Equal(t, "mint:Quantity", quantityTag.Name)
	assert.Equal(t, 0, quantityTag.Order)
	assert.Nil(t, quantityTag.Size) // Size is encoded in the type for uint
	assert.Empty(t, quantityTag.Extrinsic)

	// Check DestinationAccount field
	accountTag := tags["DestinationAccount"]
	require.NotNil(t, accountTag)
	assert.Equal(t, "mint:DestinationAccount", accountTag.Name)
	assert.Equal(t, 1, accountTag.Order)
	assert.Equal(t, "account:Account", accountTag.Extrinsic)
	assert.Nil(t, accountTag.Size) // Extrinsic fields don't have size

	// Check Data field
	dataTag := tags["Data"]
	require.NotNil(t, dataTag)
	assert.Equal(t, "mint:Data", dataTag.Name)
	assert.Equal(t, 2, dataTag.Order)
	require.NotNil(t, dataTag.Size)
	assert.Equal(t, 128, *dataTag.Size)
	assert.Empty(t, dataTag.Extrinsic)

	// Check Name field
	nameTag := tags["Name"]
	require.NotNil(t, nameTag)
	assert.Equal(t, "mint:Name", nameTag.Name)
	assert.Equal(t, 3, nameTag.Order)
	require.NotNil(t, nameTag.Size)
	assert.Equal(t, 64, *nameTag.Size)
	assert.Empty(t, nameTag.Extrinsic)

	// Verify all tags can be parsed by ParseRDFTag
	for fieldName, tag := range tags {
		parsedTag, err := ParseRDFTag(tag.Raw)
		require.NoError(t, err, "Failed to parse tag for field %s", fieldName)

		// Compare parsed tag with original
		assert.Equal(t, tag.Name, parsedTag.Name, "Name mismatch for field %s", fieldName)
		assert.Equal(t, tag.Order, parsedTag.Order, "Order mismatch for field %s", fieldName)
		assert.Equal(t, tag.Extrinsic, parsedTag.Extrinsic, "Extrinsic mismatch for field %s", fieldName)

		if tag.Size != nil {
			require.NotNil(t, parsedTag.Size, "Size should not be nil for field %s", fieldName)
			assert.Equal(t, *tag.Size, *parsedTag.Size, "Size mismatch for field %s", fieldName)
		} else {
			assert.Nil(t, parsedTag.Size, "Size should be nil for field %s", fieldName)
		}
	}
}

func TestRDFGeneratedTagsCompatibility(t *testing.T) {
	// Sample RDF document that should generate compatible tags
	rdfDocument := `
@prefix mint: <https://types.quilibrium.com/mint/> .
@prefix account: <https://types.quilibrium.com/account/> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

mint:MintRequest a rdfs:Class .

mint:Quantity a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 0 ;
    rdfs:range mint:MintRequest ;
    rdfs:comment "The amount to mint" .

mint:DestinationAccount a rdfs:Property ;
    rdfs:domain account:Account ;
    qcl:order 1 ;
    rdfs:range mint:MintRequest ;
    rdfs:comment "The account receiving the minted tokens" .

mint:MintAuthorization a rdfs:Property ;
    rdfs:domain mint:MintAuthorizationClass ;
    qcl:order 2 ;
    rdfs:range mint:MintRequest .

mint:Data a rdfs:Property ;
    rdfs:domain qcl:ByteArray ;
    qcl:size 128 ;
    qcl:order 3 ;
    rdfs:range mint:MintRequest .

mint:Name a rdfs:Property ;
    rdfs:domain qcl:String ;
    qcl:size 64 ;
    qcl:order 4 ;
    rdfs:range mint:MintRequest .
`

	parser := &TurtleRDFParser{}

	// Generate QCL code
	generated, err := parser.GenerateQCL(rdfDocument)
	require.NoError(t, err)

	// Extract struct definition
	lines := strings.Split(generated, "\n")
	var structLines []string
	inStruct := false

	for _, line := range lines {
		if strings.HasPrefix(line, "type MintRequest struct") {
			inStruct = true
			continue
		}
		if inStruct && line == "}" {
			break
		}
		if inStruct && strings.TrimSpace(line) != "" {
			structLines = append(structLines, strings.TrimSpace(line))
		}
	}

	// Parse each field's tag
	type fieldInfo struct {
		name      string
		typ       string
		tag       string
		parsedTag *RDFTag
	}

	var fields []fieldInfo

	for _, line := range structLines {
		// Skip comment lines
		if strings.HasPrefix(line, "//") {
			continue
		}

		// Parse field definition
		// Format: FieldName Type `rdf:"..."`
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		fieldName := parts[0]
		fieldType := parts[1]

		// Extract tag
		tagStart := strings.Index(line, "`rdf:\"")
		tagEnd := strings.LastIndex(line, "\"`")
		if tagStart == -1 || tagEnd == -1 {
			continue
		}

		tagValue := line[tagStart+6 : tagEnd]

		// Parse the tag using our tag parser
		parsedTag, err := ParseRDFTag(tagValue)
		require.NoError(t, err, "Failed to parse tag for field %s: %s", fieldName, tagValue)

		fields = append(fields, fieldInfo{
			name:      fieldName,
			typ:       fieldType,
			tag:       tagValue,
			parsedTag: parsedTag,
		})
	}

	// Verify we got all expected fields
	assert.Len(t, fields, 5, "Expected 5 fields in generated struct")

	// Expected field configurations
	expectedFields := map[string]struct {
		typ       string
		order     int
		size      *int
		extrinsic string
	}{
		"Quantity": {
			typ:   "uint64",
			order: 0,
		},
		"DestinationAccount": {
			typ:       "hypergraph.Extrinsic",
			order:     1,
			extrinsic: "account:Account",
		},
		"MintAuthorization": {
			typ:       "hypergraph.Extrinsic",
			order:     2,
			extrinsic: "mint:MintAuthorizationClass",
		},
		"Data": {
			typ:   "[128]byte",
			order: 3,
			size:  intPtr(128),
		},
		"Name": {
			typ:   "string",
			order: 4,
			size:  intPtr(64),
		},
	}

	// Verify each field
	for _, field := range fields {
		expected, ok := expectedFields[field.name]
		assert.True(t, ok, "Unexpected field: %s", field.name)

		// Check type
		assert.Equal(t, expected.typ, field.typ, "Field %s type mismatch", field.name)

		// Check order
		assert.Equal(t, expected.order, field.parsedTag.Order,
			"Field %s order mismatch. Tag: %s", field.name, field.tag)

		// Check size
		if expected.size != nil {
			require.NotNil(t, field.parsedTag.Size,
				"Field %s expected size but got nil. Tag: %s", field.name, field.tag)
			assert.Equal(t, *expected.size, *field.parsedTag.Size,
				"Field %s size mismatch. Tag: %s", field.name, field.tag)
		} else {
			assert.Nil(t, field.parsedTag.Size,
				"Field %s expected no size but got %v. Tag: %s",
				field.name, field.parsedTag.Size, field.tag)
		}

		// Check extrinsic
		assert.Equal(t, expected.extrinsic, field.parsedTag.Extrinsic,
			"Field %s extrinsic mismatch. Tag: %s", field.name, field.tag)
	}

	// Verify the tags can be validated as a complete struct
	// Create a mock struct type with the parsed tags
	mockFields := make([]reflect.StructField, len(fields))
	for i, field := range fields {
		mockFields[i] = reflect.StructField{
			Name: field.name,
			Type: getFieldType(field.typ),
			Tag:  reflect.StructTag(`rdf:"` + field.tag + `"`),
		}
	}

	mockStruct := reflect.StructOf(mockFields)
	tags, err := ValidateStructTags(mockStruct)
	require.NoError(t, err, "Generated tags should pass validation")

	// Verify field ordering
	fieldOrder := GetFieldOrder(tags, mockStruct)
	expectedOrder := []string{"Quantity", "DestinationAccount", "MintAuthorization", "Data", "Name"}
	assert.Equal(t, expectedOrder, fieldOrder, "Field order should match")
}

func TestRDFGeneratedTagsEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		rdfDocument string
		expectError bool
		validate    func(t *testing.T, generated string)
	}{
		{
			name: "struct with no size fields",
			rdfDocument: `
@prefix test: <https://types.quilibrium.com/test/> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

test:Simple a rdfs:Class .

test:Field1 a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 4 ;
    qcl:order 0 ;
    rdfs:range test:Simple .

test:Field2 a rdfs:Property ;
    rdfs:domain qcl:Bool ;
    qcl:order 1 ;
    rdfs:range test:Simple .
`,
			validate: func(t *testing.T, generated string) {
				// Extract Field2 tag
				assert.Contains(t, generated, `Field2 bool `+"`"+`rdf:"test:Field2,order=1"`+"`")
				// No size attribute for bool
				assert.NotContains(t, generated, "Field2,order=1,size")
			},
		},
		{
			name: "struct with mixed types",
			rdfDocument: `
@prefix test: <https://types.quilibrium.com/test/> .
@prefix other: <https://types.quilibrium.com/other/> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

test:Mixed a rdfs:Class .

test:SmallInt a rdfs:Property ;
    rdfs:domain qcl:Int ;
    qcl:size 2 ;
    qcl:order 0 ;
    rdfs:range test:Mixed .

test:BigInt a rdfs:Property ;
    rdfs:domain qcl:Int ;
    qcl:size 8 ;
    qcl:order 1 ;
    rdfs:range test:Mixed .

test:FixedBytes a rdfs:Property ;
    rdfs:domain qcl:ByteArray ;
    qcl:size 32 ;
    qcl:order 2 ;
    rdfs:range test:Mixed .

test:Reference a rdfs:Property ;
    rdfs:domain other:Thing ;
    qcl:order 3 ;
    rdfs:range test:Mixed .
`,
			validate: func(t *testing.T, generated string) {
				// Check each field's tag
				lines := strings.Split(generated, "\n")
				for _, line := range lines {
					if strings.Contains(line, "SmallInt") && strings.Contains(line, "`rdf:") {
						assert.Contains(t, line, `rdf:"test:SmallInt,order=0"`)
						assert.NotContains(t, line, "size=") // Size is in the type int16
					}
					if strings.Contains(line, "FixedBytes") && strings.Contains(line, "`rdf:") {
						assert.Contains(t, line, `rdf:"test:FixedBytes,order=2,size=32"`)
					}
					if strings.Contains(line, "Reference") && strings.Contains(line, "`rdf:") {
						assert.Contains(t, line, `rdf:"test:Reference,extrinsic=other:Thing,order=3"`)
						assert.NotContains(t, line, "size=") // Extrinsic doesn't have size
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &TurtleRDFParser{}
			generated, err := parser.GenerateQCL(tt.rdfDocument)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, generated)
			}

			// Verify all tags in the generated code can be parsed
			lines := strings.Split(generated, "\n")
			for _, line := range lines {
				if tagStart := strings.Index(line, "`rdf:\""); tagStart != -1 {
					tagEnd := strings.Index(line[tagStart:], "\"`")
					if tagEnd != -1 {
						tagValue := line[tagStart+6 : tagStart+tagEnd]
						_, err := ParseRDFTag(tagValue)
						assert.NoError(t, err, "Failed to parse generated tag: %s", tagValue)
					}
				}
			}
		})
	}
}

// Helper function to map type strings to reflect.Type
func getFieldType(typeName string) reflect.Type {
	switch typeName {
	case "bool":
		return reflect.TypeOf(false)
	case "uint8":
		return reflect.TypeOf(uint8(0))
	case "uint16":
		return reflect.TypeOf(uint16(0))
	case "uint32":
		return reflect.TypeOf(uint32(0))
	case "uint64":
		return reflect.TypeOf(uint64(0))
	case "int8":
		return reflect.TypeOf(int8(0))
	case "int16":
		return reflect.TypeOf(int16(0))
	case "int32":
		return reflect.TypeOf(int32(0))
	case "int64":
		return reflect.TypeOf(int64(0))
	case "string":
		return reflect.TypeOf("")
	case "hypergraph.Extrinsic":
		// Return the actual hypergraph.Extrinsic type
		return reflect.TypeOf(hypergraph.Extrinsic{})
	default:
		// Handle byte arrays like [32]byte, [128]byte
		if strings.HasPrefix(typeName, "[") && strings.HasSuffix(typeName, "]byte") {
			// For simplicity, return []byte type
			return reflect.TypeOf([]byte{})
		}
		return reflect.TypeOf(struct{}{})
	}
}
