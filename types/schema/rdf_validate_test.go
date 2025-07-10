package schema

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTurtleRDFParserValidate(t *testing.T) {
	parser := &TurtleRDFParser{}

	tests := []struct {
		name        string
		document    string
		expectValid bool
		expectError bool
	}{
		{
			name: "valid simple document",
			document: `PREFIX account: <https://types.quilibrium.com/account/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

account:Account a rdfs:Class.`,
			expectValid: true,
			expectError: false,
		},
		{
			name: "valid complex document",
			document: `@prefix mint: <https://types.quilibrium.com/mint/> .
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

mint:MintRequest a rdfs:Class .
mint:Quantity a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 0 ;
    rdfs:range mint:MintRequest .`,
			expectValid: true,
			expectError: false,
		},
		{
			name:        "invalid syntax",
			document:    `This is not valid RDF`,
			expectValid: false,
			expectError: true,
		},
		{
			name: "missing prefix definition",
			document: `unknown:Something a rdfs:Class.`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "empty document",
			document:    "",
			expectValid: true, // Empty is technically valid RDF
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := parser.Validate(tt.document)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestGenerateQCLErrorCases(t *testing.T) {
	parser := &TurtleRDFParser{}

	tests := []struct {
		name        string
		document    string
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing size for uint",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "size unspecified for Field, add a qcl:size predicate",
		},
		{
			name: "missing size for string",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Name a rdfs:Property;
    rdfs:domain qcl:String;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "size unspecified for Name, add a qcl:size predicate",
		},
		{
			name: "missing size for byte array",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Data a rdfs:Property;
    rdfs:domain qcl:ByteArray;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "size unspecified for Data, add a qcl:size predicate",
		},
		{
			name: "invalid property type",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain rdfs:Resource;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "invalid property type for Field: Resource",
		},
		{
			name: "invalid order negative",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 8;
    qcl:order -1;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "invalid order for Field: -1",
		},
		{
			name: "invalid order non-numeric",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 8;
    qcl:order "abc";
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "invalid order for Field: abc",
		},
		{
			name: "missing order",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 8;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "field order unspecified for Field, add a qcl:order predicate",
		},
		{
			name: "invalid size zero",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 0;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "invalid size for Field: 0",
		},
		{
			name: "invalid size non-numeric",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:ByteArray;
    qcl:size "large";
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "invalid size for Field: large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.GenerateQCL(tt.document)
			
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateQCLBooleanType(t *testing.T) {
	parser := &TurtleRDFParser{}

	document := `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:IsActive a rdfs:Property;
    rdfs:domain qcl:Bool;
    qcl:order 0;
    rdfs:range test:TestClass.
test:Count a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 4;
    qcl:order 1;
    rdfs:range test:TestClass.`

	generated, err := parser.GenerateQCL(document)
	require.NoError(t, err)

	// Check struct generation
	assert.Contains(t, generated, "IsActive bool `rdf:\"test:IsActive,order=0\"`")
	assert.Contains(t, generated, "Count uint32 `rdf:\"test:Count,order=1\"`")

	// Check unmarshal function - bool should increment by 1
	assert.Contains(t, generated, "func UnmarshalTestClass(payload [5]byte) TestClass")
	
	// Check marshal function - bool should use if/else
	assert.Contains(t, generated, "func MarshalTestClass(obj TestClass) [5]byte")
	assert.Contains(t, generated, "if obj.IsActive { buf[0] = 0xff } else { buf[0] = 0x00 }")
}

func TestGenerateQCLMixedTypes(t *testing.T) {
	parser := &TurtleRDFParser{}

	document := `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:MixedType a rdfs:Class.
test:Flag a rdfs:Property;
    rdfs:domain qcl:Bool;
    qcl:order 0;
    rdfs:range test:MixedType.
test:SmallInt a rdfs:Property;
    rdfs:domain qcl:Int;
    qcl:size 1;
    qcl:order 1;
    rdfs:range test:MixedType.
test:Data a rdfs:Property;
    rdfs:domain qcl:ByteArray;
    qcl:size 32;
    qcl:order 2;
    rdfs:range test:MixedType.
test:Name a rdfs:Property;
    rdfs:domain qcl:String;
    qcl:size 16;
    qcl:order 3;
    rdfs:range test:MixedType.`

	generated, err := parser.GenerateQCL(document)
	require.NoError(t, err)

	// Check struct fields
	assert.Contains(t, generated, "Flag bool")
	assert.Contains(t, generated, "SmallInt int8")
	assert.Contains(t, generated, "Data [32]byte")
	assert.Contains(t, generated, "Name string")

	// Check total size calculation (1 + 1 + 32 + 16 = 50)
	assert.Contains(t, generated, "func UnmarshalMixedType(payload [50]byte)")
	assert.Contains(t, generated, "func MarshalMixedType(obj MixedType) [50]byte")

	// Check marshal operations
	lines := strings.Split(generated, "\n")
	marshalStart := -1
	for i, line := range lines {
		if strings.Contains(line, "func MarshalMixedType") {
			marshalStart = i
			break
		}
	}
	
	require.NotEqual(t, -1, marshalStart, "Marshal function not found")
	
	// Find the marshal function body
	marshalBody := []string{}
	for i := marshalStart; i < len(lines) && i < marshalStart+20; i++ {
		marshalBody = append(marshalBody, lines[i])
	}
	
	marshalText := strings.Join(marshalBody, "\n")
	
	// Check bool handling
	assert.Contains(t, marshalText, "if obj.Flag { buf[0] = 0xff } else { buf[0] = 0x00 }")
	
	// Check other field handling
	assert.Contains(t, marshalText, "binary.PutInt(buf, 1, obj.SmallInt)")
	assert.Contains(t, marshalText, "copy(buf[2:34], obj.Data)")
	assert.Contains(t, marshalText, "copy(buf[34:50], []byte(obj.Name))")
}

func TestGetTagsErrorCases(t *testing.T) {
	parser := &TurtleRDFParser{}

	tests := []struct {
		name        string
		document    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid RDF syntax",
			document:    "This is not valid RDF",
			expectError: true,
			errorMsg:    "get tags",
		},
		{
			name: "missing size",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:String;
    qcl:order 0;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "size unspecified",
		},
		{
			name: "missing order",
			document: `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain qcl:Bool;
    rdfs:range test:TestClass.`,
			expectError: true,
			errorMsg:    "field order unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.GetTags(tt.document)
			
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateQCLSpecialCases(t *testing.T) {
	parser := &TurtleRDFParser{}

	t.Run("uint256 for 32-byte uint", func(t *testing.T) {
		document := `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:Account a rdfs:Class.
test:Balance a rdfs:Property;
    rdfs:domain qcl:Uint;
    qcl:size 32;
    qcl:order 0;
    rdfs:range test:Account.`

		generated, err := parser.GenerateQCL(document)
		require.NoError(t, err)

		// Should use uint256 not uint32
		assert.Contains(t, generated, "Balance uint256")
		assert.NotContains(t, generated, "Balance uint32")
	})

	t.Run("rdfs:Literal property type", func(t *testing.T) {
		document := `PREFIX test: <https://types.quilibrium.com/test/>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

test:TestClass a rdfs:Class.
test:Field a rdfs:Property;
    rdfs:domain rdfs:Literal;
    qcl:order 0;
    rdfs:range test:TestClass.`

		generated, err := parser.GenerateQCL(document)
		require.NoError(t, err)

		// Should generate with Literal type
		assert.Contains(t, generated, "Field Literal")
	})
}