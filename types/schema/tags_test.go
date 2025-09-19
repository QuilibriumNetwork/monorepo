package schema

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
)

// Test structures
type ValidStruct struct {
	Quantity           uint64               `rdf:"mint:Quantity"`
	DestinationAccount hypergraph.Extrinsic `rdf:"mint:DestinationAccount,extrinsic=account:Account"`
	MintAuthorization  hypergraph.Extrinsic `rdf:"mint:MintAuthorization,extrinsic=mintauthorization:MintAuthorization"`
	Signature          [114]byte            `rdf:"mint:Signature"`
}

type StructWithOrder struct {
	Field3 uint32   `rdf:"test:Field3,order=2"`
	Field1 uint64   `rdf:"test:Field1,order=0"`
	Field2 [32]byte `rdf:"test:Field2,order=1"`
}

type StructWithCompleteOrder struct {
	FieldA string               `rdf:"test:FieldA,order=0,size=32"`
	FieldB uint64               `rdf:"test:FieldB,order=1"`
	FieldC []byte               `rdf:"test:FieldC,order=2,size=64"`
	FieldD hypergraph.Extrinsic `rdf:"test:FieldD,order=3,extrinsic=foo:Bar"`
}

type StructWithSizes struct {
	Name   string   `rdf:"test:Name,size=64"`
	Data   []byte   `rdf:"test:Data,size=128"`
	Amount *big.Int `rdf:"test:Amount,size=32"`
	Count  uint     `rdf:"test:Count,size=8"`
}

type InvalidStructMissingExtrinsic struct {
	Account hypergraph.Extrinsic `rdf:"test:Account"` // Missing extrinsic key
}

type InvalidStructWithExtrinsicOnNonExtrinsic struct {
	Value uint64 `rdf:"test:Value,extrinsic=foo:Bar"` // extrinsic on non-Extrinsic type
}

type InvalidStructMissingSize struct {
	Name string `rdf:"test:Name"` // Missing required size
}

type InvalidStructWithSizeOnExtrinsic struct {
	Account hypergraph.Extrinsic `rdf:"test:Account,extrinsic=account:Account,size=32"` // Size on Extrinsic
}

type InvalidStructBadType struct {
	Data map[string]string `rdf:"test:Data"` // Unsupported type
}

type InvalidStructPointer struct {
	Value *uint64 `rdf:"test:Value"` // Pointer type not allowed (except *big.Int)
}

type StructWithPartialOrder struct {
	Field1 uint64 `rdf:"test:Field1,order=0"`
	Field2 uint32 `rdf:"test:Field2"` // Missing order when others have it
}

type StructWithDuplicateOrder struct {
	Field1 uint64 `rdf:"test:Field1,order=0"`
	Field2 uint32 `rdf:"test:Field2,order=0"` // Duplicate order
	Field3 uint16 `rdf:"test:Field3,order=1"`
}

type StructWithNonSequentialOrder struct {
	Field1 uint64 `rdf:"test:Field1,order=0"`
	Field2 uint32 `rdf:"test:Field2,order=2"` // Skip order 1
	Field3 uint16 `rdf:"test:Field3,order=3"`
}

func TestParseRDFTag(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		want    *RDFTag
		wantErr bool
	}{
		{
			name: "simple tag",
			tag:  "mint:Quantity",
			want: &RDFTag{
				Name:  "mint:Quantity",
				Order: -1,
				Raw:   "mint:Quantity",
			},
		},
		{
			name: "tag with extrinsic",
			tag:  "mint:DestinationAccount,extrinsic=account:Account",
			want: &RDFTag{
				Name:      "mint:DestinationAccount",
				Extrinsic: "account:Account",
				Order:     -1,
				Raw:       "mint:DestinationAccount,extrinsic=account:Account",
			},
		},
		{
			name: "tag with order",
			tag:  "test:Field,order=2",
			want: &RDFTag{
				Name:  "test:Field",
				Order: 2,
				Raw:   "test:Field,order=2",
			},
		},
		{
			name: "tag with size",
			tag:  "test:Data,size=128",
			want: &RDFTag{
				Name:  "test:Data",
				Order: -1,
				Size:  intPtr(128),
				Raw:   "test:Data,size=128",
			},
		},
		{
			name: "tag with all attributes",
			tag:  "test:Field,order=1,size=64",
			want: &RDFTag{
				Name:  "test:Field",
				Order: 1,
				Size:  intPtr(64),
				Raw:   "test:Field,order=1,size=64",
			},
		},
		{
			name:    "empty tag",
			tag:     "",
			wantErr: true,
		},
		{
			name:    "invalid order",
			tag:     "test:Field,order=abc",
			wantErr: true,
		},
		{
			name:    "negative order",
			tag:     "test:Field,order=-1",
			wantErr: true,
		},
		{
			name:    "invalid size",
			tag:     "test:Field,size=0",
			wantErr: true,
		},
		{
			name:    "unknown key",
			tag:     "test:Field,unknown=value",
			wantErr: true,
		},
		{
			name:    "malformed key-value",
			tag:     "test:Field,order",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRDFTag(tt.tag)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateStructTags(t *testing.T) {
	tests := []struct {
		name    string
		typ     reflect.Type
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid struct",
			typ:  reflect.TypeOf(ValidStruct{}),
		},
		{
			name: "struct with order",
			typ:  reflect.TypeOf(StructWithOrder{}),
		},
		{
			name: "struct with complete sequential order",
			typ:  reflect.TypeOf(StructWithCompleteOrder{}),
		},
		{
			name: "struct with sizes",
			typ:  reflect.TypeOf(StructWithSizes{}),
		},
		{
			name:    "missing extrinsic key",
			typ:     reflect.TypeOf(InvalidStructMissingExtrinsic{}),
			wantErr: true,
			errMsg:  "extrinsic key must be specified",
		},
		{
			name:    "extrinsic on wrong type",
			typ:     reflect.TypeOf(InvalidStructWithExtrinsicOnNonExtrinsic{}),
			wantErr: true,
			errMsg:  "extrinsic key can only be specified",
		},
		{
			name:    "missing size for string",
			typ:     reflect.TypeOf(InvalidStructMissingSize{}),
			wantErr: true,
			errMsg:  "size must be specified for string",
		},
		{
			name:    "size on extrinsic",
			typ:     reflect.TypeOf(InvalidStructWithSizeOnExtrinsic{}),
			wantErr: true,
			errMsg:  "size must not be specified for hypergraph.Extrinsic",
		},
		{
			name:    "unsupported type",
			typ:     reflect.TypeOf(InvalidStructBadType{}),
			wantErr: true,
			errMsg:  "unsupported field type",
		},
		{
			name:    "invalid pointer type",
			typ:     reflect.TypeOf(InvalidStructPointer{}),
			wantErr: true,
			errMsg:  "pointer types not allowed except *big.Int",
		},
		{
			name:    "partial order specification",
			typ:     reflect.TypeOf(StructWithPartialOrder{}),
			wantErr: true,
			errMsg:  "order must be specified for all fields with rdf tags or none at all",
		},
		{
			name:    "duplicate order values",
			typ:     reflect.TypeOf(StructWithDuplicateOrder{}),
			wantErr: true,
			errMsg:  "duplicate order 0",
		},
		{
			name:    "non-sequential order values",
			typ:     reflect.TypeOf(StructWithNonSequentialOrder{}),
			wantErr: true,
			errMsg:  "missing order 1 in sequence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateStructTags(tt.typ)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetFieldOrder(t *testing.T) {
	t.Run("explicit order", func(t *testing.T) {
		typ := reflect.TypeOf(StructWithOrder{})
		tags, err := ValidateStructTags(typ)
		require.NoError(t, err)

		order := GetFieldOrder(tags, typ)

		// Fields should be ordered by their order tag
		assert.Equal(t, []string{"Field1", "Field2", "Field3"}, order)
	})

	t.Run("complete sequential order", func(t *testing.T) {
		typ := reflect.TypeOf(StructWithCompleteOrder{})
		tags, err := ValidateStructTags(typ)
		require.NoError(t, err)

		order := GetFieldOrder(tags, typ)

		// Fields should be ordered by their order tag
		assert.Equal(t, []string{"FieldA", "FieldB", "FieldC", "FieldD"}, order)
	})

	t.Run("default order", func(t *testing.T) {
		typ := reflect.TypeOf(ValidStruct{})
		tags, err := ValidateStructTags(typ)
		require.NoError(t, err)

		order := GetFieldOrder(tags, typ)

		// Fields should maintain struct order
		assert.Equal(t, []string{"Quantity", "DestinationAccount", "MintAuthorization", "Signature"}, order)
	})
}

func TestGetFieldSize(t *testing.T) {
	tests := []struct {
		name      string
		fieldType reflect.Type
		tag       *RDFTag
		want      int
		wantErr   bool
	}{
		{
			name:      "explicit size",
			fieldType: reflect.TypeOf(""),
			tag:       &RDFTag{Order: -1, Size: intPtr(64)},
			want:      64,
		},
		{
			name:      "bool type",
			fieldType: reflect.TypeOf(true),
			tag:       &RDFTag{Order: -1},
			want:      1,
		},
		{
			name:      "uint64 type",
			fieldType: reflect.TypeOf(uint64(0)),
			tag:       &RDFTag{Order: -1},
			want:      8,
		},
		{
			name:      "byte array",
			fieldType: reflect.TypeOf([32]byte{}),
			tag:       &RDFTag{Order: -1},
			want:      32,
		},
		{
			name:      "hypergraph.Extrinsic",
			fieldType: reflect.TypeOf(hypergraph.Extrinsic{}),
			tag:       &RDFTag{Order: -1},
			want:      32,
		},
		{
			name:      "*big.Int without size",
			fieldType: reflect.TypeOf((*big.Int)(nil)),
			tag:       &RDFTag{Order: -1},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetFieldSize(tt.fieldType, tt.tag)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestValidateFieldType(t *testing.T) {
	tests := []struct {
		name      string
		fieldType reflect.Type
		tag       *RDFTag
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid uint64",
			fieldType: reflect.TypeOf(uint64(0)),
			tag:       &RDFTag{Order: -1},
		},
		{
			name:      "valid byte array",
			fieldType: reflect.TypeOf([32]byte{}),
			tag:       &RDFTag{Order: -1},
		},
		{
			name:      "valid string with size",
			fieldType: reflect.TypeOf(""),
			tag:       &RDFTag{Order: -1, Size: intPtr(64)},
		},
		{
			name:      "valid []byte with size",
			fieldType: reflect.TypeOf([]byte{}),
			tag:       &RDFTag{Order: -1, Size: intPtr(128)},
		},
		{
			name:      "valid *big.Int with size",
			fieldType: reflect.TypeOf((*big.Int)(nil)),
			tag:       &RDFTag{Order: -1, Size: intPtr(32)},
		},
		{
			name:      "valid hypergraph.Extrinsic",
			fieldType: reflect.TypeOf(hypergraph.Extrinsic{}),
			tag:       &RDFTag{Order: -1, Extrinsic: "account:Account"},
		},
		{
			name:      "string without size",
			fieldType: reflect.TypeOf(""),
			tag:       &RDFTag{Order: -1},
			wantErr:   true,
			errMsg:    "size must be specified for string",
		},
		{
			name:      "slice without size",
			fieldType: reflect.TypeOf([]byte{}),
			tag:       &RDFTag{Order: -1},
			wantErr:   true,
			errMsg:    "size must be specified for slice",
		},
		{
			name:      "*big.Int without size",
			fieldType: reflect.TypeOf((*big.Int)(nil)),
			tag:       &RDFTag{Order: -1},
			wantErr:   true,
			errMsg:    "size must be specified for *big.Int",
		},
		{
			name:      "non-byte slice",
			fieldType: reflect.TypeOf([]int{}),
			tag:       &RDFTag{Order: -1, Size: intPtr(32)},
			wantErr:   true,
			errMsg:    "only []byte slices are allowed",
		},
		{
			name:      "invalid pointer",
			fieldType: reflect.TypeOf((*uint64)(nil)),
			tag:       &RDFTag{Order: -1},
			wantErr:   true,
			errMsg:    "pointer types not allowed except *big.Int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFieldType(tt.fieldType, tt.tag)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function
func intPtr(i int) *int {
	return &i
}
