package schema

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateQCLCompleteExample(t *testing.T) {
	// Full RDF document
	rdfDocument := `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX account: <https://types.quilibrium.com/schema-repository/examples/token/account/>
PREFIX coin: <https://types.quilibrium.com/schema-repository/examples/token/coin/>
PREFIX pending: <https://types.quilibrium.com/schema-repository/examples/token/pending/>
PREFIX create: <https://types.quilibrium.com/schema-repository/examples/token/create/>
PREFIX allow: <https://types.quilibrium.com/schema-repository/examples/token/allow/>
PREFIX merge: <https://types.quilibrium.com/schema-repository/examples/token/merge/>
PREFIX mintauthorization: <https://types.quilibrium.com/schema-repository/examples/token/mintauthorization/>
PREFIX mint: <https://types.quilibrium.com/schema-repository/examples/token/mint/>
PREFIX mutualtransferrecipient: <https://types.quilibrium.com/schema-repository/examples/token/mutualtransferrecipient/>
PREFIX mutualtransfersender: <https://types.quilibrium.com/schema-repository/examples/token/mutualtransfersender/>
PREFIX allowance: <https://types.quilibrium.com/schema-repository/examples/token/allowance/>
PREFIX revoke: <https://types.quilibrium.com/schema-repository/examples/token/revoke/>
PREFIX mintauthority: <https://types.quilibrium.com/schema-repository/examples/token/mintauthority/>
PREFIX setmintauthority: <https://types.quilibrium.com/schema-repository/examples/token/setmintauthority/>
PREFIX split: <https://types.quilibrium.com/schema-repository/examples/token/split/>
PREFIX accept: <https://types.quilibrium.com/schema-repository/examples/token/accept/>
PREFIX intersectsender: <https://types.quilibrium.com/schema-repository/examples/token/intersectsender/>
PREFIX intersectrecipient: <https://types.quilibrium.com/schema-repository/examples/token/intersectrecipient/>
PREFIX reject: <https://types.quilibrium.com/schema-repository/examples/token/reject/>


account:Account a rdfs:Class;
  rdfs:label "an account object".
account:TotalBalance a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 0;
  rdfs:range account:Account.
account:PublicKey a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 57;
  qcl:order 1;
  rdfs:range account:Account.

coin:Coin a rdfs:Class;
  rdfs:label "an object containing a numeric balance and historical lineage".
coin:CoinBalance a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 0;
  rdfs:range coin:Coin.
coin:OwnerAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range coin:Coin.
coin:Lineage a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 1024;
  qcl:order 2;
  rdfs:range coin:Coin.

pending:PendingTransaction a rdfs:Class;
  rdfs:label "a pending transaction".
pending:ToAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 0;
  rdfs:range pending:PendingTransaction.
pending:RefundAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range pending:PendingTransaction.
pending:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 2;
  rdfs:range pending:PendingTransaction.

create:CreateTransactionRequest a rdfs:Class;
  rdfs:label "creates a pending transaction".
create:ToAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 0;
  rdfs:range create:CreateTransactionRequest.
create:RefundAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range create:CreateTransactionRequest.
create:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 2;
  rdfs:range create:CreateTransactionRequest.
create:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 3;
  rdfs:range create:CreateTransactionRequest.

allow:AllowRequest a rdfs:Class;
  rdfs:label "allows another address to create transaction requests and perform mutual transfers".
allow:AllowedAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 0;
  rdfs:range allow:AllowRequest.
allow:AllowedCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 1;
  rdfs:range allow:AllowRequest.
allow:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 2;
  rdfs:range allow:AllowRequest.

merge:MergeRequest a rdfs:Class;
  rdfs:label "merges two coin objects together".
merge:Left a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 0;
  rdfs:range merge:MergeRequest.
merge:Right a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 1;
  rdfs:range merge:MergeRequest.
merge:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 2;
  rdfs:range merge:MergeRequest.

mintauthorization:MintAuthorization a rdfs:Class;
  rdfs:label "a mint authorization".
mintauthorization:PublicKey a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 57;
  qcl:order 0;
  rdfs:range mintauthorization:MintAuthorization.
mintauthorization:Quantity a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 1;
  rdfs:range mintauthorization:MintAuthorization.

mint:MintRequest a rdfs:Class;
  rdfs:label "performs a mint operation".
mint:Quantity a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 0;
  rdfs:range mint:MintRequest.
mint:DestinationAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range mint:MintRequest.
mint:MintAuthorization a rdfs:Property;
  rdfs:domain mintauthorization:MintAuthorization;
  qcl:order 2;
  rdfs:range mint:MintRequest.
mint:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 3;
  rdfs:range mint:MintRequest.

mutualtransfersender:MutualTransferSenderRequest a rdfs:Class;
  rdfs:label "performs a mutual transfer, from the sending side".
mutualtransfersender:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 0;
  rdfs:range mutualtransfersender:MutualTransferSenderRequest.
mutualtransfersender:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 1;
  rdfs:range mutualtransfersender:MutualTransferSenderRequest.

mutualtransferrecipient:MutualTransferRecipientRequest a rdfs:Class;
  rdfs:label "performs a mutual transfer, from the receiving side".
mutualtransferrecipient:ToAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 0;
  rdfs:range mutualtransferrecipient:MutualTransferRecipientRequest.
mutualtransferrecipient:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 1;
  rdfs:range mutualtransferrecipient:MutualTransferRecipientRequest.

allowance:Allowance a rdfs:Class;
  rdfs:label "an allowed account that can create transaction requests and perform mutual transfers".
allowance:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 0;
  rdfs:range allowance:Allowance.
allowance:AllowedAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range allowance:Allowance.

revoke:RevokeRequest a rdfs:Class;
  rdfs:label "revokes a previous allowance".
revoke:Allowance a rdfs:Property;
  rdfs:domain allowance:Allowance;
  qcl:order 0;
  rdfs:range revoke:RevokeRequest.
revoke:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 1;
  rdfs:range revoke:RevokeRequest.

mintauthority:MintAuthority a rdfs:Class;
  rdfs:label "the authority account allowed to issue mint authorizations".
mintauthority:AuthorizedAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 0;
  rdfs:range mintauthority:MintAuthority.

setmintauthority:SetMintAuthorityRequest a rdfs:Class;
  rdfs:label "sets the authority address for performing mint operations".
setmintauthority:MintAuthority a rdfs:Property;
  rdfs:domain mintauthority:MintAuthority;
  qcl:order 0;
  rdfs:range setmintauthority:SetMintAuthorityRequest.
setmintauthority:AuthorizedAccount a rdfs:Property;
  rdfs:domain account:Account;
  qcl:order 1;
  rdfs:range setmintauthority:SetMintAuthorityRequest.
setmintauthority:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 2;
  rdfs:range setmintauthority:SetMintAuthorityRequest.

split:SplitRequest a rdfs:Class;
  rdfs:label "splits a coin into two coin objects".
split:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 0;
  rdfs:range split:SplitRequest.
split:LeftAmount a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 1;
  rdfs:range split:SplitRequest.
split:RightAmount a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 32;
  qcl:order 2;
  rdfs:range split:SplitRequest.
split:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 3;
  rdfs:range split:SplitRequest.

accept:AcceptRequest a rdfs:Class;
  rdfs:label "accepts a pending transfer".
accept:PendingTransaction a rdfs:Property;
  rdfs:domain pending:PendingTransaction;
  qcl:order 0;
  rdfs:range accept:AcceptRequest.
accept:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 1;
  rdfs:range accept:AcceptRequest.

intersectsender:IntersectSenderRequest a rdfs:Class;
  rdfs:label "performs a private set intersection comparison, from the sending side".
intersectsender:OfCoin a rdfs:Property;
  rdfs:domain coin:Coin;
  qcl:order 0;
  rdfs:range intersectsender:IntersectSenderRequest.

intersectrecipient:IntersectRecipientRequest a rdfs:Class;
  rdfs:label "performs a private set intersection comparison, from the receiving side".
intersectrecipient:Lineage a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 1024;
  qcl:order 0;
  rdfs:range intersectrecipient:IntersectRecipientRequest.

reject:RejectRequest a rdfs:Class;
  rdfs:label "rejects a pending transfer".
reject:PendingTransaction a rdfs:Property;
  rdfs:domain pending:PendingTransaction;
  qcl:order 0;
  rdfs:range reject:RejectRequest.
reject:Signature a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 114;
  qcl:order 1;
  rdfs:range reject:RejectRequest.
`

	parser := &TurtleRDFParser{}
	generated, err := parser.GenerateQCL(rdfDocument)
	require.NoError(t, err)

	// Normalize whitespace for comparison
	generated = strings.TrimSpace(generated)
	
	// Expected structs in the output
	expectedStructs := []struct {
		name   string
		fields []struct {
			name      string
			typ       string
			tag       string
		}
	}{
		{
			name: "AcceptRequest",
			fields: []struct {
				name string
				typ  string
				tag  string
			}{
				{name: "PendingTransaction", typ: "hypergraph.Extrinsic", tag: `accept:PendingTransaction,extrinsic=pending:PendingTransaction,order=0`},
				{name: "Signature", typ: "[114]byte", tag: `accept:Signature,order=1,size=114`},
			},
		},
		{
			name: "Account",
			fields: []struct {
				name string
				typ  string
				tag  string
			}{
				{name: "TotalBalance", typ: "uint256", tag: `account:TotalBalance,order=0`},
				{name: "PublicKey", typ: "[57]byte", tag: `account:PublicKey,order=1,size=57`},
			},
		},
		{
			name: "AllowRequest",
			fields: []struct {
				name string
				typ  string
				tag  string
			}{
				{name: "AllowedAccount", typ: "hypergraph.Extrinsic", tag: `allow:AllowedAccount,extrinsic=account:Account,order=0`},
				{name: "AllowedCoin", typ: "hypergraph.Extrinsic", tag: `allow:AllowedCoin,extrinsic=coin:Coin,order=1`},
				{name: "Signature", typ: "[114]byte", tag: `allow:Signature,order=2,size=114`},
			},
		},
		{
			name: "Coin",
			fields: []struct {
				name string
				typ  string
				tag  string
			}{
				{name: "CoinBalance", typ: "uint256", tag: `coin:CoinBalance,order=0`},
				{name: "OwnerAccount", typ: "hypergraph.Extrinsic", tag: `coin:OwnerAccount,extrinsic=account:Account,order=1`},
				{name: "Lineage", typ: "[1024]byte", tag: `coin:Lineage,order=2,size=1024`},
			},
		},
		{
			name: "MintRequest",
			fields: []struct {
				name string
				typ  string
				tag  string
			}{
				{name: "Quantity", typ: "uint256", tag: `mint:Quantity,order=0`},
				{name: "DestinationAccount", typ: "hypergraph.Extrinsic", tag: `mint:DestinationAccount,extrinsic=account:Account,order=1`},
				{name: "MintAuthorization", typ: "hypergraph.Extrinsic", tag: `mint:MintAuthorization,extrinsic=mintauthorization:MintAuthorization,order=2`},
				{name: "Signature", typ: "[114]byte", tag: `mint:Signature,order=3,size=114`},
			},
		},
	}

	// Check that each expected struct is present with correct fields
	for _, expectedStruct := range expectedStructs {
		t.Run(expectedStruct.name, func(t *testing.T) {
			// Find the struct definition
			structDef := "type " + expectedStruct.name + " struct {"
			structStart := strings.Index(generated, structDef)
			require.NotEqual(t, -1, structStart, "Struct %s not found", expectedStruct.name)
			
			// Find the end of the struct
			structEnd := strings.Index(generated[structStart:], "}")
			require.NotEqual(t, -1, structEnd, "Struct %s closing brace not found", expectedStruct.name)
			
			structBody := generated[structStart : structStart+structEnd+1]
			
			// Check each field
			for _, field := range expectedStruct.fields {
				fieldLine := field.name + " " + field.typ + " `rdf:\"" + field.tag + "\"`"
				assert.Contains(t, structBody, fieldLine, 
					"Struct %s missing field: %s", expectedStruct.name, fieldLine)
			}
		})
	}

	// Verify that all struct tags can be parsed
	lines := strings.Split(generated, "\n")
	for _, line := range lines {
		if tagStart := strings.Index(line, "`rdf:\""); tagStart != -1 {
			tagEnd := strings.Index(line[tagStart:], "\"`")
			if tagEnd != -1 {
				tagValue := line[tagStart+6 : tagStart+tagEnd]
				parsedTag, err := ParseRDFTag(tagValue)
				assert.NoError(t, err, "Failed to parse generated tag: %s", tagValue)
				
				// Verify tag has order
				assert.GreaterOrEqual(t, parsedTag.Order, 0, "Tag missing order: %s", tagValue)
			}
		}
	}
	
	// Verify unmarshal functions are generated
	assert.Contains(t, generated, "func UnmarshalAcceptRequest(payload [146]byte) AcceptRequest")
	assert.Contains(t, generated, "func UnmarshalAccount(payload [89]byte) Account")
	assert.Contains(t, generated, "func UnmarshalMintRequest(payload [210]byte) MintRequest")
	
	// Verify marshal functions are generated
	assert.Contains(t, generated, "func MarshalAcceptRequest(obj AcceptRequest) [146]byte")
	assert.Contains(t, generated, "func MarshalAccount(obj Account) [89]byte")
	assert.Contains(t, generated, "func MarshalMintRequest(obj MintRequest) [210]byte")
	
	// Check specific type mappings
	assert.Contains(t, generated, "uint256") // 32-byte Uint should map to uint256
	assert.NotContains(t, generated, "uint32") // Should not use uint32 for 32-byte values
}