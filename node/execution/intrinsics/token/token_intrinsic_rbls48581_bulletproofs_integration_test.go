//go:build integrationtest
// +build integrationtest

package token_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func generateRDFPrelude(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) string {
	appAddressHex := hex.EncodeToString(appAddress)

	prelude := "BASE <https://types.quilibrium.com/schema-repository/>\n" +
		"PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
		"PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n" +
		"PREFIX qcl: <https://types.quilibrium.com/qcl/>\n" +
		"PREFIX coin: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/coin/>\n"

	if config.Behavior&token.Acceptable != 0 {
		prelude += "PREFIX pending: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/pending/>\n"
	}

	prelude += "\n"

	return prelude
}

func prepareRDFSchemaFromConfig(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) (string, error) {
	schema := generateRDFPrelude(appAddress, config)

	schema += "coin:Coin a rdfs:Class.\n" +
		"coin:FrameNumber a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 8;\n" +
		"  qcl:order 0;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Commitment a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 1;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:OneTimeKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 2;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:VerificationKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 3;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:CoinBalance a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 4;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Mask a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 5;\n" +
		"  rdfs:range coin:Coin.\n"

	if config.Behavior&token.Divisible == 0 {
		schema += "coin:AdditionalReference a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 64;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range coin:Coin.\n"
		schema += "coin:AdditionalReferenceKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range coin:Coin.\n"
	}

	if config.Behavior&token.Acceptable != 0 {
		schema += "\npending:PendingTransaction a rdfs:Class;\n" +
			"  rdfs:label \"a pending transaction\".\n" +
			"pending:FrameNumber a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 8;\n" +
			"  qcl:order 0;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:Commitment a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 1;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 2;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 3;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 4;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 5;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 8;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 9;\n" +
			"  rdfs:range pending:PendingTransaction.\n"

		if config.Behavior&token.Divisible == 0 {
			schema += "pending:ToAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 10;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:ToAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 11;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 12;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 13;\n" +
				"  rdfs:range pending:PendingTransaction.\n"
		}

		if config.Behavior&token.Expirable != 0 {
			schema += "pending:Expiration a rdfs:Property;\n" +
				"  rdfs:domain qcl:Uint;\n" +
				"  qcl:size 8;\n"

			if config.Behavior&token.Divisible == 0 {
				schema += "  qcl:order 14;\n"
			} else {
				schema += "  qcl:order 10;\n"
			}

			schema += "  rdfs:range pending:PendingTransaction.\n"
		}
	}

	schema += "\n"

	return schema, nil
}

func TestValidMintWithProofOfMeaningfulWorkTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	_, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	_, err = km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	prover, _, err := km.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	assert.NoError(t, err)

	proveraddr, err := poseidon.HashBytes(prover.Public().([]byte))
	txn, _ := hg.NewTransaction(false)
	rand1 := make([]byte, 32)
	rand2 := make([]byte, 32)
	rand3 := make([]byte, 32)
	rand.Read(rand1[1:])
	rand.Read(rand2)
	rand.Read(rand3)
	tree := &qcrypto.VectorCommitmentTree{}
	tree.Insert([]byte{0}, proveraddr.FillBytes(make([]byte, 32)), nil, big.NewInt(0))
	tree.Insert([]byte{1 << 2}, big.NewInt(10000).FillBytes(make([]byte, 32)), nil, big.NewInt(0))
	vert := hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(proveraddr.FillBytes(make([]byte, 32))), tree.Commit(ip, false), big.NewInt(74))
	err = hg.AddVertex(txn, vert)
	assert.NoError(t, err)
	err = hg.SetVertexData(txn, [64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS[:], proveraddr.FillBytes(make([]byte, 32)))), tree)
	assert.NoError(t, err)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(rand1), nil, big.NewInt(74)))
	err = txn.Commit()
	assert.NoError(t, err)
	hg.Commit()
	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	input, err := token.NewMintTransactionInput(big.NewInt(10000), proveraddr.FillBytes(make([]byte, 32)))
	assert.NoError(t, err)

	output, err := token.NewMintTransactionOutput(big.NewInt(10000), vk.Public(), sk.Public())
	assert.NoError(t, err)

	tokenconfig := token.QUIL_TOKEN_CONFIGURATION

	// Create RDF multiprover for testing
	rdfSchema, _ := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{output},
		[]*big.Int{}, // although this is simulated, mints of QUIL are free.
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithVerkleMultiproofSignatureTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	otk1, _ := dc.New()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	image, _ := a1.Add(psk.Public())

	message := slices.Concat(
		big.NewInt(10000).FillBytes(make([]byte, 32)),
		image,
	)

	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)

	rand1 := make([]byte, len(message))
	rand2 := make([]byte, len(message))
	rand3 := make([]byte, len(message))
	rand.Read(rand1)
	rand.Read(rand2)
	rand.Read(rand3)

	proofTree := &qcrypto.VectorCommitmentTree{}
	proofTree.Insert([]byte{0x00, 0x00}, message, nil, big.NewInt(int64(len(message))))
	proofTree.Insert([]byte{0x00, 0x01}, rand1, nil, big.NewInt(int64(len(message))))
	proofTree.Insert([]byte{0x00, 0x02}, rand2, nil, big.NewInt(int64(len(message))))
	proofTree.Insert([]byte{0x00, 0x03}, rand3, nil, big.NewInt(int64(len(message))))
	root := proofTree.Commit(ip, false)

	tp, err := proofTree.Prove(ip, []byte{0x00, 0x00}).ToBytes()
	assert.NoError(t, err)
	output := slices.Concat(
		tp,
		message,
		otk1.Private(),
	)

	input, err := token.NewMintTransactionInput(big.NewInt(10000), output)
	assert.NoError(t, err)

	out, err := token.NewMintTransactionOutput(big.NewInt(10000), vk.Public(), sk.Public())
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.VerkleMultiproofWithSignature,
			VerkleRoot:   root,
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{out},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithAuthorityTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	authorityKey, _, err := km.CreateSigningKey("foobar", crypto.KeyTypeEd448)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	otk1, _ := dc.New()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	image, _ := a1.Add(psk.Public())

	message := slices.Concat(
		big.NewInt(10000).FillBytes(make([]byte, 32)),
		image,
	)

	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)
	// <value> | <image> | <signature> | <one time private key>
	signature, err := authorityKey.SignWithDomain(message, mintdomain)
	assert.NoError(t, err)

	output := slices.Concat(
		message,
		signature,
		otk1.Private(),
	)

	input, err := token.NewMintTransactionInput(big.NewInt(10000), output)
	assert.NoError(t, err)

	out, err := token.NewMintTransactionOutput(big.NewInt(10000), vk.Public(), sk.Public())
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithAuthority,
			Authority: &token.Authority{
				PublicKey: authorityKey.Public().([]byte),
				KeyType:   crypto.KeyTypeEd448,
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{out},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithSignatureTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	authorityKey, _, err := km.CreateSigningKey("foobar", crypto.KeyTypeEd448)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	otk1, _ := dc.New()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	image, _ := a1.Add(psk.Public())

	message := slices.Concat(
		big.NewInt(10000).FillBytes(make([]byte, 32)),
		image,
	)

	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)
	// <value> | <image> | <signature> | <one time private key>
	signature, err := authorityKey.SignWithDomain(message, mintdomain)
	assert.NoError(t, err)

	output := slices.Concat(
		message,
		signature,
		otk1.Private(),
	)

	input, err := token.NewMintTransactionInput(big.NewInt(10000), output)
	assert.NoError(t, err)

	out, err := token.NewMintTransactionOutput(big.NewInt(10000), pvk.Public(), psk.Public())
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithSignature,
			Authority: &token.Authority{
				PublicKey: authorityKey.Public().([]byte),
				KeyType:   crypto.KeyTypeEd448,
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{out},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithPaymentZeroFeeBasisTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	_, err = km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	otk1, _ := dc.New()
	c1, _ := dc.New()

	mask1 := c1.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	big.NewInt(8000000001).FillBytes(maskedCoinBalanceBytes1)
	slices.Reverse(maskedCoinBalanceBytes1)
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}

	output := slices.Concat(c1.Private(), otk1.Private(), rvk.Public(), rsk.Public())

	input, err := token.NewMintTransactionInput(big.NewInt(1), output)
	assert.NoError(t, err)

	out, err := token.NewMintTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	assert.NoError(t, err)

	recipientAddress, err := poseidon.HashBytes(slices.Concat(rvk.Public(), rsk.Public()))
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior:   token.MintWithPayment,
			PaymentAddress: recipientAddress.FillBytes(make([]byte, 32)),
			FeeBasis: &token.FeeBasis{
				Type:     token.NoFeeBasis,
				Baseline: big.NewInt(0),
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{out},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithPaymentNonDivisibleNonZeroFeeBasisValidQuantityTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(4000000000), rvk.Public(), rsk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}

	out2, err := token.NewPendingTransactionOutput(big.NewInt(4000000000), rvk.Public(), rsk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}

	out3, err := token.NewMintTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	out4, err := token.NewMintTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	c1, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(8000000004)}, c1.Private())
	mask1 := c1.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	big.NewInt(8000000004).FillBytes(maskedCoinBalanceBytes1)
	slices.Reverse(maskedCoinBalanceBytes1)
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}
	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1},
		[]*token.PendingTransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}, // Tricky bit: sumcheck needs to verify fee distro, but also secondary fee carries into the other tx
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 2); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, false), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}

	output1 := slices.Concat(output, tx.Outputs[0].GetBlind(), tx.Outputs[0].GetEphemeralKey(), rvk.Public(), rsk.Public())
	output2 := slices.Concat(output, tx.Outputs[1].GetBlind(), tx.Outputs[1].GetEphemeralKey(), rvk.Public(), rsk.Public())

	input2, err := token.NewMintTransactionInput(big.NewInt(1), output1)
	assert.NoError(t, err)

	input3, err := token.NewMintTransactionInput(big.NewInt(1), output2)
	assert.NoError(t, err)

	recipientAddress, err := poseidon.HashBytes(slices.Concat(rvk.Public(), rsk.Public()))
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior:   token.MintWithPayment,
			PaymentAddress: recipientAddress.FillBytes(make([]byte, 32)),
			FeeBasis: &token.FeeBasis{
				Type:     token.PerUnit,
				Baseline: big.NewInt(4000000000),
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err = prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser = &schema.TurtleRDFParser{}
	rdfMultiprover = schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input2, input3},
		[]*token.MintTransactionOutput{out3, out4},
		[]*big.Int{big.NewInt(1), big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidMintWithPaymentNonDivisibleNonZeroFeeBasisInvalidQuantityTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(8000000000), rvk.Public(), rsk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// This should fail:
	out2, err := token.NewMintTransactionOutput(big.NewInt(2), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	c1, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(8000000002)}, c1.Private())
	mask1 := c1.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	big.NewInt(8000000002).FillBytes(maskedCoinBalanceBytes1)
	slices.Reverse(maskedCoinBalanceBytes1)
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}
	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1},
		[]*token.PendingTransactionOutput{out1},
		[]*big.Int{big.NewInt(1), big.NewInt(1)}, // Tricky bit: sumcheck needs to verify fee distro, but also secondary fee carries into the other tx
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 2); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}

	output = slices.Concat(output, tx.Outputs[0].GetBlind(), tx.Outputs[0].GetEphemeralKey(), rvk.Public(), rsk.Public())

	input2, err := token.NewMintTransactionInput(big.NewInt(2), output)
	assert.NoError(t, err)

	recipientAddress, err := poseidon.HashBytes(slices.Concat(rvk.Public(), rsk.Public()))
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior:   token.MintWithPayment,
			PaymentAddress: recipientAddress.FillBytes(make([]byte, 32)),
			FeeBasis: &token.FeeBasis{
				Type:     token.PerUnit,
				Baseline: big.NewInt(4000000000),
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err = prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser = &schema.TurtleRDFParser{}
	rdfMultiprover = schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input2},
		[]*token.MintTransactionOutput{out2},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.Error(t, err)
	assert.False(t, valid)
}

func TestValidMintWithPaymentNonZeroFeeBasisTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(8000000000), rvk.Public(), rsk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := token.NewMintTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	c1, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(8000000002)}, c1.Private())
	mask1 := c1.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	big.NewInt(8000000002).FillBytes(maskedCoinBalanceBytes1)
	slices.Reverse(maskedCoinBalanceBytes1)
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}
	mintdomain := make([]byte, 32)
	rand.Read(mintdomain)

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1},
		[]*token.PendingTransactionOutput{out1},
		[]*big.Int{big.NewInt(1), big.NewInt(1)}, // Tricky bit: sumcheck needs to verify fee distro, but also secondary fee carries into the other tx
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 2); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}

	output = slices.Concat(output, tx.Outputs[0].GetBlind(), tx.Outputs[0].GetEphemeralKey(), rvk.Public(), rsk.Public())

	input2, err := token.NewMintTransactionInput(big.NewInt(1), output)
	assert.NoError(t, err)

	recipientAddress, err := poseidon.HashBytes(slices.Concat(rvk.Public(), rsk.Public()))
	assert.NoError(t, err)

	mintconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior:   token.MintWithPayment,
			PaymentAddress: recipientAddress.FillBytes(make([]byte, 32)),
			FeeBasis: &token.FeeBasis{
				Type:     token.PerUnit,
				Baseline: big.NewInt(8000000000),
			},
		},
		Units:  big.NewInt(1),
		Name:   "Bongocat",
		Symbol: "BONGOCAT",
	}

	// Create RDF multiprover for testing
	rdfSchema, err = prepareRDFSchemaFromConfig(mintdomain, mintconfig)
	assert.NoError(t, err)
	parser = &schema.TurtleRDFParser{}
	rdfMultiprover = schema.NewRDFMultiprover(parser, ip)

	minttx := token.NewMintTransaction(
		[32]byte(mintdomain),
		[]*token.MintTransactionInput{input2},
		[]*token.MintTransactionOutput{out2},
		[]*big.Int{big.NewInt(1)},
		mintconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = minttx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)

	valid, err := minttx.Verify(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestValidPendingTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(7), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := token.NewPendingTransactionOutput(big.NewInt(2), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	tree2 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	otk2, _ := dc.New()
	c1, _ := dc.New()
	c2, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(3)}, c1.Private())
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(9)}, c2.Private())
	mask1 := c1.Private()
	mask2 := c2.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())
	a2, _ := otk2.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	maskedCoinBalanceBytes1[0] = 0x03
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}
	blindMask2 := make([]byte, 56)
	coinMask2 := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2)

	for i := range blindMask2 {
		mask2[i] ^= blindMask2[i]
	}
	maskedCoinBalanceBytes2 := make([]byte, 56)
	maskedCoinBalanceBytes2[0] = 0x09
	for i := range maskedCoinBalanceBytes2 {
		maskedCoinBalanceBytes2[i] ^= coinMask2[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))
	verifkey2, _ := a2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, verifkey2, nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, maskedCoinBalanceBytes2, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, mask2, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address2[32:]), tree2.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address2, tree2)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	input2, _ := token.NewPendingTransactionInput(address2[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1, input2},
		[]*token.PendingTransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 2); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, false), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}

func TestValidPendingTransactionFeeOnly(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(0), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	tree2 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	otk2, _ := dc.New()
	c1, _ := dc.New()
	c2, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(3)}, c1.Private())
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(9)}, c2.Private())
	mask1 := c1.Private()
	mask2 := c2.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())
	a2, _ := otk2.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	maskedCoinBalanceBytes1[0] = 0x03
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}
	blindMask2 := make([]byte, 56)
	coinMask2 := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2)

	for i := range blindMask2 {
		mask2[i] ^= blindMask2[i]
	}
	maskedCoinBalanceBytes2 := make([]byte, 56)
	maskedCoinBalanceBytes2[0] = 0x09
	for i := range maskedCoinBalanceBytes2 {
		maskedCoinBalanceBytes2[i] ^= coinMask2[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))
	verifkey2, _ := a2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, verifkey2, nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, maskedCoinBalanceBytes2, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, mask2, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address2[32:]), tree2.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address2, tree2)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	input2, _ := token.NewPendingTransactionInput(address2[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1, input2},
		[]*token.PendingTransactionOutput{out1},
		[]*big.Int{big.NewInt(12)},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 2); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}

func TestValidPendingTransactionMixed(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(7), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), token.FRAME_2_1_CUTOVER+3)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := token.NewPendingTransactionOutput(big.NewInt(2), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), token.FRAME_2_1_CUTOVER+3)
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	priv, _, _ := km.CreateSigningKey("q-peer-key", crypto.KeyTypeEd448)
	privateKey, _ := pcrypto.UnmarshalEd448PrivateKey(priv.Private())
	publicKey := privateKey.GetPublic()
	peerId, _ := peer.IDFromPublicKey(publicKey)

	addrBI, _ := poseidon.HashBytes([]byte(peerId))
	reversed := addrBI.FillBytes(make([]byte, 32))
	slices.Reverse(reversed)

	repBytes := slices.Concat([]byte{1}, bytes.Repeat([]byte{0}, 54), []byte{0x06}, bytes.Repeat([]byte{0}, 54), []byte{0}, reversed, bytes.Repeat([]byte{0}, 22))
	coinOut := ve.Encrypt(repBytes, []byte(ed448.NewKeyFromSeed(make([]byte, 57)).Public().(ed448.PublicKey)))
	compressed := []thypergraph.Encrypted{}
	for _, co := range coinOut {
		compressed = append(compressed, co.Compress())
	}
	vertTree := thypergraph.EncryptedToVertexTree(ip, compressed)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree2 := &qcrypto.VectorCommitmentTree{}
	otk2, _ := dc.New()
	c2, _ := dc.New()
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(6)}, c2.Private())
	mask2 := c2.Private()
	a2, _ := otk2.AgreeWithAndHashToScalar(pvk.Public())

	blindMask2 := make([]byte, 56)
	coinMask2 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2)

	for i := range blindMask2 {
		mask2[i] ^= blindMask2[i]
	}
	maskedCoinBalanceBytes2 := make([]byte, 56)
	maskedCoinBalanceBytes2[0] = 0x06
	for i := range maskedCoinBalanceBytes2 {
		maskedCoinBalanceBytes2[i] ^= coinMask2[i]
	}

	verifkey2, _ := a2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, verifkey2, nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, maskedCoinBalanceBytes2, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, mask2, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), vertTree.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, vertTree)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address2[32:]), tree2.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address2, tree2)

	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	input2, _ := token.NewPendingTransactionInput(address2[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1, input2},
		[]*token.PendingTransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 3); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.PendingTransaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 3); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}

func TestValidPendingTransactionLegacyOnly(t *testing.T) {
	var comms [][]byte
	for i := 0; i < 3; i++ {
		dc := &bulletproofs.Decaf448KeyConstructor{}
		// Shake out invariant behaviors that should not be invariant by statically-assigning key values:
		vkpriv, _ := hex.DecodeString("baa9944680e2a63b9412a2307e60af09a185fbe8845b33bcda2ad32d685c205744e72658be5bfdfbe7b905bbeeb7a7b07b3a7afd7ea0121f")
		vkpub, _ := hex.DecodeString("628b9b1355182d1d61092c6dd14ad59408238a13a595e81a1181445e22266a8301fd027b681c4bc0ec393aed26f66328045799ce32d64c48")
		skpriv, _ := hex.DecodeString("dd6d3dbe15ab7b71aca7d7245ed296eeea832b49993c07005eccd956ecf3918b1cf94bca7f42abaf260850396bc8a0901467ceb002786d01")
		skpub, _ := hex.DecodeString("4c5dc9a9d57010f7daa0b8d579210e4d58d83529cd8f0679abeb3816f0fffe76f94c3b649b022df94e1757f82d6beeeee20873ee87fda50f")
		rvkpriv, _ := hex.DecodeString("5497ade6a118f309cf8e14524b817724497cdf8ea69abeb604bea9b4ebf36ad69e23c99e450b731358ff71cac7550fe035a29d94bfb6092e")
		rvkpub, _ := hex.DecodeString("f43c361d369113b64c423cf5c352b6dcf977b4ef07d65cca024acb26347263badc591a844ec045a0b685883b733accfc8214fd92fb6e1a30")
		rskpriv, _ := hex.DecodeString("245dd915d919e5c7e142d1c03a3f7942259d2343923f9f9962bf00c0fcbc0259d9d5b9d131bf996213a6e8c90f61d2b1fff008c9c9bf1c2f")
		rskpub, _ := hex.DecodeString("984015acc54156ee93ffe1a2c7cb18997e3de4f0294e538e7fe0dd404a7f45bf0d9391ba1d1fd6183c3dee32b49f1f6f1b25c961dbc55341")
		vk, _ := dc.FromBytes(vkpriv, vkpub)
		sk, _ := dc.FromBytes(skpriv, skpub)
		rvk, _ := dc.FromBytes(rvkpriv, rvkpub)
		rsk, _ := dc.FromBytes(rskpriv, rskpub)

		out1, err := token.NewPendingTransactionOutput(big.NewInt(9), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), token.FRAME_2_1_CUTOVER+3)
		if err != nil {
			t.Fatal(err)
		}
		// out2, err := token.NewPendingTransactionOutput(big.NewInt(2), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), token.FRAME_2_1_CUTOVER+3)
		// if err != nil {
		// 	t.Fatal(err)
		// }

		l, _ := zap.NewProduction()
		ip := bls48581.NewKZGInclusionProver(l)
		s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		ve := verenc.NewMPCitHVerifiableEncryptor(1)
		hg := hypergraph.NewHypergraph(
			l,
			store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
			ip,
			[]int{},
			&tests.Nopthenticator{},
		)
		bp := &bulletproofs.Decaf448BulletproofProver{}
		km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
		priv, _, _ := km.CreateSigningKey("q-peer-key", crypto.KeyTypeEd448)
		privateKey, _ := pcrypto.UnmarshalEd448PrivateKey(priv.Private())
		publicKey := privateKey.GetPublic()
		peerId, _ := peer.IDFromPublicKey(publicKey)

		addrBI, _ := poseidon.HashBytes([]byte(peerId))

		reversed := addrBI.FillBytes(make([]byte, 32))
		slices.Reverse(reversed)

		repBytes := slices.Concat([]byte{1}, bytes.Repeat([]byte{0}, 54), []byte{0x0C}, bytes.Repeat([]byte{0}, 54), []byte{0}, reversed, bytes.Repeat([]byte{0}, 22))
		coinOut := ve.Encrypt(repBytes, []byte(ed448.NewKeyFromSeed(make([]byte, 57)).Public().(ed448.PublicKey)))
		compressed := []thypergraph.Encrypted{}
		for _, co := range coinOut {
			compressed = append(compressed, co.Compress())
		}
		vertTree := thypergraph.EncryptedToVertexTree(ip, compressed)

		address1 := [64]byte{}
		copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
		rand.Read(address1[32:])

		txn, _ := hg.NewTransaction(false)
		hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), vertTree.Commit(ip, false), big.NewInt(55*26)))
		hg.SetVertexData(txn, address1, vertTree)
		txn.Commit()

		// simulate input as commitment to total
		input1, _ := token.NewPendingTransactionInput(address1[:])
		tokenconfig := &token.TokenIntrinsicConfiguration{
			Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
			MintStrategy: &token.TokenMintStrategy{
				MintBehavior: token.MintWithProof,
				ProofBasis:   token.ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(8000000000),
			Name:   "QUIL",
			Symbol: "QUIL",
		}

		tx := token.NewPendingTransaction(
			[32]byte(token.QUIL_TOKEN_ADDRESS),
			[]*token.PendingTransactionInput{input1},
			[]*token.PendingTransactionOutput{out1},
			[]*big.Int{big.NewInt(1), big.NewInt(2)},
			tokenconfig,
			hg,
			bp,
			ip,
			ve,
			dc,
			keys.ToKeyRing(km, false),
			"",
			nil,
		)

		if err := tx.Prove(token.FRAME_2_1_CUTOVER + 3); err != nil {
			t.Fatal(err)
		}

		output, err := tx.ToBytes()
		assert.NoError(t, err)

		newTx := &token.PendingTransaction{}
		err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", nil)
		assert.NoError(t, err)

		comms = append(comms, newTx.Outputs[0].Commitment)

		if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 3); !valid {
			t.Fatal("Expected transaction to verify but it failed", err)
		}
	}

	for i := 1; i < 3; i++ {
		if bytes.Equal(comms[i-1], comms[i]) {
			t.Fatalf("Commitments should not match, got %x", comms[i])
		}
	}
}

func TestValidTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()

	// one accept
	out1, err := token.NewTransactionOutput(big.NewInt(7), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	// one refund
	out2, err := token.NewTransactionOutput(big.NewInt(2), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	othervk, _ := dc.New()
	othersk, _ := dc.New()
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	tree2 := &qcrypto.VectorCommitmentTree{}
	otk1a, _ := dc.New()
	otk1b, _ := dc.New()
	otk2a, _ := dc.New()
	otk2b, _ := dc.New()
	c1, _ := dc.New()
	c2, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(3)}, c1.Private())
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(9)}, c2.Private())
	mask1a := slices.Clone(c1.Private())
	mask1b := slices.Clone(c1.Private())
	mask2a := slices.Clone(c2.Private())
	mask2b := slices.Clone(c2.Private())
	a1, _ := otk1a.AgreeWithAndHashToScalar(pvk.Public())
	b1, _ := otk1b.AgreeWithAndHashToScalar(othervk.Public())
	a2, _ := otk2a.AgreeWithAndHashToScalar(othervk.Public())
	b2, _ := otk2b.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1a := make([]byte, 56)
	coinMask1a := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1a)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1a)

	for i := range blindMask1a {
		mask1a[i] ^= blindMask1a[i]
	}
	maskedCoinBalanceBytes1a := make([]byte, 56)
	maskedCoinBalanceBytes1a[0] = 0x03
	for i := range maskedCoinBalanceBytes1a {
		maskedCoinBalanceBytes1a[i] ^= coinMask1a[i]
	}

	blindMask1b := make([]byte, 56)
	coinMask1b := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(b1.Public())
	shake.Read(blindMask1b)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(b1.Public())
	shake.Read(coinMask1b)

	for i := range blindMask1b {
		mask1b[i] ^= blindMask1b[i]
	}
	maskedCoinBalanceBytes1b := make([]byte, 56)
	maskedCoinBalanceBytes1b[0] = 0x03
	for i := range maskedCoinBalanceBytes1b {
		maskedCoinBalanceBytes1b[i] ^= coinMask1b[i]
	}

	blindMask2a := make([]byte, 56)
	coinMask2a := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2a)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2a)

	for i := range blindMask2a {
		mask2a[i] ^= blindMask2a[i]
	}
	maskedCoinBalanceBytes2a := make([]byte, 56)
	maskedCoinBalanceBytes2a[0] = 0x09
	for i := range maskedCoinBalanceBytes2a {
		maskedCoinBalanceBytes2a[i] ^= coinMask2a[i]
	}

	blindMask2b := make([]byte, 56)
	coinMask2b := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(b2.Public())
	shake.Read(blindMask2b)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(b2.Public())
	shake.Read(coinMask2b)

	for i := range blindMask2b {
		mask2b[i] ^= blindMask2b[i]
	}
	maskedCoinBalanceBytes2b := make([]byte, 56)
	maskedCoinBalanceBytes2b[0] = 0x09
	for i := range maskedCoinBalanceBytes2b {
		maskedCoinBalanceBytes2b[i] ^= coinMask2b[i]
	}

	verifkey1a, _ := a1.Add(psk.Public())
	verifkey1b, _ := b1.Add(othersk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1a.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, otk1b.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, verifkey1a, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, verifkey1b, nil, big.NewInt(56))
	tree1.Insert([]byte{6 << 2}, maskedCoinBalanceBytes1a, nil, big.NewInt(56))
	tree1.Insert([]byte{7 << 2}, maskedCoinBalanceBytes1b, nil, big.NewInt(56))
	tree1.Insert([]byte{8 << 2}, mask1a, nil, big.NewInt(56))
	tree1.Insert([]byte{9 << 2}, mask1b, nil, big.NewInt(56))
	tree1.Insert([]byte{10 << 2}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+3), nil, big.NewInt(8))
	verifkey2a, _ := a2.Add(othersk.Public())
	verifkey2b, _ := b2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2a.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, otk2b.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, verifkey2a, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, verifkey2b, nil, big.NewInt(56))
	tree2.Insert([]byte{6 << 2}, maskedCoinBalanceBytes2a, nil, big.NewInt(56))
	tree2.Insert([]byte{7 << 2}, maskedCoinBalanceBytes2b, nil, big.NewInt(56))
	tree2.Insert([]byte{8 << 2}, mask2a, nil, big.NewInt(56))
	tree2.Insert([]byte{9 << 2}, mask2b, nil, big.NewInt(56))
	tree2.Insert([]byte{10 << 2}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+3), nil, big.NewInt(8))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")

	pendingTypeBI, _ := poseidon.HashBytes(
		slices.Concat(token.QUIL_TOKEN_ADDRESS, []byte("pending:PendingTransaction")),
	)

	typeAddr := pendingTypeBI.FillBytes(make([]byte, 32))
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address2[32:]), tree2.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address2, tree2)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewTransactionInput(address1[:])
	input2, _ := token.NewTransactionInput(address2[:])
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.TransactionInput{input1, input2},
		[]*token.TransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 3); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.Transaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 3); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}

// Other than verifying non-divisible semantics, this should also exclude fees
// from the sumcheck
func TestValidAltTransaction(t *testing.T) {
	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()

	// one accept
	out1, err := token.NewTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	// one refund
	out2, err := token.NewTransactionOutput(big.NewInt(1), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)
	othervk, _ := dc.New()
	othersk, _ := dc.New()
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Acceptable | token.Expirable | token.Tenderable | token.Divisible,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "NOTQUIL",
		Symbol: "NOTQUIL",
	}

	intrinsic, err := token.NewTokenIntrinsic(tokenconfig, hg, ve, dc, bp, ip, km)
	assert.NoError(t, err)

	var st state.State = hgstate.NewHypergraphState(hg)
	st, err = intrinsic.Deploy(token.TOKEN_BASE_DOMAIN, [][]byte{}, []byte{}, big.NewInt(0), nil, 0, st)
	assert.NoError(t, err)
	domain := st.Changeset()[0].Domain
	err = st.Commit()
	assert.NoError(t, err)

	address1 := [64]byte{}
	copy(address1[:32], domain)
	rand.Read(address1[32:])
	address2 := [64]byte{}
	copy(address2[:32], domain)
	rand.Read(address2[32:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	tree2 := &qcrypto.VectorCommitmentTree{}
	otk1a, _ := dc.New()
	otk1b, _ := dc.New()
	otk2a, _ := dc.New()
	otk2b, _ := dc.New()
	c1, _ := dc.New()
	c2, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(1)}, c1.Private())
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(1)}, c2.Private())
	mask1a := slices.Clone(c1.Private())
	mask1b := slices.Clone(c1.Private())
	mask2a := slices.Clone(c2.Private())
	mask2b := slices.Clone(c2.Private())
	a1, _ := otk1a.AgreeWithAndHashToScalar(pvk.Public())
	b1, _ := otk1b.AgreeWithAndHashToScalar(othervk.Public())
	a2, _ := otk2a.AgreeWithAndHashToScalar(othervk.Public())
	b2, _ := otk2b.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1a := make([]byte, 56)
	coinMask1a := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1a)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1a)

	for i := range blindMask1a {
		mask1a[i] ^= blindMask1a[i]
	}
	maskedCoinBalanceBytes1a := make([]byte, 56)
	maskedCoinBalanceBytes1a[0] = 0x01
	for i := range maskedCoinBalanceBytes1a {
		maskedCoinBalanceBytes1a[i] ^= coinMask1a[i]
	}

	blindMask1b := make([]byte, 56)
	coinMask1b := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(b1.Public())
	shake.Read(blindMask1b)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(b1.Public())
	shake.Read(coinMask1b)

	for i := range blindMask1b {
		mask1b[i] ^= blindMask1b[i]
	}
	maskedCoinBalanceBytes1b := make([]byte, 56)
	maskedCoinBalanceBytes1b[0] = 0x01
	for i := range maskedCoinBalanceBytes1b {
		maskedCoinBalanceBytes1b[i] ^= coinMask1b[i]
	}

	blindMask2a := make([]byte, 56)
	coinMask2a := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2a)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2a)

	for i := range blindMask2a {
		mask2a[i] ^= blindMask2a[i]
	}
	maskedCoinBalanceBytes2a := make([]byte, 56)
	maskedCoinBalanceBytes2a[0] = 0x01
	for i := range maskedCoinBalanceBytes2a {
		maskedCoinBalanceBytes2a[i] ^= coinMask2a[i]
	}

	blindMask2b := make([]byte, 56)
	coinMask2b := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(b2.Public())
	shake.Read(blindMask2b)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(b2.Public())
	shake.Read(coinMask2b)

	for i := range blindMask2b {
		mask2b[i] ^= blindMask2b[i]
	}
	maskedCoinBalanceBytes2b := make([]byte, 56)
	maskedCoinBalanceBytes2b[0] = 0x01
	for i := range maskedCoinBalanceBytes2b {
		maskedCoinBalanceBytes2b[i] ^= coinMask2b[i]
	}

	verifkey1a, _ := a1.Add(psk.Public())
	verifkey1b, _ := b1.Add(othersk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1a.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, otk1b.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, verifkey1a, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, verifkey1b, nil, big.NewInt(56))
	tree1.Insert([]byte{6 << 2}, maskedCoinBalanceBytes1a, nil, big.NewInt(56))
	tree1.Insert([]byte{7 << 2}, maskedCoinBalanceBytes1b, nil, big.NewInt(56))
	tree1.Insert([]byte{8 << 2}, mask1a, nil, big.NewInt(56))
	tree1.Insert([]byte{9 << 2}, mask1b, nil, big.NewInt(56))
	tree1.Insert([]byte{10 << 2}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+3), nil, big.NewInt(8))
	verifkey2a, _ := a2.Add(othersk.Public())
	verifkey2b, _ := b2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+1), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2a.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, otk2b.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, verifkey2a, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, verifkey2b, nil, big.NewInt(56))
	tree2.Insert([]byte{6 << 2}, maskedCoinBalanceBytes2a, nil, big.NewInt(56))
	tree2.Insert([]byte{7 << 2}, maskedCoinBalanceBytes2b, nil, big.NewInt(56))
	tree2.Insert([]byte{8 << 2}, mask2a, nil, big.NewInt(56))
	tree2.Insert([]byte{9 << 2}, mask2b, nil, big.NewInt(56))
	tree2.Insert([]byte{10 << 2}, binary.BigEndian.AppendUint64(nil, token.FRAME_2_1_CUTOVER+3), nil, big.NewInt(8))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")

	pendingTypeBI, _ := poseidon.HashBytes(
		slices.Concat(domain, []byte("pending:PendingTransaction")),
	)

	typeAddr := pendingTypeBI.FillBytes(make([]byte, 32))
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	txn, _ := hg.NewTransaction(false)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(domain), [32]byte(address1[32:]), tree1.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address1, tree1)
	hg.AddVertex(txn, hypergraph.NewVertex([32]byte(domain), [32]byte(address2[32:]), tree2.Commit(ip, false), big.NewInt(55*26)))
	hg.SetVertexData(txn, address2, tree2)
	txn.Commit()

	// simulate input as commitment to total
	input1, _ := token.NewTransactionInput(address1[:])
	input2, _ := token.NewTransactionInput(address2[:])

	// Create RDF multiprover for testing
	rdfSchema := intrinsic.GetRDFSchemaDocument()
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	tx := token.NewTransaction(
		[32]byte(domain),
		[]*token.TransactionInput{input1, input2},
		[]*token.TransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(token.FRAME_2_1_CUTOVER + 3); err != nil {
		t.Fatal(err)
	}

	output, err := tx.ToBytes()
	assert.NoError(t, err)

	newTx := &token.Transaction{}
	err = newTx.FromBytes(output, tokenconfig, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	assert.NoError(t, err)

	if valid, err := newTx.Verify(token.FRAME_2_1_CUTOVER + 3); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}

func TestFullTokenFlow_MintPendingTransaction(t *testing.T) {
	// Initialize all necessary components
	dc := &bulletproofs.Decaf448KeyConstructor{}
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)

	// Step 1: Create BLS key and set up prover data with 10000 balance
	prover, _, err := km.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	assert.NoError(t, err)

	proveraddr, err := poseidon.HashBytes(prover.Public().([]byte))
	assert.NoError(t, err)

	proverTree := &qcrypto.VectorCommitmentTree{}
	proverTree.Insert([]byte{0}, proveraddr.FillBytes(make([]byte, 32)), nil, big.NewInt(0))
	proverTree.Insert([]byte{1 << 2}, big.NewInt(10000).FillBytes(make([]byte, 32)), nil, big.NewInt(0))

	// Set up prover with 10000 balance
	txn, _ := hg.NewTransaction(false)
	vert := hypergraph.NewVertex(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[32]byte(proveraddr.FillBytes(make([]byte, 32))),
		proverTree.Commit(ip, false),
		big.NewInt(74),
	)
	err = hg.AddVertex(txn, vert)
	assert.NoError(t, err)
	err = hg.SetVertexData(txn, vert.GetID(), proverTree)
	assert.NoError(t, err)
	hg.Commit()
	err = txn.Commit()
	assert.NoError(t, err)

	hgs := hgstate.NewHypergraphState(hg)

	// Create keys for sender and receiver
	senderViewKey, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	senderSpendKey, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	// Step 2: Create MintTransaction for ProofOfMeaningfulWork
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(8000000000),
		Name:   "QUIL",
		Symbol: "QUIL",
	}

	// Create RDF multiprover for testing
	rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
	assert.NoError(t, err)
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)
	mintInput, err := token.NewMintTransactionInput(big.NewInt(10000), proveraddr.FillBytes(make([]byte, 32)))
	assert.NoError(t, err)

	mintOutput, err := token.NewMintTransactionOutput(
		big.NewInt(10000),
		senderViewKey.Public(),
		senderSpendKey.Public(),
	)
	assert.NoError(t, err)

	mintTx := token.NewMintTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.MintTransactionInput{mintInput},
		[]*token.MintTransactionOutput{mintOutput},
		[]*big.Int{}, // QUIL mints are free
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = mintTx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	out, err := mintTx.ToBytes()
	assert.NoError(t, err)

	intrinsic, err := token.LoadTokenIntrinsic(
		token.QUIL_TOKEN_ADDRESS,
		hg,
		ve,
		dc,
		bp,
		ip,
		km,
	)
	assert.NoError(t, err)

	nhgs, err := intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+2, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)

	mintedAddress := nhgs.Changeset()[1].Address
	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	hgs = hgstate.NewHypergraphState(hg)

	// Step 3: Create PendingTransaction
	pendingInput, err := token.NewPendingTransactionInput(slices.Concat(token.QUIL_TOKEN_ADDRESS, mintedAddress))
	assert.NoError(t, err)

	// Create output
	pendingOutput, err := token.NewPendingTransactionOutput(
		big.NewInt(10000),
		senderViewKey.Public(),
		senderSpendKey.Public(),
		senderViewKey.Public(),
		senderSpendKey.Public(),
		0,
	)
	assert.NoError(t, err)

	pendingTx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{pendingInput},
		[]*token.PendingTransactionOutput{pendingOutput},
		[]*big.Int{big.NewInt(0)}, // no fees for this test
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = pendingTx.Prove(token.FRAME_2_1_CUTOVER + 3)
	assert.NoError(t, err)
	out, err = pendingTx.ToBytes()
	assert.NoError(t, err)

	nhgs, err = intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+3, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)
	pendingAddr := hgs.Changeset()[0].Address

	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	hgs = hgstate.NewHypergraphState(hg)

	// Step 4: Create Transaction to accept the pending transaction
	// Receiver accepts the pending transaction
	txInput, err := token.NewTransactionInput(slices.Concat(token.QUIL_TOKEN_ADDRESS, pendingAddr))
	assert.NoError(t, err)

	// Create outputs
	receiverOutput, err := token.NewTransactionOutput(
		big.NewInt(10000),
		senderViewKey.Public(),
		senderSpendKey.Public(),
	)
	assert.NoError(t, err)

	acceptTx := token.NewTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.TransactionInput{txInput},
		[]*token.TransactionOutput{receiverOutput},
		[]*big.Int{big.NewInt(0)}, // no fees
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = acceptTx.Prove(token.FRAME_2_1_CUTOVER + 4)
	assert.NoError(t, err)

	out, err = acceptTx.ToBytes()
	assert.NoError(t, err)

	nhgs, err = intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+4, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)
	acceptAddr := hgs.Changeset()[0].Address

	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	// hgs = hgstate.NewHypergraphState(hg)

	// Verify final state:
	// 1. Original minted coin should be marked as spent
	txn, _ = hg.NewTransaction(true)
	mintedCoinVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, mintedAddress)))
	assert.NoError(t, err)
	mintImage, err := mintedCoinVertex.Get([]byte{3 << 2})
	assert.NoError(t, err)
	mintSpendBI, err := poseidon.HashBytes(mintImage)
	assert.NoError(t, err)
	mintSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, mintSpendBI.FillBytes(make([]byte, 32)))))
	assert.NoError(t, err)
	mintSpendMarker, err := mintSpendVertex.Get([]byte{0})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01}, mintSpendMarker) // Should be spent

	// 2. Pending transaction should be marked as spent
	pendingVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, pendingAddr)))
	assert.NoError(t, err)
	pendingImage, err := pendingVertex.Get([]byte{4 << 2})
	assert.NoError(t, err)
	pendingSpendBI, err := poseidon.HashBytes(pendingImage)
	assert.NoError(t, err)
	pendingSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, pendingSpendBI.FillBytes(make([]byte, 32)))))
	assert.NoError(t, err)
	pendingSpendMarker, err := pendingSpendVertex.Get([]byte{0})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01}, pendingSpendMarker) // Should be spent

	// 3. Transaction should exist and not be spent
	acceptVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, acceptAddr)))
	assert.NoError(t, err)
	acceptImage, err := acceptVertex.Get([]byte{3 << 2})
	assert.NoError(t, err)
	acceptSpendBI, err := poseidon.HashBytes(acceptImage)
	assert.NoError(t, err)
	acceptSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, acceptSpendBI.FillBytes(make([]byte, 32)))))
	assert.Error(t, err)
	assert.Nil(t, acceptSpendVertex) // Should not be spent

	// Verify prover balance is reduced by 10000
	globalVertex, err := hg.GetVertexData([64]byte(append(token.QUIL_TOKEN_ADDRESS[:], proveraddr.FillBytes(make([]byte, 32))...)))
	assert.NoError(t, err)
	assert.NotNil(t, globalVertex)
	amtBytes, err := globalVertex.Get([]byte{1 << 2})
	assert.NoError(t, err)
	assert.True(t, big.NewInt(0).SetBytes(amtBytes).Cmp(big.NewInt(0)) == 0)
}

func TestFullTokenFlow_MintPendingTransactionNonDivisible(t *testing.T) {
	// Initialize all necessary components
	dc := &bulletproofs.Decaf448KeyConstructor{}
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	bp := &bulletproofs.Decaf448BulletproofProver{}
	km := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, dc)

	// Step 1: Create BLS key and set up prover data with 10000 balance
	prover, _, err := km.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	assert.NoError(t, err)

	proveraddr, err := poseidon.HashBytes(prover.Public().([]byte))
	assert.NoError(t, err)

	proverTree := &qcrypto.VectorCommitmentTree{}
	proverTree.Insert([]byte{0}, prover.Public().([]byte), nil, big.NewInt(0))
	proverTree.Insert([]byte{1 << 2}, big.NewInt(10000).FillBytes(make([]byte, 32)), nil, big.NewInt(0))

	// Set up prover with 10000 balance
	txn, _ := hg.NewTransaction(false)
	vert := hypergraph.NewVertex(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[32]byte(proveraddr.FillBytes(make([]byte, 32))),
		proverTree.Commit(ip, false),
		big.NewInt(74),
	)
	err = hg.AddVertex(txn, vert)
	assert.NoError(t, err)
	err = hg.SetVertexData(txn, vert.GetID(), proverTree)
	assert.NoError(t, err)
	hg.Commit()
	err = txn.Commit()
	assert.NoError(t, err)

	hgs := hgstate.NewHypergraphState(hg)

	// Create keys for sender and receiver
	senderViewKey, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	senderSpendKey, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	// Step 2: Create MintTransaction for MintWithPayment
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Acceptable | token.Expirable | token.Tenderable,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior:   token.MintWithPayment,
			PaymentAddress: make([]byte, 32),
			FeeBasis: &token.FeeBasis{
				Type:     token.PerUnit,
				Baseline: big.NewInt(0),
			},
		},
		Name:   "NOTQUIL",
		Symbol: "NOTQUIL",
	}

	otk1, _ := dc.New()
	c1, _ := dc.New()

	output := slices.Concat(c1.Private(), otk1.Private(), senderViewKey.Public(), senderSpendKey.Public())

	mintInput, err := token.NewMintTransactionInput(big.NewInt(1), output)
	assert.NoError(t, err)

	mintOutput, err := token.NewMintTransactionOutput(
		big.NewInt(1),
		senderViewKey.Public(),
		senderSpendKey.Public(),
	)
	assert.NoError(t, err)

	// Create RDF multiprover for testing - use non-divisible schema since token is not divisible
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	intrinsic, err := token.NewTokenIntrinsic(
		tokenconfig,
		hg,
		ve,
		dc,
		bp,
		ip,
		km,
	)
	assert.NoError(t, err)

	nhgs, err := intrinsic.Deploy(token.TOKEN_BASE_DOMAIN, [][]byte{}, []byte{}, big.NewInt(0), make([]byte, 120), 0, hgs)
	assert.NoError(t, err)
	err = nhgs.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	rdfSchema := intrinsic.GetRDFSchemaDocument()

	tokenAddress := intrinsic.Address()

	mintTx := token.NewMintTransaction(
		[32]byte(tokenAddress),
		[]*token.MintTransactionInput{mintInput},
		[]*token.MintTransactionOutput{mintOutput},
		[]*big.Int{},
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = mintTx.Prove(token.FRAME_2_1_CUTOVER + 2)
	assert.NoError(t, err)
	out, err := mintTx.ToBytes()
	assert.NoError(t, err)

	hgs = hgstate.NewHypergraphState(hg)

	nhgs, err = intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+2, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)

	mintedAddress := nhgs.Changeset()[1].Address
	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	hgs = hgstate.NewHypergraphState(hg)

	// Step 3: Create PendingTransaction
	pendingInput, err := token.NewPendingTransactionInput(slices.Concat(tokenAddress, mintedAddress))
	assert.NoError(t, err)

	// Create output
	pendingOutput, err := token.NewPendingTransactionOutput(
		big.NewInt(1),
		senderViewKey.Public(),
		senderSpendKey.Public(),
		senderViewKey.Public(),
		senderSpendKey.Public(),
		0,
	)
	assert.NoError(t, err)

	pendingTx := token.NewPendingTransaction(
		[32]byte(tokenAddress),
		[]*token.PendingTransactionInput{pendingInput},
		[]*token.PendingTransactionOutput{pendingOutput},
		[]*big.Int{big.NewInt(0)}, // no fees for this test
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = pendingTx.Prove(token.FRAME_2_1_CUTOVER + 3)
	assert.NoError(t, err)
	out, err = pendingTx.ToBytes()
	assert.NoError(t, err)

	nhgs, err = intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+3, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)
	pendingAddr := hgs.Changeset()[0].Address

	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	hgs = hgstate.NewHypergraphState(hg)

	// Step 4: Create Transaction to accept the pending transaction
	// Receiver accepts the pending transaction
	txInput, err := token.NewTransactionInput(slices.Concat(tokenAddress, pendingAddr))
	assert.NoError(t, err)

	// Create outputs
	receiverOutput, err := token.NewTransactionOutput(
		big.NewInt(1),
		senderViewKey.Public(),
		senderSpendKey.Public(),
	)
	assert.NoError(t, err)

	acceptTx := token.NewTransaction(
		[32]byte(tokenAddress),
		[]*token.TransactionInput{txInput},
		[]*token.TransactionOutput{receiverOutput},
		[]*big.Int{big.NewInt(0)}, // no fees
		tokenconfig,
		hg,
		bp,
		ip,
		ve,
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	err = acceptTx.Prove(token.FRAME_2_1_CUTOVER + 4)
	assert.NoError(t, err)

	out, err = acceptTx.ToBytes()
	assert.NoError(t, err)

	nhgs, err = intrinsic.InvokeStep(token.FRAME_2_1_CUTOVER+4, out, big.NewInt(0), big.NewInt(1), hgs)
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)
	acceptAddr := hgs.Changeset()[0].Address

	nhgs, err = intrinsic.Commit()
	assert.NoError(t, err)
	hgs = nhgs.(*hgstate.HypergraphState)

	err = hgs.Commit()
	assert.NoError(t, err)
	// hgs = hgstate.NewHypergraphState(hg)

	// Verify final state:
	// 1. Original minted coin should be marked as spent
	txn, _ = hg.NewTransaction(true)
	mintedCoinVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, mintedAddress)))
	assert.NoError(t, err)
	mintImage, err := mintedCoinVertex.Get([]byte{3 << 2})
	assert.NoError(t, err)
	mintSpendBI, err := poseidon.HashBytes(mintImage)
	assert.NoError(t, err)
	mintSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, mintSpendBI.FillBytes(make([]byte, 32)))))
	assert.NoError(t, err)
	mintSpendMarker, err := mintSpendVertex.Get([]byte{0})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01}, mintSpendMarker) // Should be spent

	// 2. Pending transaction should be marked as spent
	pendingVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, pendingAddr)))
	assert.NoError(t, err)
	pendingImage, err := pendingVertex.Get([]byte{4 << 2})
	assert.NoError(t, err)
	pendingSpendBI, err := poseidon.HashBytes(pendingImage)
	assert.NoError(t, err)
	pendingSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, pendingSpendBI.FillBytes(make([]byte, 32)))))
	assert.NoError(t, err)
	pendingSpendMarker, err := pendingSpendVertex.Get([]byte{0})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01}, pendingSpendMarker) // Should be spent

	// 3. Transaction should exist and not be spent
	acceptVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, acceptAddr)))
	assert.NoError(t, err)
	acceptImage, err := acceptVertex.Get([]byte{3 << 2})
	assert.NoError(t, err)
	acceptSpendBI, err := poseidon.HashBytes(acceptImage)
	assert.NoError(t, err)
	acceptSpendVertex, err := hg.GetVertexData([64]byte(slices.Concat(tokenAddress, acceptSpendBI.FillBytes(make([]byte, 32)))))
	assert.Error(t, err)
	assert.Nil(t, acceptSpendVertex) // Should not be spent
}
