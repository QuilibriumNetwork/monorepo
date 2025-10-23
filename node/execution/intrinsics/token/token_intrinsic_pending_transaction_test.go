package token

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// getTestRDFSchema returns a test RDF schema for coin:Coin
func getTestRDFSchema() string {
	return `
		@prefix coin: <https://types.quilibrium.com/schema-repository/token/test/coin/> .
		@prefix qcl: <https://types.quilibrium.com/qcl/> .
		@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

		coin:Coin a rdfs:Class.
		coin:Commitment a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 1;
			rdfs:range coin:Coin.
		coin:OneTimeKey a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 2;
			rdfs:range coin:Coin.
		coin:VerificationKey a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 3;
			rdfs:range coin:Coin.
		coin:CoinBalance a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 4;
			rdfs:range coin:Coin.
		coin:Blind a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 5;
			rdfs:range coin:Coin.
		coin:AdditionalReference a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 64;
			qcl:order 6;
			rdfs:range coin:Coin.
		coin:AdditionalReferenceKey a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 7;
			rdfs:range coin:Coin.
	`
}

func TestValidPendingTransactionWithMocks(t *testing.T) {
	dc := &mocks.MockDecafConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()

	out1, err := NewTransactionOutput(big.NewInt(7), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	out2, err := NewTransactionOutput(big.NewInt(3), vk.Public(), sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	total := new(big.Int).Add(out1.value, out2.value)
	total.Add(total, big.NewInt(2))

	hg := &mocks.MockHypergraph{}
	bp := &mocks.MockBulletproofProver{}
	ip := &mocks.MockInclusionProver{}
	ve := &mocks.MockVerifiableEncryptor{}
	km := &mocks.MockKeyRing{}
	bp.On("GenerateRangeProofFromBig", mock.Anything, mock.Anything, mock.Anything).Return(
		crypto.RangeProofResult{
			Proof:      []byte("valid-proof"),
			Commitment: []byte("valid-commitment" + string(bytes.Repeat([]byte{0x00}, 56*2-16))),
			Blinding:   []byte("valid-blinding" + string(bytes.Repeat([]byte{0x00}, 56*2-14))),
		},
		nil,
	)
	bp.On("VerifyRangeProof", mock.Anything, mock.Anything, mock.Anything).Return(true)
	bp.On("SumCheck", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	km.On("GetRawKey", "q-verenc-key").Return(&keys.Key{
		Id:         "q-verenc-key",
		Type:       crypto.KeyTypeEd448,
		PrivateKey: []byte("valid-user-specific-verifiable-encryption-key"),
		PublicKey:  []byte("valid-user-specific-verifiable-encryption-pubkey"),
	}, nil)
	inputViewKey, _ := dc.New()
	inputSpendKey, _ := dc.New()
	km.On("GetAgreementKey", "q-view-key", mock.Anything, mock.Anything).Return(inputViewKey, nil)
	km.On("GetAgreementKey", "q-spend-key", mock.Anything, mock.Anything).Return(inputSpendKey, nil)

	address := [64]byte{}
	copy(address[:32], QUIL_TOKEN_ADDRESS)
	rand.Read(address[32:])

	// Used only for non-deletion check
	hg.On("GetVertex", address).Return(nil, nil)
	hg.On("GetVertex", mock.MatchedBy(func(addr [64]byte) bool { return !bytes.Equal(addr[:], address[:]) })).Return(nil, errors.New("not found"))

	bp.On("SignHidden", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(bytes.Repeat([]byte("valid-commitment"+string(bytes.Repeat([]byte{0x00}, 56-16))), 6))
	ip.On("ProveRaw", mock.Anything, mock.Anything, mock.Anything).Return([]byte("valid-proof"+string(bytes.Repeat([]byte{0x00}, 74-11))), nil)
	ip.On("CommitRaw", mock.Anything, mock.Anything).Return([]byte("valid-commit"+string(bytes.Repeat([]byte{0x00}, 74-12))), nil)
	mp := &mocks.MockMultiproof{}
	ip.On("NewMultiproof").Return(mp)
	mp.On("ToBytes").Return([]byte("multiproof"), nil)
	mp.On("GetMulticommitment").Return([]byte("multicommitment"))
	mp.On("GetProof").Return([]byte("proof"))
	mp.On("FromBytes", mock.Anything).Return(nil)
	ip.On("ProveMultiple", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mp, nil)
	ip.On("VerifyMultiple", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	bp.On("GenerateInputCommitmentsFromBig", mock.Anything, mock.Anything).Return([]byte("input-commit" + string(bytes.Repeat([]byte{0x00}, 56-12))))
	hg.On("GetShardCommits", mock.Anything, mock.Anything).Return([][]byte{make([]byte, 64), make([]byte, 64), make([]byte, 64), make([]byte, 64)}, nil)
	hg.On("CreateTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&qcrypto.TraversalProof{
		Multiproof: &mocks.MockMultiproof{},
		SubProofs: []qcrypto.TraversalSubProof{{
			Commits: [][]byte{[]byte("valid-hg-commit" + string(bytes.Repeat([]byte{0x00}, 74-15)))},
			Ys:      [][]byte{{0x00}},
			Paths:   [][]uint64{{0}},
		}},
	}, nil)
	hg.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	hg.On("GetProver").Return(ip)
	ip.On("VerifyRaw", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	bp.On("VerifyHidden", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	tree := &qcrypto.VectorCommitmentTree{}
	tree.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END+1), nil, big.NewInt(55))
	tree.Insert([]byte{1 << 2}, []byte("valid-commitment"+string(bytes.Repeat([]byte{0x00}, 56-16))), nil, big.NewInt(56))
	tree.Insert([]byte{2 << 2}, []byte("one-time-key"+string(bytes.Repeat([]byte{0x00}, 56-12))), nil, big.NewInt(56))
	tree.Insert([]byte{3 << 2}, []byte("verification-key"+string(bytes.Repeat([]byte{0x00}, 56-16))), nil, big.NewInt(56))
	tree.Insert([]byte{4 << 2}, []byte("coin-balance-enc"+string(bytes.Repeat([]byte{0x00}, 56-16))), nil, big.NewInt(56))
	tree.Insert([]byte{5 << 2}, []byte("mask-enc1"+string(bytes.Repeat([]byte{0x00}, 56-9))), nil, big.NewInt(56))
	tree.Insert([]byte{6 << 2}, []byte("mask-enc2"+string(bytes.Repeat([]byte{0x00}, 56-9))), nil, big.NewInt(56))

	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	hg.On("GetVertexData", address).Return(tree, nil)

	// Create RDF multiprover for testing
	rdfSchema := getTestRDFSchema()
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	// simulate input as commitment to total
	input, _ := NewTransactionInput(address[:])
	tx := NewTransaction(
		[32]byte(QUIL_TOKEN_ADDRESS),
		[]*TransactionInput{input},
		[]*TransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(1)},
		&TokenIntrinsicConfiguration{
			Behavior: Mintable | Burnable | Divisible | Tenderable,
			MintStrategy: &TokenMintStrategy{
				MintBehavior: MintWithProof,
				ProofBasis:   ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(8000000000),
			Name:   "QUIL",
			Symbol: "QUIL",
		},
		hg,
		bp,
		ip,
		ve,
		dc,
		km,
		rdfSchema,
		rdfMultiprover,
	)

	if err := tx.Prove(FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END + 1); err != nil {
		t.Fatal(err)
	}

	if valid, err := tx.Verify(FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END + 2); !valid {
		t.Fatal("Expected transaction to verify but it failed", err)
	}
}
