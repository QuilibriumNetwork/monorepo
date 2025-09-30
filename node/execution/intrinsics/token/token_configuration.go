package token

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var QUIL_TOKEN_ADDRESS = []byte{
	// poseidon("q_mainnet_token")
	0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9,
	0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64,
	0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb,
	0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9,
}

var QUIL_TOKEN_CONFIGURATION = &TokenIntrinsicConfiguration{
	Behavior: Mintable | Burnable | Divisible | Acceptable | Expirable | Tenderable,
	MintStrategy: &TokenMintStrategy{
		MintBehavior: MintWithProof,
		ProofBasis:   ProofOfMeaningfulWork,
	},
	Units:  big.NewInt(8000000000),
	Name:   "QUIL",
	Symbol: "QUIL",
}

var TOKEN_PREFIX = []byte("q_token")
var TOKEN_SUPPLY = []byte("q_token_current_supply")
var TOKEN_AVAILABLE_REFERENCES = []byte("q_token_additional_references")

var TOKEN_BASE_DOMAIN [32]byte
var TOKEN_SUPPLY_ADDRESS [32]byte
var TOKEN_ADDITIONAL_REFRENCES_ADDRESS [32]byte
var TOKEN_CONFIGURATION_METADATA_SCHEMA = `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX config: <https://types.quilibrium.com/schema-repository/token/configuration/>

config:TokenConfiguration a rdfs:Class.
config:Behavior a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 2;
  qcl:order 0;
  rdfs:range config:TokenConfiguration.
config:MintStrategy a rdfs:Property;
  rdfs:domain qcl:ByteArray;
	qcl:size 701;
  qcl:order 1;
  rdfs:range config:TokenConfiguration.
config:Units a rdfs:Property;
  rdfs:domain qcl:ByteArray;
	qcl:size 32;
  qcl:order 2;
  rdfs:range config:TokenConfiguration.
config:Supply a rdfs:Property;
  rdfs:domain qcl:ByteArray;
	qcl:size 32;
  qcl:order 3;
  rdfs:range config:TokenConfiguration.
config:Name a rdfs:Property;
  rdfs:domain qcl:String;
	qcl:size 64;
  qcl:order 4;
  rdfs:range config:TokenConfiguration.
config:Symbol a rdfs:Property;
  rdfs:domain qcl:String;
	qcl:size 8;
  qcl:order 5;
  rdfs:range config:TokenConfiguration.
config:AdditionalReference a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 6;
  rdfs:range config:TokenConfiguration.
config:OwnerPublicKey a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 585;
  qcl:order 7;
  rdfs:range config:TokenConfiguration.
`

func init() {
	tokenDomainBI, err := poseidon.HashBytes(TOKEN_PREFIX)
	if err != nil {
		panic(err)
	}

	TOKEN_BASE_DOMAIN = [32]byte(tokenDomainBI.FillBytes(make([]byte, 32)))

	tokenSupplyBI, err := poseidon.HashBytes(TOKEN_SUPPLY)
	if err != nil {
		panic(err)
	}

	// Set supply address out of field modulus for poseidon to prevent collision
	TOKEN_SUPPLY_ADDRESS = [32]byte(tokenSupplyBI.FillBytes(make([]byte, 32)))
	TOKEN_SUPPLY_ADDRESS[0] = 0xff

	tokenAdditionalReferencesBI, err := poseidon.HashBytes(
		TOKEN_AVAILABLE_REFERENCES,
	)
	if err != nil {
		panic(err)
	}

	// Set additional reference address out of field modulus for poseidon to
	// prevent collision
	TOKEN_ADDITIONAL_REFRENCES_ADDRESS = [32]byte(
		tokenAdditionalReferencesBI.FillBytes(make([]byte, 32)),
	)
	TOKEN_ADDITIONAL_REFRENCES_ADDRESS[0] = 0xff
}

type TokenIntrinsicBehavior uint16

const (
	// Has an explicit mint authority - If Mintable is set, MintStrategy MUST be
	// defined, and Supply MAY be set. If not set, Supply MUST be set, and the
	// total supply is minted to the creator.
	Mintable TokenIntrinsicBehavior = 1 << iota
	// Allows the token to be burnt – If Burnable is set, Burn will decrease
	// Supply on Burn events. Additional behaviors apply based on MintStrategy.
	Burnable
	// Can be merged/split - If Divisible is set, Units MUST be defined. If not
	// set, Units MUST NOT be defined.
	Divisible
	// Enables pending transaction flow – If Acceptable is set, transaction flow
	// is Transfer -> PendingTransaction, Accept -> Transaction, Reject ->
	// PendingTransaction, MutualTransfer -> Transaction. If Acceptable is not
	// set, transaction flow is Transfer -> Transaction.
	Acceptable
	// Enables expirations on pending transactions – If Expirable is set,
	// Acceptable MUST be set, uses Deadline field of PendingTransaction to permit
	// RefundAddress to issue an Accept.
	Expirable
	// Permits application shards to set their fee basis in denomination of the
	// token. Important note: configuring an application shard to do this is
	// dangerous – the only consensus maintained by the network natively is its
	// root commitment, the shard will have no impact on QUIL emissions and may
	// go offline if all nodes configured to cover it also go offline. If
	// Tenderable is set, and MintStrategy is configured to use MintWithProof,
	// the nodes covering the application shard will be eligible to earn rewards
	// denominated in the token, following the configured WorkBasis, otherwise
	// there are no emissions-based rewards for covering that application shard,
	// only fees.
	Tenderable
)

type TokenMintBehavior uint16

const (
	// Token is not mintable. No other values for MintStrategy may be provided.
	NoMintBehavior TokenMintBehavior = 0
	// Token is mintable given some ProofBasis – If MintWithProof is set,
	// ProofBasis MUST be defined. If not set, ProofBasis MUST NOT be defined.
	MintWithProof = 1 << 0
	// Token is mintable only by an authority – If MintWithAuthority is set,
	// Authority MUST be defined.
	MintWithAuthority = 1 << 1
	// Token is mintable with a signature from an authority – If MintWithSignature
	// is set, Authority MUST be defined.
	MintWithSignature = 1 << 2
	// Token is mintable in exchange for a payment – If MintWithPayment is set,
	// PaymentAddress MUST be defined and FeeBasis MUST be defined.
	MintWithPayment = 1 << 3
)

type ProofBasisType uint16

const (
	NoProofBasis ProofBasisType = iota
	ProofOfMeaningfulWork
	VerkleMultiproofWithSignature
)

type FeeBasisType uint16

const (
	NoFeeBasis FeeBasisType = iota
	PerUnit
)

type Authority struct {
	KeyType   crypto.KeyType
	PublicKey []byte
	CanBurn   bool
}

type FeeBasis struct {
	Type     FeeBasisType
	Baseline *big.Int
}

type TokenMintStrategy struct {
	// Defines the mint behavior. For serialization purposes, an undefined
	// MintStrategy will serialize MintBehavior as NoMintBehavior. For any
	// other configurations of these values, MintBehavior MUST be defined as
	// something other than NoMintBehavior.
	MintBehavior TokenMintBehavior
	// If MintWithProof is set, ProofBasis MUST be set to a value other than
	// NoProofBasis.
	ProofBasis ProofBasisType
	// If ProofBasis is VerkleMultiproofWithSignature, this is the root commitment
	// value. Otherwise, MUST be empty.
	VerkleRoot []byte
	// If MintWithAuthority or MintWithSignature is set, Authority MUST also be
	// set.
	Authority *Authority
	// If MintWithPayment is set, PaymentAddress MUST be set.
	PaymentAddress []byte
	// If MintWithPayment is set, FeeBasis MUST be set, but MAY be zero.
	FeeBasis *FeeBasis
}

type TokenIntrinsicConfiguration struct {
	// Defines the behavior of the given token intrinsic in terms of operations
	// that can be performed on instances of it.
	Behavior TokenIntrinsicBehavior
	// If Mintable is set, this MUST be defined
	MintStrategy *TokenMintStrategy
	// Divisible units of a token. If Divisible is NOT set, this MUST be undefined
	// and will be interpreted as 1. Units MAY NOT be less than 1. Will be
	// interpreted as the number of discrete units that makes a single whole
	// instance of a token. Example: Most national currencies are divisible by
	// 100, and so Units would be 100.
	Units *big.Int
	// Sets a total supply. If Mintable is NOT set, this MUST be defined. If not
	// set, this will be interpreted as 2^255. This supply is in terms of Units,
	// not an undivided whole. Example: A token with a divisibility of 100 units
	// and a maximum supply of 100,000,000.00 tokens would be encoded as
	// 10000000000.
	Supply *big.Int
	// The printable name of the token.
	Name string
	// The short-form name of the token.
	Symbol string
	// The address corresponding to additional informational records
	AdditionalReference [64]byte
	// The owner's public key (585 bytes for BLS48-581)
	OwnerPublicKey []byte
}

// TokenDeploy creates a new token instance
type TokenDeploy struct {
	// The token configuration
	Config *TokenIntrinsicConfiguration
	// The raw RDF schema definition
	RDFSchema []byte
}

// TokenUpdate updates an existing token instance
type TokenUpdate struct {
	// The token configuration
	Config *TokenIntrinsicConfiguration
	// The raw RDF schema definition
	RDFSchema []byte
	// Signature from the owner key
	OwnerSignature *protobufs.BLS48581AggregateSignature
}

func newTokenConsensusMetadata(
	provers [][]byte,
) (*qcrypto.VectorCommitmentTree, error) {
	if len(provers) != 0 {
		return nil, errors.Wrap(
			errors.New(
				"token intrinsic may not accept a prover list for initialization",
			),
			"new token consensus metadata",
		)
	}

	return &qcrypto.VectorCommitmentTree{}, nil
}

func newTokenSumcheckInfo() (*qcrypto.VectorCommitmentTree, error) {
	return &qcrypto.VectorCommitmentTree{}, nil
}

func GenerateRDFPrelude(
	appAddress []byte,
	config *TokenIntrinsicConfiguration,
) string {
	appAddressHex := hex.EncodeToString(appAddress)

	prelude := "BASE <https://types.quilibrium.com/schema-repository/>\n" +
		"PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
		"PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n" +
		"PREFIX qcl: <https://types.quilibrium.com/qcl/>\n" +
		"PREFIX coin: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/coin/>\n"

	if config.Behavior&Acceptable != 0 {
		prelude += "PREFIX pending: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/pending/>\n"
	}

	prelude += "\n"

	return prelude
}

func PrepareRDFSchemaFromConfig(
	appAddress []byte,
	config *TokenIntrinsicConfiguration,
) (string, error) {
	schema := GenerateRDFPrelude(appAddress, config)

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

	if config.Behavior&Divisible == 0 {
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

	if config.Behavior&Acceptable != 0 {
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

		if config.Behavior&Divisible == 0 {
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

		if config.Behavior&Expirable != 0 {
			schema += "pending:Expiration a rdfs:Property;\n" +
				"  rdfs:domain qcl:Uint;\n" +
				"  qcl:size 8;\n"

			if config.Behavior&Divisible == 0 {
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

func newTokenRDFHypergraphSchema(
	appAddress []byte,
	config *TokenIntrinsicConfiguration,
) (string, error) {
	schemaDoc, err := PrepareRDFSchemaFromConfig(appAddress, config)
	if err != nil {
		return "", errors.Wrap(err, "new token rdf hypergraph schema")
	}

	valid, err := (&schema.TurtleRDFParser{}).Validate(schemaDoc)
	if err != nil {
		return "", errors.Wrap(err, "new token rdf hypergraph schema")
	}

	if !valid {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new token rdf hypergraph schema",
		)
	}

	return schemaDoc, nil
}

func validateTokenConfiguration(config *TokenIntrinsicConfiguration) error {
	// Verify config is valid based on behavior
	if (config.Behavior&Mintable) == 0 && (config.Supply == nil ||
		config.Supply.Cmp(big.NewInt(0)) <= 0 ||
		config.Supply.Cmp(
			big.NewInt(1).Lsh(big.NewInt(1), 256),
		) >= 0) {
		return errors.Wrap(
			errors.New("non-mintable token must have supply defined"),
			"validate token configuration",
		)
	}

	if (config.Behavior&Mintable) != 0 && config.MintStrategy == nil {
		return errors.Wrap(
			errors.New("mintable token must have mint strategy defined"),
			"validate token configuration",
		)
	}

	if (config.Behavior&Divisible) != 0 && (config.Units == nil ||
		config.Units.Cmp(big.NewInt(0)) <= 0 ||
		config.Units.Cmp(
			big.NewInt(1).Lsh(big.NewInt(1), 256),
		) >= 0) {
		return errors.Wrap(
			errors.New("divisible token must have units defined"),
			"validate token configuration",
		)
	}

	if (config.Behavior&Divisible) == 0 && config.Units != nil {
		return errors.Wrap(
			errors.New("non-divisible token must not have units defined"),
			"validate token configuration",
		)
	}

	if (config.Behavior&Expirable) != 0 && (config.Behavior&Acceptable) == 0 {
		return errors.Wrap(
			errors.New("expirable token must be acceptable"),
			"validate token configuration",
		)
	}

	// Validate MintStrategy if present
	if config.MintStrategy != nil {
		switch config.MintStrategy.MintBehavior {
		case NoMintBehavior:
			// Nothing else should be defined
			if config.MintStrategy.ProofBasis != NoProofBasis {
				return errors.Wrap(
					errors.New("no mint behavior must not define proof basis"),
					"validate token configuration",
				)
			}
			if config.MintStrategy.Authority != nil {
				return errors.Wrap(
					errors.New("no mint behavior must not define authority"),
					"validate token configuration",
				)
			}
			if len(config.MintStrategy.PaymentAddress) != 32 {
				return errors.Wrap(
					errors.New("no mint behavior must not define payment address"),
					"validate token configuration",
				)
			}
			if config.MintStrategy.FeeBasis != nil {
				return errors.Wrap(
					errors.New("no mint behavior must not define fee basis"),
					"validate token configuration",
				)
			}

		case MintWithProof:
			if config.MintStrategy.ProofBasis == NoProofBasis {
				return errors.Wrap(
					errors.New("mint with proof must define proof basis"),
					"validate token configuration",
				)
			}

			if config.MintStrategy.ProofBasis == VerkleMultiproofWithSignature &&
				len(config.MintStrategy.VerkleRoot) != 74 {
				return errors.Wrap(
					errors.New("verkle root must be defined"),
					"validate token configuration",
				)
			}

		case MintWithAuthority, MintWithSignature:
			if config.MintStrategy.Authority == nil {
				return errors.Wrap(
					errors.New(
						"mint with authority/signature must define authority",
					),
					"validate token configuration",
				)
			}

		case MintWithPayment:
			if len(config.MintStrategy.PaymentAddress) != 32 {
				return errors.Wrap(
					errors.New("mint with payment must define payment address"),
					"validate token configuration",
				)
			}
			if config.MintStrategy.FeeBasis == nil ||
				config.MintStrategy.FeeBasis.Baseline.Cmp(big.NewInt(0)) < 0 ||
				config.MintStrategy.FeeBasis.Baseline.Cmp(
					big.NewInt(1).Lsh(big.NewInt(1), 256),
				) >= 0 {
				return errors.Wrap(
					errors.New("mint with payment must define fee basis"),
					"validate token configuration",
				)
			}
		}
	}

	return nil
}

func NewTokenConfigurationMetadata(
	config *TokenIntrinsicConfiguration,
	rdfMultiprover *schema.RDFMultiprover,
) (*qcrypto.VectorCommitmentTree, error) {
	if err := validateTokenConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "token config")
	}

	tree := &qcrypto.VectorCommitmentTree{}

	// Store Behavior (order 0)
	behaviorBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(behaviorBytes, uint16(config.Behavior))
	if err := rdfMultiprover.Set(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		TOKEN_BASE_DOMAIN[:],
		"config:TokenConfiguration",
		"Behavior",
		behaviorBytes,
		tree,
	); err != nil {
		return nil, errors.Wrap(err, "token config")
	}

	// Store MintStrategy (order 1)
	if config.MintStrategy != nil {
		mintStrategyBytes := bytes.Buffer{}

		// Write MintBehavior
		if err := binary.Write(
			&mintStrategyBytes,
			binary.BigEndian,
			uint16(config.MintStrategy.MintBehavior),
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}

		// Write ProofBasis
		if err := binary.Write(
			&mintStrategyBytes,
			binary.BigEndian,
			uint16(config.MintStrategy.ProofBasis),
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}

		// Write VerkleRoot if present
		if config.MintStrategy.VerkleRoot != nil {
			// Write 1 to indicate VerkleRoot is present
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(1),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write VerkleRoot length and bytes
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(len(config.MintStrategy.VerkleRoot)),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
			if _, err := mintStrategyBytes.Write(
				config.MintStrategy.VerkleRoot,
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		} else {
			// Write 0 to indicate no VerkleRoot
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(0),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		}

		// Write Authority if present
		if config.MintStrategy.Authority != nil {
			// Write 1 to indicate Authority is present
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(1),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write KeyType
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(config.MintStrategy.Authority.KeyType),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write PublicKey length and bytes
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(len(config.MintStrategy.Authority.PublicKey)),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
			if _, err := mintStrategyBytes.Write(
				config.MintStrategy.Authority.PublicKey,
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write CanBurn
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				config.MintStrategy.Authority.CanBurn,
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		} else {
			// Write 0 to indicate no Authority
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(0),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		}

		// Write PaymentAddress if present
		if len(config.MintStrategy.PaymentAddress) > 0 {
			// Write length and bytes
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(len(config.MintStrategy.PaymentAddress)),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
			if _, err := mintStrategyBytes.Write(
				config.MintStrategy.PaymentAddress,
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		} else {
			// Write 0 to indicate no PaymentAddress
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(0),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		}

		// Write FeeBasis if present
		if config.MintStrategy.FeeBasis != nil {
			// Write 1 to indicate FeeBasis is present
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(1),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write Type
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(config.MintStrategy.FeeBasis.Type),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}

			// Write Baseline as bytes
			baselineBytes := config.MintStrategy.FeeBasis.Baseline.Bytes()
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint16(len(baselineBytes)),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
			if _, err := mintStrategyBytes.Write(baselineBytes); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		} else {
			// Write 0 to indicate no FeeBasis
			if err := binary.Write(
				&mintStrategyBytes,
				binary.BigEndian,
				uint8(0),
			); err != nil {
				return nil, errors.Wrap(err, "token config")
			}
		}

		// Pad to maximum size if necessary
		mintStrategyData := mintStrategyBytes.Bytes()
		if len(mintStrategyData) > 701 {
			return nil, errors.Wrap(
				errors.New("mint strategy data exceeds maximum size"),
				"token config",
			)
		}

		if err := rdfMultiprover.Set(
			TOKEN_CONFIGURATION_METADATA_SCHEMA,
			TOKEN_BASE_DOMAIN[:],
			"config:TokenConfiguration",
			"MintStrategy",
			mintStrategyData,
			tree,
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}
	}

	// Store Units (order 2)
	if config.Units != nil {
		unitsBytes := config.Units.FillBytes(make([]byte, 32))
		if err := rdfMultiprover.Set(
			TOKEN_CONFIGURATION_METADATA_SCHEMA,
			TOKEN_BASE_DOMAIN[:],
			"config:TokenConfiguration",
			"Units",
			unitsBytes,
			tree,
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}
	}

	// Store Supply (order 3)
	if config.Supply != nil {
		supplyBytes := config.Supply.FillBytes(make([]byte, 32))
		if err := rdfMultiprover.Set(
			TOKEN_CONFIGURATION_METADATA_SCHEMA,
			TOKEN_BASE_DOMAIN[:],
			"config:TokenConfiguration",
			"Supply",
			supplyBytes,
			tree,
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}
	}

	// Store Name (order 4)
	nameBytes := []byte(config.Name)
	// Truncate to 64 bytes if necessary
	if len(nameBytes) > 64 {
		nameBytes = nameBytes[:64]
	}
	if err := rdfMultiprover.Set(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		TOKEN_BASE_DOMAIN[:],
		"config:TokenConfiguration",
		"Name",
		nameBytes,
		tree,
	); err != nil {
		return nil, errors.Wrap(err, "token config")
	}

	// Store Symbol (order 5)
	symbolBytes := []byte(config.Symbol)
	// Truncate to 8 bytes if necessary
	if len(symbolBytes) > 8 {
		symbolBytes = symbolBytes[:8]
	}
	if err := rdfMultiprover.Set(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		TOKEN_BASE_DOMAIN[:],
		"config:TokenConfiguration",
		"Symbol",
		symbolBytes,
		tree,
	); err != nil {
		return nil, errors.Wrap(err, "token config")
	}

	// Store AdditionalReference (order 6)
	if err := rdfMultiprover.Set(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		TOKEN_BASE_DOMAIN[:],
		"config:TokenConfiguration",
		"AdditionalReference",
		config.AdditionalReference[:],
		tree,
	); err != nil {
		return nil, errors.Wrap(err, "token config")
	}

	// Store OwnerPublicKey (order 7)
	if len(config.OwnerPublicKey) > 0 {
		if err := rdfMultiprover.Set(
			TOKEN_CONFIGURATION_METADATA_SCHEMA,
			TOKEN_BASE_DOMAIN[:],
			"config:TokenConfiguration",
			"OwnerPublicKey",
			config.OwnerPublicKey,
			tree,
		); err != nil {
			return nil, errors.Wrap(err, "token config")
		}
	}

	return tree, nil
}

func unpackAndVerifyTokenConfigurationMetadata(
	inclusionProver crypto.InclusionProver,
	tree *qcrypto.VectorCommitmentTree,
) (*TokenIntrinsicConfiguration, error) {
	commitment := tree.Commit(inclusionProver, false)
	if len(commitment) == 0 {
		return nil, errors.Wrap(errors.New("invalid tree"), "unpack and verify")
	}

	// Get the configuration metadata from index 16
	tokenConfigurationMetadataBytes, err := tree.Get([]byte{16 << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	tokenConfigurationMetadata, err := qcrypto.DeserializeNonLazyTree(
		tokenConfigurationMetadataBytes,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	// Create an RDF multiprover for reading values using the schema
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, inclusionProver)

	config := &TokenIntrinsicConfiguration{}

	// Read Behavior (order 0)
	behaviorBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"Behavior",
		tokenConfigurationMetadata,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	if len(behaviorBytes) < 2 {
		return nil, errors.Wrap(
			errors.New("invalid behavior bytes length"),
			"unpack and verify",
		)
	}
	config.Behavior = TokenIntrinsicBehavior(
		binary.BigEndian.Uint16(behaviorBytes),
	)

	// Read MintStrategy (order 1)
	mintStrategyBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"MintStrategy",
		tokenConfigurationMetadata,
	)
	if err == nil && len(mintStrategyBytes) > 0 {
		mintStrategy := &TokenMintStrategy{}
		buf := bytes.NewReader(mintStrategyBytes)

		// Read MintBehavior
		var mintBehavior uint16
		if err := binary.Read(buf, binary.BigEndian, &mintBehavior); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}
		mintStrategy.MintBehavior = TokenMintBehavior(mintBehavior)

		// Read ProofBasis
		var proofBasis uint16
		if err := binary.Read(buf, binary.BigEndian, &proofBasis); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}
		mintStrategy.ProofBasis = ProofBasisType(proofBasis)

		// Read VerkleRoot if present
		var hasVerkleRoot uint8
		if err := binary.Read(buf, binary.BigEndian, &hasVerkleRoot); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}

		if hasVerkleRoot == 1 {
			// Read VerkleRoot
			var verkleLen uint16
			if err := binary.Read(buf, binary.BigEndian, &verkleLen); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}

			verkleRoot := make([]byte, verkleLen)
			if _, err := buf.Read(verkleRoot); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			mintStrategy.VerkleRoot = verkleRoot
		}

		// Read Authority if present
		var hasAuthority uint8
		if err := binary.Read(buf, binary.BigEndian, &hasAuthority); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}

		if hasAuthority == 1 {
			authority := &Authority{}

			// Read KeyType
			var keyType uint16
			if err := binary.Read(buf, binary.BigEndian, &keyType); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			authority.KeyType = crypto.KeyType(keyType)

			// Read PublicKey
			var pubKeyLen uint16
			if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}

			pubKey := make([]byte, pubKeyLen)
			if _, err := buf.Read(pubKey); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			authority.PublicKey = pubKey

			// Read CanBurn
			var canBurn bool
			if err := binary.Read(buf, binary.BigEndian, &canBurn); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			authority.CanBurn = canBurn

			mintStrategy.Authority = authority
		}

		// Read PaymentAddress if present
		var paymentAddrLen uint16
		if err := binary.Read(buf, binary.BigEndian, &paymentAddrLen); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}

		if paymentAddrLen > 0 {
			paymentAddr := make([]byte, paymentAddrLen)
			if _, err := buf.Read(paymentAddr); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			mintStrategy.PaymentAddress = paymentAddr
		}

		// Read FeeBasis if present
		var hasFeeBasis uint8
		if err := binary.Read(buf, binary.BigEndian, &hasFeeBasis); err != nil {
			return nil, errors.Wrap(err, "unpack and verify")
		}

		if hasFeeBasis == 1 {
			feeBasis := &FeeBasis{}

			// Read Type
			var feeType uint16
			if err := binary.Read(buf, binary.BigEndian, &feeType); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}
			feeBasis.Type = FeeBasisType(feeType)

			// Read Baseline
			var baselineLen uint16
			if err := binary.Read(buf, binary.BigEndian, &baselineLen); err != nil {
				return nil, errors.Wrap(err, "unpack and verify")
			}

			if baselineLen > 32 {
				return nil, errors.Wrap(
					errors.New("invalid baseline length"),
					"unpack and verify",
				)
			}

			if baselineLen != 0 {
				baselineBytes := make([]byte, baselineLen)
				if _, err := buf.Read(baselineBytes); err != nil {
					return nil, errors.Wrap(err, "unpack and verify")
				}
				feeBasis.Baseline = new(big.Int).SetBytes(baselineBytes)
			} else {
				feeBasis.Baseline = big.NewInt(0)
			}

			mintStrategy.FeeBasis = feeBasis
		}

		config.MintStrategy = mintStrategy
	}

	// Read Units (order 2)
	unitsBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"Units",
		tokenConfigurationMetadata,
	)
	if err == nil && len(unitsBytes) > 0 {
		config.Units = new(big.Int).SetBytes(unitsBytes)
	}

	// Read Supply (order 3)
	supplyBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"Supply",
		tokenConfigurationMetadata,
	)
	if err == nil && len(supplyBytes) > 0 {
		config.Supply = new(big.Int).SetBytes(supplyBytes)
	}

	// Read Name (order 4)
	nameBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"Name",
		tokenConfigurationMetadata,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.Name = string(nameBytes)

	// Read Symbol (order 5)
	symbolBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"Symbol",
		tokenConfigurationMetadata,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	config.Symbol = string(symbolBytes)

	// Read AdditionalReference (order 6)
	additionalRefBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"AdditionalReference",
		tokenConfigurationMetadata,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}
	if len(additionalRefBytes) != 64 {
		return nil, errors.Wrap(
			errors.New("invalid additional reference length"),
			"unpack and verify",
		)
	}
	copy(config.AdditionalReference[:], additionalRefBytes)

	// Read OwnerPublicKey (order 7)
	ownerPublicKeyBytes, err := rdfMultiprover.Get(
		TOKEN_CONFIGURATION_METADATA_SCHEMA,
		"config:TokenConfiguration",
		"OwnerPublicKey",
		tokenConfigurationMetadata,
	)
	if err == nil && len(ownerPublicKeyBytes) > 0 {
		config.OwnerPublicKey = ownerPublicKeyBytes
	}

	if err := validateTokenConfiguration(config); err != nil {
		return nil, errors.Wrap(err, "unpack and verify")
	}

	return config, nil
}

func unpackAndVerifyConsensusMetadata(tree *qcrypto.VectorCommitmentTree) (
	*qcrypto.VectorCommitmentTree,
	error,
) {
	return hg.UnpackConsensusMetadata(tree)
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

func unpackAndVerifySumcheckInfo(tree *qcrypto.VectorCommitmentTree) (
	*qcrypto.VectorCommitmentTree,
	error,
) {
	return hg.UnpackSumcheckInfo(tree)
}
