package deploy

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	tokenconfig "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var updateDomainAddress string

// signUpdate builds a BLS signature over the canonical bytes of a proto
// message with its signature field cleared. The domain used for signing is
// domainBytes || domainSuffix (e.g. domainBytes || "TOKEN_UPDATE").
func signUpdate(
	msg interface {
		ToCanonicalBytes() ([]byte, error)
	},
	domainBytes []byte,
	domainSuffix string,
) (*protobufs.BLS48581AggregateSignature, error) {
	cfg := getConfig()
	if cfg == nil {
		return nil, fmt.Errorf("no config available")
	}

	initKeyManager()
	if keyManager == nil {
		return nil, fmt.Errorf("key manager not available")
	}

	message, err := msg.ToCanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("canonical bytes: %w", err)
	}

	signer, err := keyManager.GetSigningKey(cfg.Engine.ProvingKeyId)
	if err != nil {
		return nil, fmt.Errorf("get proving key: %w", err)
	}

	sig, err := signer.SignWithDomain(
		message,
		slices.Concat(domainBytes, []byte(domainSuffix)),
	)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return &protobufs.BLS48581AggregateSignature{
		Signature: sig,
	}, nil
}

var UpdateTokenCmd = &cobra.Command{
	Use:   "update [ConfigurationKey=ConfigurationValue...]",
	Short: "Update a deployed token configuration",
	Long: `Update a deployed token configuration. Requires --domain flag.

Configuration keys:
  name=MyToken          Token name
  symbol=MTK            Token symbol
  behavior=mintable,divisible  Comma-separated behavior flags
  mintStrategy=proof    Mint strategy (proof, authority, signature, payment)
  units=1000000         Smallest unit denomination (big integer)
  supply=100000000      Total supply (big integer)`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateDomainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(updateDomainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		configMap := make(map[string]string)
		for _, arg := range args {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				configMap[strings.ToLower(parts[0])] = parts[1]
			}
		}

		tokenCfg := &protobufs.TokenConfiguration{}

		if v, ok := configMap["name"]; ok {
			tokenCfg.Name = v
		}
		if v, ok := configMap["symbol"]; ok {
			tokenCfg.Symbol = v
		}

		if v, ok := configMap["behavior"]; ok {
			var behavior uint32
			for _, flag := range strings.Split(v, ",") {
				switch strings.TrimSpace(strings.ToLower(flag)) {
				case "mintable":
					behavior |= uint32(tokenconfig.Mintable)
				case "burnable":
					behavior |= uint32(tokenconfig.Burnable)
				case "divisible":
					behavior |= uint32(tokenconfig.Divisible)
				case "acceptable":
					behavior |= uint32(tokenconfig.Acceptable)
				case "expirable":
					behavior |= uint32(tokenconfig.Expirable)
				case "tenderable":
					behavior |= uint32(tokenconfig.Tenderable)
				default:
					return fmt.Errorf("unknown behavior flag: %s", flag)
				}
			}
			tokenCfg.Behavior = behavior
		}

		if v, ok := configMap["mintstrategy"]; ok {
			mintStrategy := &protobufs.TokenMintStrategy{}
			switch strings.ToLower(v) {
			case "proof":
				mintStrategy.MintBehavior = protobufs.TokenMintBehavior_MINT_WITH_PROOF
				mintStrategy.ProofBasis = protobufs.ProofBasisType_PROOF_OF_MEANINGFUL_WORK
			case "authority":
				mintStrategy.MintBehavior = protobufs.TokenMintBehavior_MINT_WITH_AUTHORITY
			case "signature":
				mintStrategy.MintBehavior = protobufs.TokenMintBehavior_MINT_WITH_SIGNATURE
			case "payment":
				mintStrategy.MintBehavior = protobufs.TokenMintBehavior_MINT_WITH_PAYMENT
			default:
				return fmt.Errorf("unknown mint strategy: %s", v)
			}
			tokenCfg.MintStrategy = mintStrategy
		}

		if v, ok := configMap["units"]; ok {
			n, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return fmt.Errorf("invalid units value: %s", v)
			}
			tokenCfg.Units = n.Bytes()
		}

		if v, ok := configMap["supply"]; ok {
			n, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return fmt.Errorf("invalid supply value: %s", v)
			}
			tokenCfg.Supply = n.Bytes()
		}

		update := &protobufs.TokenUpdate{
			Config: tokenCfg,
		}

		// Clone without signature for signing
		updateClone := proto.Clone(update).(*protobufs.TokenUpdate)
		updateClone.PublicKeySignatureBls48581 = nil

		aggSig, err := signUpdate(updateClone, domainBytes, "TOKEN_UPDATE")
		if err != nil {
			return fmt.Errorf("sign token update: %w", err)
		}
		update.PublicKeySignatureBls48581 = aggSig

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_TokenUpdate{
				TokenUpdate: update,
			},
		}

		if err := sendDeployMessage(client, domainBytes, request); err != nil {
			return fmt.Errorf("send token update: %w", err)
		}

		fmt.Println("Token update sent successfully")
		fmt.Printf("  Domain: %s\n", hex.EncodeToString(domainBytes))

		return nil
	},
}

var UpdateHypergraphCmd = &cobra.Command{
	Use:   "update [RDFFileName] [key=value...]",
	Short: "Update a deployed hypergraph configuration",
	Long: `Update a deployed hypergraph configuration. Requires --domain flag.

Optional RDF file (*.rdf) for schema update.
Configuration keys:
  read_public_key=<hex>   Ed448 read public key (57 bytes)
  write_public_key=<hex>  Ed448 write public key (57 bytes)
  owner_public_key=<hex>  BLS48-581 owner public key (585 bytes)`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateDomainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(updateDomainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var rdfFile string
		configMap := make(map[string]string)
		for _, arg := range args {
			if strings.HasSuffix(arg, ".rdf") {
				rdfFile = arg
			} else if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				configMap[strings.ToLower(parts[0])] = parts[1]
			}
		}

		hgCfg := &protobufs.HypergraphConfiguration{}

		if v, ok := configMap["read_public_key"]; ok {
			hgCfg.ReadPublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid read_public_key hex: %w", err)
			}
		}
		if v, ok := configMap["write_public_key"]; ok {
			hgCfg.WritePublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid write_public_key hex: %w", err)
			}
		}
		if v, ok := configMap["owner_public_key"]; ok {
			hgCfg.OwnerPublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid owner_public_key hex: %w", err)
			}
		}

		update := &protobufs.HypergraphUpdate{
			Config: hgCfg,
		}

		if rdfFile != "" {
			rdfSchema, err := os.ReadFile(rdfFile)
			if err != nil {
				return fmt.Errorf("read RDF file %q: %w", rdfFile, err)
			}
			update.RdfSchema = rdfSchema
		}

		updateClone := proto.Clone(update).(*protobufs.HypergraphUpdate)
		updateClone.PublicKeySignatureBls48581 = nil

		aggSig, err := signUpdate(updateClone, domainBytes, "HYPERGRAPH_UPDATE")
		if err != nil {
			return fmt.Errorf("sign hypergraph update: %w", err)
		}
		update.PublicKeySignatureBls48581 = aggSig

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_HypergraphUpdate{
				HypergraphUpdate: update,
			},
		}

		if err := sendDeployMessage(client, domainBytes, request); err != nil {
			return fmt.Errorf("send hypergraph update: %w", err)
		}

		fmt.Println("Hypergraph update sent successfully")
		fmt.Printf("  Domain: %s\n", hex.EncodeToString(domainBytes))

		return nil
	},
}

var UpdateComputeCmd = &cobra.Command{
	Use:   "update [RDFFileName] [key=value...]",
	Short: "Update a deployed compute configuration",
	Long: `Update a deployed compute configuration. Requires --domain flag.

Optional RDF file (*.rdf) for schema update.
Configuration keys:
  read_public_key=<hex>   Ed448 read public key (57 bytes)
  write_public_key=<hex>  Ed448 write public key (57 bytes)
  owner_public_key=<hex>  BLS48-581 owner public key (585 bytes)`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateDomainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(updateDomainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var rdfFile string
		configMap := make(map[string]string)
		for _, arg := range args {
			if strings.HasSuffix(arg, ".rdf") {
				rdfFile = arg
			} else if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				configMap[strings.ToLower(parts[0])] = parts[1]
			}
		}

		computeCfg := &protobufs.ComputeConfiguration{}

		if v, ok := configMap["read_public_key"]; ok {
			computeCfg.ReadPublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid read_public_key hex: %w", err)
			}
		}
		if v, ok := configMap["write_public_key"]; ok {
			computeCfg.WritePublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid write_public_key hex: %w", err)
			}
		}
		if v, ok := configMap["owner_public_key"]; ok {
			computeCfg.OwnerPublicKey, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return fmt.Errorf("invalid owner_public_key hex: %w", err)
			}
		}

		update := &protobufs.ComputeUpdate{
			Config: computeCfg,
		}

		if rdfFile != "" {
			rdfSchema, err := os.ReadFile(rdfFile)
			if err != nil {
				return fmt.Errorf("read RDF file %q: %w", rdfFile, err)
			}
			update.RdfSchema = rdfSchema
		}

		updateClone := proto.Clone(update).(*protobufs.ComputeUpdate)
		updateClone.PublicKeySignatureBls48581 = nil

		aggSig, err := signUpdate(updateClone, domainBytes, "COMPUTE_UPDATE")
		if err != nil {
			return fmt.Errorf("sign compute update: %w", err)
		}
		update.PublicKeySignatureBls48581 = aggSig

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_ComputeUpdate{
				ComputeUpdate: update,
			},
		}

		if err := sendDeployMessage(client, domainBytes, request); err != nil {
			return fmt.Errorf("send compute update: %w", err)
		}

		fmt.Println("Compute update sent successfully")
		fmt.Printf("  Domain: %s\n", hex.EncodeToString(domainBytes))

		return nil
	},
}

func init() {
	UpdateTokenCmd.Flags().StringVarP(
		&updateDomainAddress, "domain", "d", "",
		"Domain address of the deployed token",
	)
	UpdateHypergraphCmd.Flags().StringVarP(
		&updateDomainAddress, "domain", "d", "",
		"Domain address of the deployed hypergraph",
	)
	UpdateComputeCmd.Flags().StringVarP(
		&updateDomainAddress, "domain", "d", "",
		"Domain address of the deployed compute",
	)

	DeployTokenCmd.AddCommand(UpdateTokenCmd)
	DeployHypergraphCmd.AddCommand(UpdateHypergraphCmd)
	DeployComputeCmd.AddCommand(UpdateComputeCmd)
}
