package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	libP2pCrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
)

var (
	NodeConfig      *config.Config
	ConfigDirectory string
)

var CrossMintCmd = &cobra.Command{
	Use:   "cross-mint",
	Short: "Signs a payload from the Quilibrium bridge to mint tokens on Ethereum L1 and prints the result to stdout",
	Long: `Signs a payload from the Quilibrium bridge to mint tokens on Ethereum L1 and prints the result to stdout":
	
	cross-mint <Payload>
	
	Payload – the hex-encoded payload from the Quilibrium bridge with optional 0x-prefix, must be specified
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("missing payload")
			os.Exit(1)
		}

		var nodeConfig *config.Config
		var err error
		if ConfigDirectory != "" && ConfigDirectory != "default" {
			nodeConfig, err = utils.LoadNodeConfig(ConfigDirectory)
		} else {
			nodeConfig, err = utils.LoadDefaultNodeConfig()
		}
		if err != nil {
			fmt.Printf("error loading node config: %s\n", err)
			os.Exit(1)
		}

		NodeConfig = nodeConfig
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("missing payload")
			os.Exit(1)
		}

		if len(args) > 2 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		rawPeerKey, err := hex.DecodeString(NodeConfig.P2P.PeerPrivKey)
		if err != nil {
			panic(errors.Wrap(err, "cross mint"))
		}

		peerKey, err := libP2pCrypto.UnmarshalEd448PrivateKey(rawPeerKey)
		if err != nil {
			panic(errors.Wrap(err, "cross mint"))
		}

		rawPeerKey, err = peerKey.Raw()
		if err != nil {
			panic(errors.Wrap(err, "cross mint"))
		}

		// TODO: support other key managers
		// Get the proving key
		// `config.Key.KeyStoreFile.Path` defaults to `.config/keys.yml`.
		// We do our best here to make sure the  configuration value is taken into
		// account if it was changed.
		if !filepath.IsAbs(NodeConfig.Key.KeyStoreFile.Path) {
			NodeConfig.Key.KeyStoreFile.Path = filepath.Join(
				ConfigDirectory,
				filepath.Base(NodeConfig.Key.KeyStoreFile.Path),
			)
		}

		logger, err := zap.NewProduction()
		if err != nil {
			panic(errors.Wrap(err, "cross mint"))
		}

		fileKeyManager := keys.NewFileKeyManager(NodeConfig, &bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{}, logger)
		provingKey, err := fileKeyManager.GetSigningKey(NodeConfig.Engine.ProvingKeyId)
		if err != nil {
			panic(errors.Wrap(err, "cross mint"))
		}
		// Sign the payload
		result, err := CrossMint(&CrossMintArgs{
			Payload:    args[0],
			PeerKey:    rawPeerKey,
			ProvingKey: ed448.PrivateKey(provingKey.Private()),
		})
		if err != nil {
			panic(errors.Wrap(err, "error cross minting"))
		}
		// Print the result
		jsonResult, err := json.Marshal(result)
		if err != nil {
			panic(errors.Wrap(err, "error marshaling result to json"))
		}
		fmt.Println(string(jsonResult))
	},
}

// CrossMintArgs Arguments for the cross mint operation
type CrossMintArgs struct {
	// Hex encoded payload with optional 0x prefix
	Payload string
	// The node's ed448 peer key
	PeerKey ed448.PrivateKey
	// The node's ed448 proving key
	ProvingKey ed448.PrivateKey
}

// CrossMintResult Result of the cross mint operation
type CrossMintResult struct {
	// Base64 encoded peer public key
	PeerPublicKey string `json:"peerPublicKey"`
	// Base64 encoded signature of the payload with the peer private key
	PeerSignature string `json:"peerSignature"`
	// Base64 encoded prover public key
	ProverPublicKey string `json:"proverPublicKey"`
	// Base64 encoded signature of the payload with the prover private key
	ProverSignature string `json:"proverSignature"`
}

func CrossMint(args *CrossMintArgs) (*CrossMintResult, error) {
	rawPayload, err := decodeHexString(args.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "cross mint")
	}

	peerSignature := ed448.Sign(args.PeerKey, rawPayload, "")
	peerPubKey, ok := args.PeerKey.Public().(ed448.PublicKey)
	if !ok {
		return nil, errors.Wrap(
			errors.New("error casting peer public key to ed448 public key"),
			"cross mint",
		)
	}

	provingSignature := ed448.Sign(
		args.ProvingKey,
		rawPayload,
		"",
	)
	provingPubKey, ok := args.ProvingKey.Public().(ed448.PublicKey)
	if !ok {
		return nil, errors.Wrap(
			errors.New("error casting proving public key to ed448 public key"),
			"cross mint",
		)
	}
	return &CrossMintResult{
		PeerPublicKey:   base64.StdEncoding.EncodeToString(peerPubKey),
		PeerSignature:   base64.StdEncoding.EncodeToString(peerSignature),
		ProverPublicKey: base64.StdEncoding.EncodeToString(provingPubKey),
		ProverSignature: base64.StdEncoding.EncodeToString(provingSignature),
	}, nil
}

// VerifyCrossMint Verify a cross-mint message. Returns true if both signatures
// verify with the given public keys.
func VerifyCrossMint(payload string, result *CrossMintResult) (bool, error) {
	payloadBytes, err := decodeHexString(payload)
	if err != nil {
		return false, err
	}
	peerPubKeyBytes, err := base64.StdEncoding.DecodeString(result.PeerPublicKey)
	if err != nil {
		return false, err
	}
	peerPubKey := ed448.PublicKey(peerPubKeyBytes)
	peerSignature, err := base64.StdEncoding.DecodeString(result.PeerSignature)
	if err != nil {
		return false, err
	}
	proverPubKeyBytes, err := base64.StdEncoding.DecodeString(
		result.ProverPublicKey,
	)
	if err != nil {
		return false, err
	}
	proverPubKey := ed448.PublicKey(proverPubKeyBytes)
	proverSignature, err := base64.StdEncoding.DecodeString(
		result.ProverSignature,
	)
	if err != nil {
		return false, err
	}
	peerSigOk := ed448.Verify(peerPubKey, payloadBytes, peerSignature, "")
	proverSigOk := ed448.Verify(proverPubKey, payloadBytes, proverSignature, "")
	return peerSigOk && proverSigOk, nil
}

func decodeHexString(hexStr string) ([]byte, error) {
	// Check if the string starts with '0x' and remove it
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	// Decode the hex string into bytes
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding hex string")
	}
	return data, nil
}

func init() {
	CrossMintCmd.PersistentFlags().StringVar(&ConfigDirectory, "config", "default", "config directory")
}
