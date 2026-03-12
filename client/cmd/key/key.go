package key

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
)

var (
	keyManager tkeys.KeyManager
	nodeConfig *config.Config
	aliasStore *aliases.Store
)

// Root command
var KeyCmd = &cobra.Command{
	Use:           "key",
	Short:         "Key management operations",
	Long:          `Commands for managing cryptographic keys in Quilibrium.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load node configuration
		cfg, err := utils.LoadDefaultNodeConfig()
		if err != nil {
			return errors.Wrap(err, "load node configuration")
		}
		nodeConfig = cfg

		// Load alias store if configured
		if cfg.Alias != nil && cfg.Alias.AliasFile != nil && cfg.Alias.AliasFile.Path != "" {
			aliasStore, err = aliases.Load(cfg.Alias.AliasFile.Path)
			if err != nil && cfg.Alias.AliasFile.CreateIfMissing {
				aliasStore, err = aliases.NewOnDisk(cfg.Alias.AliasFile.Path)
				if err != nil {
					return errors.Wrap(err, "create alias store")
				}
			} else if err != nil {
				// Alias store is optional, so we don't fail if it doesn't exist
				aliasStore = nil
			}
		}

		// Initialize logger
		logger, err := zap.NewProduction()
		if err != nil {
			return errors.Wrap(err, "create logger")
		}

		// Initialize key manager with constructors actually used in-tree
		keyManager = keys.NewFileKeyManager(
			nodeConfig,
			&bls48581.Bls48581KeyConstructor{},
			&bulletproofs.Decaf448KeyConstructor{},
			logger,
		)
		return nil
	},
}

// key list
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		klist, err := keyManager.ListKeys()
		if err != nil {
			return errors.Wrap(err, "list keys")
		}
		if len(klist) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

		// Stable ordering by ID for deterministic output
		sort.Slice(klist, func(i, j int) bool { return klist[i].Id < klist[j].Id })

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTYPE\tPUBLIC KEY\tALIAS")
		for _, k := range klist {
			pubKeyHex := hex.EncodeToString(k.PublicKey)
			if len(pubKeyHex) > 64 {
				pubKeyHex = pubKeyHex[:64] + "…"
			}

			// Check if there's an alias for this key
			aliasName := ""
			if aliasStore != nil {
				if name, _, ok := aliasStore.FindByAddress(k.PublicKey); ok {
					aliasName = name
				}
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.Id, getKeyTypeName(k.Type), pubKeyHex, aliasName)
		}
		return w.Flush()
	},
}

// key create
var CreateCmd = &cobra.Command{
	Use:   "create <Name> <KeyType> [Purpose]",
	Short: "Create a new key (optional purpose is informational only)",
	Args:  cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		keyTypeStr := args[1]
		var purpose string
		if len(args) == 3 {
			purpose = args[2]
		}

		kt, err := parseKeyType(keyTypeStr)
		if err != nil {
			return err
		}

		signer, popk, err := keyManager.CreateSigningKey(name, kt)
		if err != nil {
			return errors.Wrap(err, "create key")
		}

		pub := signer.Public()
		var pubBytes []byte
		switch v := pub.(type) {
		case []byte:
			pubBytes = v
		default:
			// Best-effort: rely on keyManager’s materialized public key if present
			meta, merr := keyManager.GetRawKey(name)
			if merr == nil && len(meta.PublicKey) > 0 {
				pubBytes = meta.PublicKey
			}
		}

		fmt.Printf("Created key %q (%s)\n", name, getKeyTypeName(kt))
		if len(pubBytes) > 0 {
			fmt.Printf("Public key: %s\n", hex.EncodeToString(pubBytes))

			// Optionally create an alias for this key
			if aliasStore != nil && purpose != "" {
				// Use purpose as a hint for creating an alias
				if err := aliasStore.Put(name, pubBytes, purpose); err != nil {
					fmt.Printf("Warning: failed to create alias: %v\n", err)
				} else {
					fmt.Printf("Created alias %q for this key\n", name)
				}
			}
		}
		if len(popk) > 0 {
			fmt.Printf("Proof of possession: %s\n", hex.EncodeToString(popk))
		}
		if purpose != "" {
			fmt.Printf("Purpose: %s\n", purpose)
		}
		return nil
	},
}

// key delete
var DeleteCmd = &cobra.Command{
	Use:   "delete <Name>",
	Short: "Delete a key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := keyManager.DeleteKey(name); err != nil {
			if errors.Is(err, keys.KeyNotFoundErr) {
				return fmt.Errorf("key %q not found", name)
			}
			return errors.Wrap(err, "delete key")
		}
		fmt.Printf("Deleted key %q\n", name)
		return nil
	},
}

// key import (private key material in hex)
var ImportCmd = &cobra.Command{
	Use:   "import <Name> <KeyType> <KeyBytesHex>",
	Short: "Import a private key (hex)",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		keyTypeStr := args[1]
		keyHex := strings.TrimPrefix(args[2], "0x")

		data, err := hex.DecodeString(keyHex)
		if err != nil {
			return errors.Wrap(err, "decode key hex")
		}

		kt, err := parseKeyType(keyTypeStr)
		if err != nil {
			return err
		}

		// Let the key manager / constructor perform validation and derive public
		// key as needed.
		key := &tkeys.Key{
			Id:         name,
			Type:       kt,
			PrivateKey: append([]byte(nil), data...), // copy
		}

		if err := keyManager.PutRawKey(key); err != nil {
			return errors.Wrap(err, "import key")
		}

		// Try to show the derived public key if available
		meta, merr := keyManager.GetRawKey(name)
		if merr == nil && len(meta.PublicKey) > 0 {
			fmt.Printf(
				"Imported key %q (%s)\nPublic key: %s\n",
				name,
				getKeyTypeName(kt),
				hex.EncodeToString(meta.PublicKey),
			)
		} else {
			fmt.Printf("Imported key %q (%s)\n", name, getKeyTypeName(kt))
		}
		return nil
	},
}

// key sign
var SignCmd = &cobra.Command{
	Use:   "sign <Name> <PayloadHex> [DomainHex]",
	Short: "(DANGEROUS) Sign a raw payload (and optional domain)",
	Args:  cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		payloadHex := strings.TrimPrefix(args[1], "0x")

		signer, err := keyManager.GetSigningKey(name)
		if err != nil {
			if errors.Is(err, keys.KeyNotFoundErr) {
				return fmt.Errorf("key %q not found", name)
			}
			return errors.Wrap(err, "get signing key")
		}

		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			return errors.Wrap(err, "decode payload hex")
		}

		var domain []byte
		if len(args) >= 3 && args[2] != "" {
			dh := strings.TrimPrefix(args[2], "0x")
			domain, err = hex.DecodeString(dh)
			if err != nil {
				return errors.Wrap(err, "decode domain hex")
			}
		}

		sig, err := signer.SignWithDomain(payload, domain)
		if err != nil {
			return errors.Wrap(err, "sign payload")
		}
		fmt.Printf("Signature: %s\n", hex.EncodeToString(sig))
		return nil
	},
}

func init() {
	KeyCmd.AddCommand(ListCmd)
	KeyCmd.AddCommand(CreateCmd)
	KeyCmd.AddCommand(DeleteCmd)
	KeyCmd.AddCommand(ImportCmd)
	KeyCmd.AddCommand(SignCmd)
}

// --- helpers ---

// parseKeyType maps common strings to qcrypto.KeyType.
// Supports both the main set and legacy/auxiliary bit-shifted constants.
func parseKeyType(s string) (qcrypto.KeyType, error) {
	k := strings.ToLower(strings.TrimSpace(s))

	switch k {
	case "ed448":
		return qcrypto.KeyTypeEd448, nil
	case "x448":
		return qcrypto.KeyTypeX448, nil
	case "decaf448", "decaf":
		return qcrypto.KeyTypeDecaf448, nil
	case "bls", "bls48581", "bls48", "bls48581g1", "bls-g1", "g1":
		return qcrypto.KeyTypeBLS48581G1, nil
	case "bls48581g2", "bls-g2", "g2":
		return qcrypto.KeyTypeBLS48581G2, nil

	// optional legacy/compat aliases (not used by key manager, but accepted)
	case "ed25519":
		return qcrypto.KeyTypeEd25519, nil
	case "secp256k1-sha256", "secp256k1/sha256", "k1-sha256":
		return qcrypto.KeyTypeSecp256K1SHA256, nil
	case "secp256k1-sha3", "secp256k1/sha3", "k1-sha3":
		return qcrypto.KeyTypeSecp256K1SHA3, nil
	}

	return 0, fmt.Errorf(
		"unsupported key type %q (supported: ed448, x448, decaf448, bls48581[g1|g2])",
		s,
	)
}

// getKeyTypeName returns a human-readable label.
func getKeyTypeName(kt qcrypto.KeyType) string {
	switch kt {
	case qcrypto.KeyTypeEd448:
		return "Ed448"
	case qcrypto.KeyTypeX448:
		return "X448"
	case qcrypto.KeyTypeDecaf448:
		return "Decaf448"
	case qcrypto.KeyTypeBLS48581G1:
		return "BLS48-581 G1"
	case qcrypto.KeyTypeBLS48581G2:
		return "BLS48-581 G2"
	case qcrypto.KeyTypeSecp256K1SHA256:
		return "secp256k1/SHA-256"
	case qcrypto.KeyTypeSecp256K1SHA3:
		return "secp256k1/SHA-3"
	case qcrypto.KeyTypeEd25519:
		return "Ed25519"
	default:
		// fall back to numeric to avoid hiding unknown values
		return fmt.Sprintf("Type(%d)", kt)
	}
}
