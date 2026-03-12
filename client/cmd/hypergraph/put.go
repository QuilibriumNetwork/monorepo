package hypergraph

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"

	hgpkg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var domainAddress string

var PutCmd = &cobra.Command{
	Use:   "put",
	Short: "Insert or update hypergraph data",
	Long:  `Insert or update vertex or hyperedge data in the hypergraph.`,
}

var PutVertexCmd = &cobra.Command{
	Use:   "vertex [key=value...] [EncryptionKeyBytes]",
	Short: "Insert or update vertex data",
	Long: `Encrypts and inserts a vertex into the hypergraph.
Requires --domain flag with 32-byte hex domain address or alias.
Properties are specified as key=value pairs.`,
	Args: cobra.MinimumNArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if domainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(domainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var domain [32]byte
		copy(domain[:], domainBytes)

		// Parse key=value pairs and optional encryption key
		var rawData []byte
		var encryptionKey string
		for _, arg := range args {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				rawData = append(rawData, []byte(parts[0])...)
				rawData = append(rawData, []byte(parts[1])...)
			} else {
				encryptionKey = arg
			}
		}

		if len(rawData) == 0 {
			return fmt.Errorf("at least one key=value property is required")
		}

		// Generate deterministic data address from data hash
		dataHash := sha3.Sum256(rawData)
		var dataAddress [32]byte
		copy(dataAddress[:], dataHash[:])

		// Init crypto
		inclusionProver, _, verEnc, signer, err := initCrypto()
		if err != nil {
			return fmt.Errorf("init crypto: %w", err)
		}

		// Encrypt data
		var encKey []byte
		if encryptionKey != "" {
			encKey, err = hex.DecodeString(strings.TrimPrefix(encryptionKey, "0x"))
			if err != nil {
				return fmt.Errorf("invalid encryption key hex: %w", err)
			}
		}

		encrypted := verEnc.Encrypt(rawData, encKey)
		if len(encrypted) == 0 {
			return fmt.Errorf("could not encrypt data")
		}

		// Compress and build tree
		out := []hypergraph.Encrypted{}
		for _, d := range encrypted {
			out = append(out, d.Compress())
		}
		tree := hypergraph.EncryptedToVertexTree(inclusionProver, out)

		// Serialize tree
		serialized, err := tries.SerializeNonLazyTree(tree)
		if err != nil {
			return fmt.Errorf("serialize tree: %w", err)
		}

		// Build signing message: domain || data_address || proof_bytes
		message := []byte{}
		message = append(message, domain[:]...)
		message = append(message, dataAddress[:]...)
		for _, d := range encrypted {
			message = append(message, d.ToBytes()...)
		}

		// Sign
		sig, err := signer.SignWithDomain(
			message,
			slices.Concat(domain[:], []byte("VERTEX_ADD")),
		)
		if err != nil {
			return fmt.Errorf("sign vertex add: %w", err)
		}

		// Build and send message
		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_VertexAdd{
				VertexAdd: &protobufs.VertexAdd{
					Domain:      domain[:],
					DataAddress: dataAddress[:],
					Data:        serialized,
					Signature:   sig,
				},
			},
		}

		if err := sendHypergraphMessage(client, domain[:], request); err != nil {
			return fmt.Errorf("send vertex add: %w", err)
		}

		fullAddress := append(domain[:], dataAddress[:]...)
		fmt.Printf("Vertex submitted successfully\n")
		fmt.Printf("Full address: %s\n", hex.EncodeToString(fullAddress))

		return nil
	},
}

var PutHyperedgeCmd = &cobra.Command{
	Use:   "hyperedge <FullAddress|Alias> [AtomAddresses|Aliases...]",
	Short: "Insert or update hyperedge data",
	Long: `Creates a hyperedge connecting atoms in the hypergraph.
Requires --domain flag with 32-byte hex domain address or alias.
FullAddress is the 64-byte hex hyperedge address or alias.
AtomAddresses are 64-byte hex addresses (or aliases) of atoms to connect, comma-separated.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if domainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(domainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var domain [32]byte
		copy(domain[:], domainBytes)

		// Parse hyperedge full address
		fullAddrBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("hyperedge address: %w", err)
		}

		var appAddr, dataAddr [32]byte
		copy(appAddr[:], fullAddrBytes[:32])
		copy(dataAddr[:], fullAddrBytes[32:])

		// Parse atom addresses (support aliases and comma-separated lists)
		var atomAddresses [][64]byte
		for i := 1; i < len(args); i++ {
			for _, atomArg := range strings.Split(args[i], ",") {
				atomArg = strings.TrimSpace(atomArg)
				if atomArg == "" {
					continue
				}
				atomBytes, err := resolveAddress(atomArg, 64)
				if err != nil {
					return fmt.Errorf("atom address %q: %w", atomArg, err)
				}
				var atomID [64]byte
				copy(atomID[:], atomBytes)
				atomAddresses = append(atomAddresses, atomID)
			}
		}

		// Init crypto
		inclusionProver, _, _, signer, err := initCrypto()
		if err != nil {
			return fmt.Errorf("init crypto: %w", err)
		}

		// Create hyperedge and add atoms
		he := hgpkg.NewHyperedge(appAddr, dataAddr)
		for _, atomID := range atomAddresses {
			// Create minimal atom reference for extrinsic tree
			atom := &atomRef{id: atomID}
			he.AddExtrinsic(atom)
		}

		// Commit to generate commitment
		commit := he.Commit(inclusionProver)
		if len(commit) == 0 {
			return fmt.Errorf("failed to generate hyperedge commitment")
		}

		// Serialize hyperedge
		heBytes := he.ToBytes()
		if len(heBytes) == 0 {
			return fmt.Errorf("failed to serialize hyperedge")
		}

		// Sign: hyperedge_id || commitment
		hyperedgeID := he.GetID()
		signMessage := make([]byte, 0, 64+len(commit))
		signMessage = append(signMessage, hyperedgeID[:]...)
		signMessage = append(signMessage, commit...)

		sig, err := signer.SignWithDomain(
			signMessage,
			slices.Concat(domain[:], []byte("HYPEREDGE_ADD")),
		)
		if err != nil {
			return fmt.Errorf("sign hyperedge add: %w", err)
		}

		// Build and send message
		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_HyperedgeAdd{
				HyperedgeAdd: &protobufs.HyperedgeAdd{
					Domain:    domain[:],
					Value:     heBytes,
					Signature: sig,
				},
			},
		}

		if err := sendHypergraphMessage(client, domain[:], request); err != nil {
			return fmt.Errorf("send hyperedge add: %w", err)
		}

		fmt.Printf("Hyperedge submitted successfully\n")
		fmt.Printf("Full address: %s\n", hex.EncodeToString(hyperedgeID[:]))

		return nil
	},
}

// atomRef is a minimal Atom implementation used for building hyperedge extrinsics.
type atomRef struct {
	id [64]byte
}

func (a *atomRef) GetID() [64]byte                                    { return a.id }
func (a *atomRef) GetAtomType() hypergraph.AtomType                   { return hypergraph.VertexAtomType }
func (a *atomRef) GetAppAddress() [32]byte                            { return [32]byte(a.id[:32]) }
func (a *atomRef) GetDataAddress() [32]byte                           { return [32]byte(a.id[32:]) }
func (a *atomRef) ToBytes() []byte                                    { return a.id[:] }
func (a *atomRef) GetSize() *big.Int                                  { return big.NewInt(64) }
func (a *atomRef) Commit(prover qcrypto.InclusionProver) []byte       { return a.id[:] }

func init() {
	PutCmd.PersistentFlags().StringVarP(&domainAddress, "domain", "d", "", "Domain address for the operation (32-byte hex)")
	PutCmd.AddCommand(PutVertexCmd)
	PutCmd.AddCommand(PutHyperedgeCmd)
}
