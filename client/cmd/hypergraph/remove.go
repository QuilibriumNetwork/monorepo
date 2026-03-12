package hypergraph

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	hgpkg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var removeDomainAddress string

var RemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove hypergraph data",
	Long:  `Remove vertex or hyperedge data from the hypergraph.`,
}

var RemoveVertexCmd = &cobra.Command{
	Use:   "vertex <FullAddress|Alias>",
	Short: "Remove a vertex from the hypergraph",
	Long: `Removes a vertex from the hypergraph.
Requires --domain flag with 32-byte hex domain address or alias.
FullAddress is the 64-byte hex vertex address (or alias).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if removeDomainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(removeDomainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var domain [32]byte
		copy(domain[:], domainBytes)

		// Parse vertex full address (64 bytes: 32 app + 32 data)
		fullAddrBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("vertex address: %w", err)
		}

		dataAddress := fullAddrBytes[32:64]

		// Init crypto for signing
		_, _, _, signer, err := initCrypto()
		if err != nil {
			return fmt.Errorf("init crypto: %w", err)
		}

		// Sign: message = domain || dataAddress, domain = domain || "VERTEX_REMOVE"
		message := make([]byte, 0, 64)
		message = append(message, domain[:]...)
		message = append(message, dataAddress...)

		sig, err := signer.SignWithDomain(
			message,
			slices.Concat(domain[:], []byte("VERTEX_REMOVE")),
		)
		if err != nil {
			return fmt.Errorf("sign vertex remove: %w", err)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_VertexRemove{
				VertexRemove: &protobufs.VertexRemove{
					Domain:      domain[:],
					DataAddress: dataAddress,
					Signature:   sig,
				},
			},
		}

		if err := sendHypergraphMessage(client, domain[:], request); err != nil {
			return fmt.Errorf("send vertex remove: %w", err)
		}

		fmt.Println("Vertex remove submitted successfully")
		fmt.Printf("Address: %s\n", hex.EncodeToString(fullAddrBytes))

		return nil
	},
}

var RemoveHyperedgeCmd = &cobra.Command{
	Use:   "hyperedge <FullAddress|Alias>",
	Short: "Remove a hyperedge from the hypergraph",
	Long: `Removes a hyperedge from the hypergraph.
Requires --domain flag with 32-byte hex domain address or alias.
FullAddress is the 64-byte hex hyperedge address (or alias).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if removeDomainAddress == "" {
			return fmt.Errorf("--domain is required")
		}

		domainBytes, err := resolveAddress(removeDomainAddress, 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var domain [32]byte
		copy(domain[:], domainBytes)

		// Parse hyperedge full address (64 bytes: 32 app + 32 data)
		fullAddrBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("hyperedge address: %w", err)
		}

		var appAddr, dataAddr [32]byte
		copy(appAddr[:], fullAddrBytes[:32])
		copy(dataAddr[:], fullAddrBytes[32:])

		// Create minimal hyperedge for serialization
		he := hgpkg.NewHyperedge(appAddr, dataAddr)
		heBytes := he.ToBytes()
		if len(heBytes) == 0 {
			return fmt.Errorf("failed to serialize hyperedge")
		}

		// Init crypto for signing
		_, _, _, signer, err := initCrypto()
		if err != nil {
			return fmt.Errorf("init crypto: %w", err)
		}

		// Sign: message = hyperedgeID (64 bytes), domain = domain || "HYPEREDGE_REMOVE"
		hyperedgeID := he.GetID()
		sig, err := signer.SignWithDomain(
			hyperedgeID[:],
			slices.Concat(domain[:], []byte("HYPEREDGE_REMOVE")),
		)
		if err != nil {
			return fmt.Errorf("sign hyperedge remove: %w", err)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_HyperedgeRemove{
				HyperedgeRemove: &protobufs.HyperedgeRemove{
					Domain:    domain[:],
					Value:     heBytes,
					Signature: sig,
				},
			},
		}

		if err := sendHypergraphMessage(client, domain[:], request); err != nil {
			return fmt.Errorf("send hyperedge remove: %w", err)
		}

		fmt.Println("Hyperedge remove submitted successfully")
		fmt.Printf("Address: %s\n", hex.EncodeToString(hyperedgeID[:]))

		return nil
	},
}

func init() {
	RemoveCmd.PersistentFlags().StringVarP(
		&removeDomainAddress, "domain", "d", "",
		"Domain address for the operation (32-byte hex)",
	)
	RemoveCmd.AddCommand(RemoveVertexCmd)
	RemoveCmd.AddCommand(RemoveHyperedgeCmd)
}
