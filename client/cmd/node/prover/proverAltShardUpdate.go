package prover

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var NodeProverAltShardUpdateCmd = &cobra.Command{
	Use:   "alt-shard-update <vertex-adds-root> <vertex-removes-root> <hyperedge-adds-root> <hyperedge-removes-root>",
	Short: "Submit an alternative shard state update",
	Long: `Submits an alternative shard state update with the specified roots.

	alt-shard-update <vertex-adds-root> <vertex-removes-root> <hyperedge-adds-root> <hyperedge-removes-root>

	Each root is a hex-encoded value (64 or 74 bytes).
	`,
	Args: cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		initKeyManager()
		if KeyManager == nil {
			fmt.Println("Failed to initialize key manager")
			os.Exit(1)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}

		// Parse the four root arguments
		roots := make([][]byte, 4)
		rootNames := []string{
			"vertex-adds-root",
			"vertex-removes-root",
			"hyperedge-adds-root",
			"hyperedge-removes-root",
		}
		for i, arg := range args {
			roots[i], err = hex.DecodeString(arg)
			if err != nil {
				fmt.Printf("Invalid %s hex: %v\n", rootNames[i], err)
				os.Exit(1)
			}
		}

		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		// Get BLS signer
		signer, err := KeyManager.GetSigningKey("q-prover-key")
		if err != nil {
			fmt.Printf("Failed to get prover key: %v\n", err)
			os.Exit(1)
		}

		blsPublicKey := signer.Public().([]byte)

		// Build message: frameNumber(8 bytes BE) || roots...
		frameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(frameBytes, frameNumber)

		message := make([]byte, 0, 8+len(roots[0])+len(roots[1])+len(roots[2])+len(roots[3]))
		message = append(message, frameBytes...)
		for _, root := range roots {
			message = append(message, root...)
		}

		// Compute domain: poseidon.HashBytes(GLOBAL_INTRINSIC_ADDRESS || "ALT_SHARD_UPDATE")
		globalAddr := bytes.Repeat([]byte{0xff}, 32)
		domainPreimage := slices.Concat(globalAddr, []byte("ALT_SHARD_UPDATE"))
		domainBI, err := poseidon.HashBytes(domainPreimage)
		if err != nil {
			fmt.Printf("Failed to compute domain: %v\n", err)
			os.Exit(1)
		}
		domain := domainBI.FillBytes(make([]byte, 32))

		// Sign
		sig, err := signer.SignWithDomain(message, domain)
		if err != nil {
			fmt.Printf("Failed to sign: %v\n", err)
			os.Exit(1)
		}

		globalDomain := bytes.Repeat([]byte{0xff}, 32)

		err = sendProverMessage(
			client,
			globalDomain,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_AltShardUpdate{
					AltShardUpdate: &protobufs.AltShardUpdate{
						PublicKey:            blsPublicKey,
						FrameNumber:          frameNumber,
						VertexAddsRoot:       roots[0],
						VertexRemovesRoot:    roots[1],
						HyperedgeAddsRoot:    roots[2],
						HyperedgeRemovesRoot: roots[3],
						Signature:            sig,
					},
				},
			},
		)
		if err != nil {
			fmt.Printf("Failed to send alt shard update: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Alt shard update sent successfully")
	},
}
