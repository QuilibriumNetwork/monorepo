package prover

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var NodeProverDelegateCmd = &cobra.Command{
	Use:   "delegate <DelegateAddress>",
	Short: "Delegate prover rewards",
	Long: `Delegates rewards for a prover to an alternative address.

	delegate <DelegateAddress>

	DelegateAddress - the 0x-prefixed hex-encoded 32-byte destination address
	`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		initKeyManager()
		if KeyManager == nil {
			fmt.Println("Failed to initialize key manager")
			os.Exit(1)
		}

		addrHex := strings.TrimPrefix(args[0], "0x")
		delegateAddress, err := hex.DecodeString(addrHex)
		if err != nil || len(delegateAddress) != 32 {
			fmt.Println("Invalid delegate address: must be 32 bytes hex-encoded")
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

		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		update := global.NewProverUpdate(
			delegateAddress,
			nil, // signature will be populated by Prove()
			nil, // hypergraph not needed for Prove()
			nil, // signer not needed for Prove()
			nil, // rdfMultiprover not needed for Prove()
			KeyManager,
		)

		if err := update.Prove(frameNumber); err != nil {
			fmt.Printf("Failed to prove update: %v\n", err)
			os.Exit(1)
		}

		globalDomain := bytes.Repeat([]byte{0xff}, 32)

		err = sendProverMessage(
			client,
			globalDomain,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Update{
					Update: update.ToProtobuf(),
				},
			},
		)
		if err != nil {
			fmt.Printf("Failed to send delegate update: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Delegate address updated to 0x%s\n", hex.EncodeToString(delegateAddress))
	},
}
