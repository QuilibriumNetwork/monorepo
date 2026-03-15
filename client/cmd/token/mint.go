package token

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	chg "source.quilibrium.com/quilibrium/monorepo/client/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	nodekeys "source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

var MintCmd = &cobra.Command{
	Use:   "mint <ProofHex> [<RecipientAccount>]",
	Short: "Mints tokens from proof of work",
	Long: `Mints tokens from proof of work:
	mint <ProofHex> [<RecipientAccount>]
	ProofHex - the hex encoded proof of work
	RecipientAccount - optional recipient account (view_key:spend_key in hex), defaults to self`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proofHex := strings.TrimPrefix(args[0], "0x")
		proof, err := hex.DecodeString(proofHex)
		if err != nil {
			fmt.Printf("Invalid proof hex: %v\n", err)
			os.Exit(1)
		}

		var recipientViewKey, recipientSpendKey []byte

		vk, sk := getOwnKeys()

		if len(args) > 1 {
			recipientViewKey, recipientSpendKey, err = parseAccount(args[1])
			if err != nil {
				fmt.Printf("Invalid recipient account: %v\n", err)
				os.Exit(1)
			}
		} else {
			recipientViewKey = vk.Public()
			recipientSpendKey = sk.Public()
		}

		conn, err := utils.GetGRPCClient(
			LightNode,
			ClientConfig.CustomRpc,
			NodeConfig,
		)
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)

		// Set up crypto primitives
		logger, _ := zap.NewProduction()
		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		bulletproofProver := bulletproofs.NewBulletproofProver()
		decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		verEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

		var domain [32]byte
		copy(domain[:], token.QUIL_TOKEN_ADDRESS[:32])

		rdfSchema, err := token.PrepareRDFSchemaFromConfig(
			token.QUIL_TOKEN_ADDRESS,
			token.QUIL_TOKEN_CONFIGURATION,
		)
		if err != nil {
			fmt.Printf("Failed to prepare RDF schema: %v\n", err)
			os.Exit(1)
		}

		rdfMultiprover := schema.NewRDFMultiprover(
			&schema.TurtleRDFParser{},
			inclusionProver,
		)

		hg := chg.NewRemoteHypergraph(client, inclusionProver, domain)
		keyRing := nodekeys.ToKeyRing(KeyManager, false)

		// Build MintTransactionInput
		mintInput, err := token.NewMintTransactionInput(
			big.NewInt(0), // value determined by proof
			proof,
		)
		if err != nil {
			fmt.Printf("Failed to create mint input: %v\n", err)
			os.Exit(1)
		}

		mintOutput, err := token.NewMintTransactionOutput(
			big.NewInt(0), // value determined by proof
			recipientViewKey,
			recipientSpendKey,
		)
		if err != nil {
			fmt.Printf("Failed to create mint output: %v\n", err)
			os.Exit(1)
		}

		mintTx := token.NewMintTransaction(
			domain,
			[]*token.MintTransactionInput{mintInput},
			[]*token.MintTransactionOutput{mintOutput},
			[]*big.Int{big.NewInt(0)},
			token.QUIL_TOKEN_CONFIGURATION,
			hg,
			bulletproofProver,
			inclusionProver,
			verEncryptor,
			decafConstructor,
			keyRing,
			rdfSchema,
			rdfMultiprover,
			nil, // clockStore not needed for Prove()
		)

		frameInfo, err := client.GetNodeInfo(
			context.Background(),
			&protobufs.GetNodeInfoRequest{},
		)
		if err != nil {
			fmt.Printf("Failed to get node info: %v\n", err)
			os.Exit(1)
		}
		frameNumber := frameInfo.GetLastGlobalHeadFrame()

		if err := mintTx.Prove(frameNumber); err != nil {
			fmt.Printf("Failed to prove mint transaction: %v\n", err)
			os.Exit(1)
		}

		err = SendTransaction(
			client,
			token.QUIL_TOKEN_ADDRESS,
			&protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_MintTransaction{
					MintTransaction: mintTx.ToProtobuf(),
				},
			},
			KeyManager,
		)
		if err != nil {
			fmt.Printf("Failed to send transaction: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Mint transaction sent successfully")
	},
}
