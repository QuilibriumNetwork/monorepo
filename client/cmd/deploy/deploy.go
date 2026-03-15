package deploy

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	tokenconfig "source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

var domainAddress string

var DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy to the network",
	Long:  `Deploy files, tokens, hypergraph schemas, or compute programs to the Quilibrium network.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No subcommand specified. Use 'qclient deploy --help' to see available subcommands.")
		fmt.Println("To deploy compute, use: qclient deploy compute <QCLFileName>")
	},
}

const chunkThreshold = 4 * 1024 * 1024 // 4MB

var DeployFileCmd = &cobra.Command{
	Use:   "file <FileName> [EncryptionKeyBytes]",
	Short: "Deploy a file to the hypergraph",
	Long: `Convenience wrapper method that deploys a file to the hypergraph using the
standard file RDF schema. Files >= 4MB are automatically split into chunks.`,
	Args: cobra.RangeArgs(1, 2),
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

		fileName := args[0]
		rawData, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("read file %q: %w", fileName, err)
		}

		var encKey []byte
		if len(args) > 1 {
			encKey, err = hex.DecodeString(strings.TrimPrefix(args[1], "0x"))
			if err != nil {
				return fmt.Errorf("invalid encryption key hex: %w", err)
			}
		}

		if len(rawData) >= chunkThreshold {
			return deployFileChunked(domain, rawData, encKey)
		}
		return deployFileSingle(domain, rawData, encKey)
	},
}

var DeployTokenCmd = &cobra.Command{
	Use:   "token [ConfigurationKey=ConfigurationValue...]",
	Short: "Deploy a token",
	Long: `Deploy a token with the specified configuration.

Configuration keys:
  name=MyToken          Token name
  symbol=MTK            Token symbol
  behavior=mintable,divisible  Comma-separated behavior flags
    Valid flags: mintable, burnable, divisible, acceptable, expirable, tenderable
  mintStrategy=proof    Mint strategy (proof, authority, signature, payment)
  units=1000000         Smallest unit denomination (big integer)
  supply=100000000      Total supply (big integer)`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
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
				return fmt.Errorf("unknown mint strategy: %s (valid: proof, authority, signature, payment)", v)
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

		_, _, ownerPubKey, err := getDeployKeys()
		if err != nil {
			return fmt.Errorf("get deploy keys: %w", err)
		}
		tokenCfg.OwnerPublicKey = ownerPubKey

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_TokenDeploy{
				TokenDeploy: &protobufs.TokenDeploy{
					Config: tokenCfg,
				},
			},
		}

		if err := sendDeployMessage(client, make([]byte, 32), request); err != nil {
			return fmt.Errorf("send token deploy: %w", err)
		}

		fmt.Println("Token deployed successfully")
		if tokenCfg.Name != "" {
			fmt.Printf("  Name: %s\n", tokenCfg.Name)
		}
		if tokenCfg.Symbol != "" {
			fmt.Printf("  Symbol: %s\n", tokenCfg.Symbol)
		}

		return nil
	},
}

var DeployHypergraphCmd = &cobra.Command{
	Use:   "hypergraph [ConfigurationKey=ConfigurationValue...] [RDFFileName]",
	Short: "Deploy a hypergraph schema",
	Long:  `Deploy a hypergraph schema with the specified configuration.`,
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var rdfFile string

		for _, arg := range args {
			if strings.HasSuffix(arg, ".rdf") {
				rdfFile = arg
			}
		}

		readPubKey, writePubKey, ownerPubKey, err := getDeployKeys()
		if err != nil {
			return fmt.Errorf("get deploy keys: %w", err)
		}

		deploy := &protobufs.HypergraphDeploy{
			Config: &protobufs.HypergraphConfiguration{
				ReadPublicKey:  readPubKey,
				WritePublicKey: writePubKey,
				OwnerPublicKey: ownerPubKey,
			},
		}

		if rdfFile != "" {
			rdfSchema, err := os.ReadFile(rdfFile)
			if err != nil {
				return fmt.Errorf("read RDF file %q: %w", rdfFile, err)
			}
			deploy.RdfSchema = rdfSchema
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_HypergraphDeploy{
				HypergraphDeploy: deploy,
			},
		}

		if err := sendDeployMessage(client, make([]byte, 32), request); err != nil {
			return fmt.Errorf("send hypergraph deploy: %w", err)
		}

		fmt.Println("Hypergraph schema deployed successfully")

		return nil
	},
}

var DeployComputeCmd = &cobra.Command{
	Use:   "compute <QCLFileName> [RDFFileName]",
	Short: "Deploy a QCL compute program",
	Long: `Deploys a QCL file to the network. If no domain is specified, deploys a new
compute intrinsic. If --domain is specified, deploys QCL code to an existing domain.

If no RDF schema is present, attempts to infer accompanying RDF file name from
QCLFileName (swapping extension from .qcl to .rdf).`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		qclFile := args[0]
		var rdfFile string

		if len(args) > 1 {
			rdfFile = args[1]
		} else if strings.HasSuffix(qclFile, ".qcl") {
			inferred := strings.TrimSuffix(qclFile, ".qcl") + ".rdf"
			if _, err := os.Stat(inferred); err == nil {
				rdfFile = inferred
				fmt.Printf("Inferred RDF file: %s\n", rdfFile)
			}
		}

		if domainAddress != "" {
			// Deploy QCL code to existing domain
			return deployCodeToExistingDomain(qclFile)
		}

		// Deploy new compute intrinsic
		return deployNewComputeIntrinsic(qclFile, rdfFile)
	},
}

func deployNewComputeIntrinsic(qclFile, rdfFile string) error {
	readPubKey, writePubKey, ownerPubKey, err := getDeployKeys()
	if err != nil {
		return fmt.Errorf("get deploy keys: %w", err)
	}

	deploy := &protobufs.ComputeDeploy{
		Config: &protobufs.ComputeConfiguration{
			ReadPublicKey:  readPubKey,
			WritePublicKey: writePubKey,
			OwnerPublicKey: ownerPubKey,
		},
	}

	if rdfFile != "" {
		rdfSchema, err := os.ReadFile(rdfFile)
		if err != nil {
			return fmt.Errorf("read RDF file %q: %w", rdfFile, err)
		}
		deploy.RdfSchema = rdfSchema
	}

	client, conn, err := getNodeClient()
	if err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}
	defer conn.Close()

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_ComputeDeploy{
			ComputeDeploy: deploy,
		},
	}

	if err := sendDeployMessage(client, make([]byte, 32), request); err != nil {
		return fmt.Errorf("send compute deploy: %w", err)
	}

	fmt.Println("Compute intrinsic deployed successfully")

	return nil
}

func deployCodeToExistingDomain(qclFile string) error {
	circuit, err := os.ReadFile(qclFile)
	if err != nil {
		return fmt.Errorf("read QCL file %q: %w", qclFile, err)
	}

	domainBytes, err := resolveAddress(domainAddress, 32)
	if err != nil {
		return fmt.Errorf("domain: %w", err)
	}

	client, conn, err := getNodeClient()
	if err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}
	defer conn.Close()

	request := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_CodeDeploy{
			CodeDeploy: &protobufs.CodeDeployment{
				Circuit: circuit,
				Domain:  domainBytes,
			},
		},
	}

	if err := sendDeployMessage(client, domainBytes, request); err != nil {
		return fmt.Errorf("send code deploy: %w", err)
	}

	fmt.Println("Code deployed successfully")
	fmt.Printf("  Domain: %s\n", hex.EncodeToString(domainBytes))

	return nil
}

// initCrypto initializes the cryptographic primitives needed for file deployment.
func initCrypto() (
	qcrypto.InclusionProver,
	qcrypto.BulletproofProver,
	qcrypto.VerifiableEncryptor,
	qcrypto.Signer,
	error,
) {
	initKeyManager()
	if keyManager == nil {
		return nil, nil, nil, nil, fmt.Errorf("key manager not available")
	}

	logger, _ := zap.NewProduction()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	bulletproofProver := bulletproofs.NewBulletproofProver()
	verEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	signer, err := keyManager.GetSigningKey("q-node-auth")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("init crypto: get signing key: %w", err)
	}

	return inclusionProver, bulletproofProver, verEncryptor, signer, nil
}

// deployFileSingle deploys a file as a single vertex (< 4MB path).
func deployFileSingle(domain [32]byte, rawData, encKey []byte) error {
	dataHash := sha3.Sum256(rawData)
	var dataAddress [32]byte
	copy(dataAddress[:], dataHash[:])

	inclusionProver, _, verEnc, signer, err := initCrypto()
	if err != nil {
		return fmt.Errorf("init crypto: %w", err)
	}

	encrypted := verEnc.Encrypt(rawData, encKey)
	if len(encrypted) == 0 {
		return fmt.Errorf("could not encrypt data")
	}

	out := []hypergraph.Encrypted{}
	for _, d := range encrypted {
		out = append(out, d.Compress())
	}
	tree := hypergraph.EncryptedToVertexTree(inclusionProver, out)

	serialized, err := tries.SerializeNonLazyTree(tree)
	if err != nil {
		return fmt.Errorf("serialize tree: %w", err)
	}

	message := []byte{}
	message = append(message, domain[:]...)
	message = append(message, dataAddress[:]...)
	for _, d := range encrypted {
		message = append(message, d.ToBytes()...)
	}

	sig, err := signer.SignWithDomain(
		message,
		slices.Concat(domain[:], []byte("VERTEX_ADD")),
	)
	if err != nil {
		return fmt.Errorf("sign vertex add: %w", err)
	}

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

	if err := sendDeployMessage(client, domain[:], request); err != nil {
		return fmt.Errorf("send file deploy: %w", err)
	}

	fullAddress := append(domain[:], dataAddress[:]...)
	fmt.Printf("File deployed successfully\n")
	fmt.Printf("Full address: %s\n", hex.EncodeToString(fullAddress))
	return nil
}

// deployFileChunked splits a large file into 4MB chunks and deploys each as a
// separate vertex, then creates an index vertex that lists the chunk addresses.
func deployFileChunked(domain [32]byte, rawData, encKey []byte) error {
	inclusionProver, _, verEnc, signer, err := initCrypto()
	if err != nil {
		return fmt.Errorf("init crypto: %w", err)
	}

	client, conn, err := getNodeClient()
	if err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}
	defer conn.Close()

	totalSize := uint64(len(rawData))
	chunkSize := uint32(chunkThreshold)
	chunkCount := (len(rawData) + chunkThreshold - 1) / chunkThreshold
	blobAddresses := make([][32]byte, 0, chunkCount)

	for i := 0; i < chunkCount; i++ {
		start := i * chunkThreshold
		end := start + chunkThreshold
		if end > len(rawData) {
			end = len(rawData)
		}
		chunk := rawData[start:end]

		chunkHash := sha3.Sum256(chunk)
		var chunkDataAddress [32]byte
		copy(chunkDataAddress[:], chunkHash[:])

		fmt.Printf("Uploading chunk %d/%d (%.1f MB)...\n",
			i+1, chunkCount, float64(len(chunk))/(1024*1024))

		if err := deployVertex(
			inclusionProver, verEnc, signer, client,
			domain, chunkDataAddress, chunk, encKey,
		); err != nil {
			return fmt.Errorf("deploy chunk %d/%d: %w", i+1, chunkCount, err)
		}

		blobAddresses = append(blobAddresses, chunkDataAddress)
	}

	// Build and deploy the index vertex
	indexContent := hypergraph.BuildFileIndex(totalSize, chunkSize, blobAddresses)
	indexHash := sha3.Sum256(indexContent)
	var indexDataAddress [32]byte
	copy(indexDataAddress[:], indexHash[:])

	fmt.Println("Uploading file index...")

	// Index is encrypted with nil key so it's readable without the decryption key
	if err := deployVertex(
		inclusionProver, verEnc, signer, client,
		domain, indexDataAddress, indexContent, nil,
	); err != nil {
		return fmt.Errorf("deploy file index: %w", err)
	}

	fullAddress := append(domain[:], indexDataAddress[:]...)
	fmt.Printf("File deployed successfully (%d chunks)\n", chunkCount)
	fmt.Printf("Full address: %s\n", hex.EncodeToString(fullAddress))
	return nil
}

// deployVertex encrypts data, builds a vertex tree, signs, and sends via RPC.
func deployVertex(
	inclusionProver qcrypto.InclusionProver,
	verEnc qcrypto.VerifiableEncryptor,
	signer qcrypto.Signer,
	client protobufs.NodeServiceClient,
	domain [32]byte,
	dataAddress [32]byte,
	data []byte,
	encKey []byte,
) error {
	encrypted := verEnc.Encrypt(data, encKey)
	if len(encrypted) == 0 {
		return fmt.Errorf("could not encrypt data")
	}

	out := []hypergraph.Encrypted{}
	for _, d := range encrypted {
		out = append(out, d.Compress())
	}
	tree := hypergraph.EncryptedToVertexTree(inclusionProver, out)

	serialized, err := tries.SerializeNonLazyTree(tree)
	if err != nil {
		return fmt.Errorf("serialize tree: %w", err)
	}

	message := []byte{}
	message = append(message, domain[:]...)
	message = append(message, dataAddress[:]...)
	for _, d := range encrypted {
		message = append(message, d.ToBytes()...)
	}

	sig, err := signer.SignWithDomain(
		message,
		slices.Concat(domain[:], []byte("VERTEX_ADD")),
	)
	if err != nil {
		return fmt.Errorf("sign vertex add: %w", err)
	}

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

	return sendDeployMessage(client, domain[:], request)
}

var DeployFileGetCmd = &cobra.Command{
	Use:   "get <FullAddress|Alias> <OutputPath> [DecryptionKey]",
	Short: "Retrieve a deployed file from the hypergraph",
	Long: `Retrieve a file that was deployed to the hypergraph. Supports both single-vertex
files and chunked files (created by deploy file for files >= 4MB).`,
	Args: cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		addressBytes, err := resolveAddress(args[0], 64)
		if err != nil {
			return fmt.Errorf("address: %w", err)
		}

		outputPath := args[1]

		var decryptionKey []byte
		if len(args) > 2 {
			decryptionKey, err = hex.DecodeString(strings.TrimPrefix(args[2], "0x"))
			if err != nil {
				return fmt.Errorf("invalid decryption key hex: %w", err)
			}
		}

		_, _, verEnc, _, err := initCrypto()
		if err != nil {
			return fmt.Errorf("init crypto: %w", err)
		}

		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		// Fetch primary vertex
		rawData, err := fetchAndDecrypt(client, verEnc, addressBytes, nil)
		if err != nil {
			return fmt.Errorf("fetch vertex: %w", err)
		}

		if !hypergraph.IsFileIndex(rawData) {
			// Small/legacy file — decrypt directly with user key
			if decryptionKey != nil {
				rawData, err = fetchAndDecrypt(client, verEnc, addressBytes, decryptionKey)
				if err != nil {
					return fmt.Errorf("decrypt file: %w", err)
				}
			}
			if err := os.WriteFile(outputPath, rawData, 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("File saved to %s (%d bytes)\n", outputPath, len(rawData))
			return nil
		}

		// Chunked file — parse index and reassemble
		totalSize, _, blobAddresses, err := hypergraph.ParseFileIndex(rawData)
		if err != nil {
			return fmt.Errorf("parse file index: %w", err)
		}

		fmt.Printf("Downloading %d chunks (%.1f MB total)...\n",
			len(blobAddresses), float64(totalSize)/(1024*1024))

		domain := addressBytes[:32]
		assembled := make([]byte, 0, totalSize)

		for i, blobAddr := range blobAddresses {
			fmt.Printf("Downloading chunk %d/%d...\n", i+1, len(blobAddresses))

			chunkAddress := make([]byte, 64)
			copy(chunkAddress[:32], domain)
			copy(chunkAddress[32:], blobAddr[:])
			chunkData, err := fetchAndDecrypt(client, verEnc, chunkAddress, decryptionKey)
			if err != nil {
				return fmt.Errorf("fetch chunk %d/%d: %w", i+1, len(blobAddresses), err)
			}
			assembled = append(assembled, chunkData...)
		}

		// Truncate to exact file size (last chunk may have padding)
		if uint64(len(assembled)) > totalSize {
			assembled = assembled[:totalSize]
		}

		if err := os.WriteFile(outputPath, assembled, 0644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}

		fmt.Printf("File saved to %s (%d bytes)\n", outputPath, len(assembled))
		return nil
	},
}

// fetchAndDecrypt fetches a vertex's full tree data from the node, deserializes
// the tree, extracts encrypted data, and decrypts it.
func fetchAndDecrypt(
	client protobufs.NodeServiceClient,
	verEnc qcrypto.VerifiableEncryptor,
	address []byte,
	decryptionKey []byte,
) ([]byte, error) {
	resp, err := client.GetVertexData(
		context.Background(),
		&protobufs.GetVertexDataRequest{
			Address:  address,
			FullData: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get vertex data: %w", err)
	}

	if len(resp.GetRawData()) == 0 {
		return nil, fmt.Errorf("no raw data returned for vertex")
	}

	tree, err := tries.DeserializeNonLazyTree(resp.GetRawData())
	if err != nil {
		return nil, fmt.Errorf("deserialize tree: %w", err)
	}

	encrypted := hypergraph.VertexTreeToEncrypted(verEnc, tree)
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("no encrypted data found in vertex")
	}

	// Convert hypergraph.Encrypted to crypto.VerEnc for Decrypt
	verEncSlice := make([]qcrypto.VerEnc, len(encrypted))
	for i, e := range encrypted {
		verEncSlice[i] = e.(qcrypto.VerEnc)
	}

	return verEnc.Decrypt(verEncSlice, decryptionKey), nil
}

func init() {
	DeployFileCmd.Flags().StringVarP(&domainAddress, "domain", "d", "", "Domain address for deployment")
	DeployComputeCmd.Flags().StringVarP(&domainAddress, "domain", "d", "", "Domain address for deployment")

	DeployFileCmd.AddCommand(DeployFileGetCmd)

	DeployCmd.AddCommand(DeployFileCmd)
	DeployCmd.AddCommand(DeployTokenCmd)
	DeployCmd.AddCommand(DeployHypergraphCmd)
	DeployCmd.AddCommand(DeployComputeCmd)
}
