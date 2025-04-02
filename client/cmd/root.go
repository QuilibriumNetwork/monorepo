package cmd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var configDirectory string
var signatureCheck bool = true
var NodeConfig *config.Config
var simulateFail bool
var LightNode bool = false
var DryRun bool = false
var publicRPC bool = false

var standardizedQClientFileName string = "qclient-" + config.GetVersionString() + "-" + osType + "-" + arch
var rootCmd = &cobra.Command{
	Use:   "qclient",
	Short: "Quilibrium client",
	Long: `Quilibrium client is a command-line tool for managing Quilibrium nodes.
It provides commands for installing, updating, and managing Quilibrium nodes.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if signatureCheck {
			ex, err := os.Executable()
			if err != nil {
				panic(err)
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				fmt.Println(
					"Error encountered during signature check – are you running this " +
						"from source? (use --signature-check=false)",
				)
				panic(err)
			}

			checksum := sha3.Sum256(b)

			// First check var data path for signatures
			varDataPath := filepath.Join(utils.ClientDataPath, config.GetVersionString())
			digestPath := filepath.Join(varDataPath, standardizedQClientFileName+".dgst")

			fmt.Printf("Checking signature for %s\n", digestPath)

			// Try to read digest from var data path first
			digest, err := os.ReadFile(digestPath)
			if err != nil {
				// Fall back to checking next to executable
				digest, err = os.ReadFile(ex + ".dgst")
				if err != nil {
					fmt.Println("The digest file was not found. Do you want to continue without signature verification? (y/n)")
					fmt.Println("You can also use --signature-check=false in your command to skip this prompt")

					reader := bufio.NewReader(os.Stdin)
					response, _ := reader.ReadString('\n')
					response = strings.TrimSpace(strings.ToLower(response))

					if response != "y" && response != "yes" {
						fmt.Println("Exiting due to missing digest file")
						os.Exit(1)
					}

					fmt.Println("Continuing without signature verification")
					signatureCheck = false
				}
			}

			if signatureCheck {
				parts := strings.Split(string(digest), " ")
				if len(parts) != 2 {
					fmt.Println("Invalid digest file format")
					os.Exit(1)
				}

				digestBytes, err := hex.DecodeString(parts[1][:64])
				if err != nil {
					fmt.Println("Invalid digest file format")
					os.Exit(1)
				}

				if !bytes.Equal(checksum[:], digestBytes) {
					fmt.Println("Invalid digest for node")
					os.Exit(1)
				}

				count := 0

				for i := 1; i <= len(config.Signatories); i++ {
					// Try var data path first for signature files
					signatureFile := filepath.Join(varDataPath, fmt.Sprintf("%s.dgst.sig.%d", filepath.Base(ex), i))
					sig, err := os.ReadFile(signatureFile)
					if err != nil {
						// Fall back to checking next to executable
						signatureFile = fmt.Sprintf(ex+".dgst.sig.%d", i)
						sig, err = os.ReadFile(signatureFile)
						if err != nil {
							continue
						}
					}

					pubkey, _ := hex.DecodeString(config.Signatories[i-1])
					if !ed448.Verify(pubkey, digest, sig, "") {
						fmt.Printf("Failed signature check for signatory #%d\n", i)
						os.Exit(1)
					}
					count++
				}

				if count < ((len(config.Signatories)-4)/2)+((len(config.Signatories)-4)%2) {
					fmt.Printf("Quorum on signatures not met")
					os.Exit(1)
				}

				fmt.Println("Signature check passed")
			}
		} else {
			fmt.Println("Signature check bypassed, be sure you know what you're doing")
		}

		// Skip config checks for node and link commands
		if len(os.Args) > 1 && (os.Args[1] != "node" && os.Args[1] != "link") {
			// These commands handle their own configuration
			_, err := os.Stat(configDirectory)
			if os.IsNotExist(err) {
				fmt.Printf("config directory doesn't exist: %s\n", configDirectory)
				os.Exit(1)
			}

			NodeConfig, err = config.LoadConfig(configDirectory, "", false)
			if err != nil {
				fmt.Printf("invalid config directory: %s\n", configDirectory)
				os.Exit(1)
			}

			if publicRPC {
				fmt.Println("Public RPC enabled, using light node")
				LightNode = true
			}

			if !LightNode && NodeConfig.ListenGRPCMultiaddr == "" {
				fmt.Println("No ListenGRPCMultiaddr found in config, using light node")
				LightNode = true
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func GetGRPCClient() (*grpc.ClientConn, error) {
	addr := "rpc.quilibrium.com:8337"
	credentials := credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})
	if !LightNode {
		ma, err := multiaddr.NewMultiaddr(NodeConfig.ListenGRPCMultiaddr)
		if err != nil {
			panic(err)
		}

		_, addr, err = mn.DialArgs(ma)
		if err != nil {
			panic(err)
		}
		credentials = insecure.NewCredentials()
	}

	return grpc.Dial(
		addr,
		grpc.WithTransportCredentials(
			credentials,
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		),
	)
}

func signatureCheckDefault() bool {
	envVarValue, envVarExists := os.LookupEnv("QUILIBRIUM_SIGNATURE_CHECK")
	if envVarExists {
		def, err := strconv.ParseBool(envVarValue)
		if err == nil {
			return def
		} else {
			fmt.Println("Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false'. Got: " + envVarValue)
		}
	}

	return true
}

func init() {
	rootCmd.PersistentFlags().StringVar(
		&configDirectory,
		"config",
		".config/",
		"config directory (default is .config/)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&DryRun,
		"dry-run",
		false,
		"runs the command (if applicable) without actually mutating state (printing effect output)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&signatureCheck,
		"signature-check",
		signatureCheckDefault(),
		"bypass signature check (not recommended for binaries) (default true or value of QUILIBRIUM_SIGNATURE_CHECK env var)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&publicRPC,
		"public-rpc",
		false,
		"uses the public RPCd",
	)

	// Create config directory if it doesn't exist
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Skip for help command and download-signatures command
		if cmd.Name() == "help" || cmd.Name() == "download-signatures" {
			return nil
		}

		// Create config directory if it doesn't exist
		if err := os.MkdirAll(utils.ClientConfigDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %v", err)
		}

		// Check for signature files
		ex, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %v", err)
		}

		// First check var data path for signatures
		version := config.GetVersionString()
		varDataPath := filepath.Join(utils.ClientDataPath, version)
		digestPath := filepath.Join(varDataPath, standardizedQClientFileName+".dgst")
		fmt.Printf("Checking signature for %s\n", digestPath)
		if signatureCheck && !utils.FileExists(digestPath) {
			// Fall back to checking next to executable
			digestPath = ex + ".dgst"
			if !utils.FileExists(digestPath) {
				fmt.Println("Signature file not found. Would you like to download it? (y/n)")
				reader := bufio.NewReader(os.Stdin)
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(strings.ToLower(response))

				if response == "y" || response == "yes" {
					fmt.Println("Downloading signature files...")
					if version == "" {
						fmt.Println("Could not determine version from executable name")
						return fmt.Errorf("could not determine version from executable name")
					}

					// Download signature files
					if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeQClient, version); err != nil {
						fmt.Printf("Error downloading signature files: %v\n", err)
						return fmt.Errorf("failed to download signature files: %v", err)
					}
					fmt.Println("Successfully downloaded signature files")
				} else {
					fmt.Println("Continuing without signature verification")
					signatureCheck = false
				}
			}
		}
		return nil
	}

	// Add the node command
	rootCmd.AddCommand(node.NodeCmd)
}
