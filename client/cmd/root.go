package cmd

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"

	clientConfig "source.quilibrium.com/quilibrium/monorepo/client/cmd/config"
	"source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/cmd/token"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var configDirectory string
var signatureCheck bool = true
var byPassSignatureCheck bool = false
var NodeConfig *config.Config
var simulateFail bool
var DryRun bool = false
var ClientConfig *utils.ClientConfig

var StandardizedQClientFileName string = "qclient-" + config.GetVersionString() + "-" + osType + "-" + arch

var rootCmd = &cobra.Command{
	Use:   "qclient",
	Short: "Quilibrium client",
	Long: `Quilibrium client is a command-line tool for managing Quilibrium nodes.
It provides commands for installing, updating, and managing Quilibrium nodes.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		if cmd.Name() == "help" || cmd.Name() == "download-signatures" {
			return
		}

		if !utils.FileExists(utils.GetConfigPath()) {
			fmt.Println("Client config not found, creating default config")
			utils.CreateDefaultConfig()
		}

		clientConfig, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading client config: %v\n", err)
			os.Exit(1)
		}

		if !clientConfig.SignatureCheck || byPassSignatureCheck {
			signatureCheck = false
		}

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
			digestPath := filepath.Join(varDataPath, StandardizedQClientFileName+".dgst")

			fmt.Printf("Checking signature for %s\n", digestPath)

			// Try to read digest from var data path first
			digest, err := os.ReadFile(digestPath)
			if err != nil {
				// Fall back to checking next to executable
				digest, err = os.ReadFile(ex + ".dgst")
				if err != nil {
					fmt.Println("")
					fmt.Println("The digest file was not found. Do you want to continue without signature verification? (y/n)")

					reader := bufio.NewReader(os.Stdin)
					response, _ := reader.ReadString('\n')
					response = strings.ToLower(strings.TrimSpace(response))

					if response != "y" && response != "yes" {
						fmt.Println("Exiting due to missing digest file")
						fmt.Println("The signature files (if they exist) can be downloaded with the 'qclient download-signatures' command")
						fmt.Println("You can also skip this prompt manually by using the --signature-check=false flag or to permanently disable signature checks running 'qclient config signature-check false'")

						os.Exit(1)
					}
					// Check if the user is trying to run the config command to disable/enable signature checks
					if len(os.Args) >= 3 && os.Args[1] == "config" && os.Args[2] != "signature-check" {
						fmt.Println("The signature files (if they exist) can be downloaded with the 'qclient download-signatures' command")
						fmt.Println("You can also skip this prompt manually by using the --signature-check=false flag or to permanently disable signature checks running 'qclient config signature-check false'")
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
			fmt.Println("----------------------------------------------------------")
			fmt.Println("")
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
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
	rootCmd.PersistentFlags().BoolVar(
		&signatureCheck,
		"signature-check",
		signatureCheckDefault(),
		"bypass signature check (not recommended for binaries) (default true or value of QUILIBRIUM_SIGNATURE_CHECK env var)",
	)

	rootCmd.PersistentFlags().BoolVarP(
		&byPassSignatureCheck,
		"yes",
		"y",
		false,
		"auto-approve and bypass signature check (sets signature-check=false)",
	)

	// Add the node command
	rootCmd.AddCommand(node.NodeCmd)
	rootCmd.AddCommand(clientConfig.ConfigCmd)
	rootCmd.AddCommand(token.TokenCmd)
}
