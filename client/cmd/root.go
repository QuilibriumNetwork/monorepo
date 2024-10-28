package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
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
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var configDirectory string
var signatureCheck bool = true
var NodeConfig *config.Config
var simulateFail bool
var LightNode bool = false
var DryRun bool = false

var rootCmd = &cobra.Command{
	Use:   "qclient",
	Short: "Quilibrium RPC Client",
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
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				fmt.Println("Digest file not found")
				os.Exit(1)
			}

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
				signatureFile := fmt.Sprintf(ex+".dgst.sig.%d", i)
				sig, err := os.ReadFile(signatureFile)
				if err != nil {
					continue
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
		} else {
			fmt.Println("Signature check bypassed, be sure you know what you're doing")
		}

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

		if NodeConfig.ListenGRPCMultiaddr == "" {
			fmt.Println("gRPC not enabled, using light node")
			LightNode = true
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
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
}
