package compute

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	aliases "source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
)

var nodeConfig *config.Config
var keyMgr tkeys.KeyManager
var aliasStore *aliases.Store

func getConfig() *config.Config {
	if nodeConfig != nil {
		return nodeConfig
	}
	cfg, err := utils.LoadDefaultNodeConfig()
	if err != nil {
		return nil
	}
	nodeConfig = cfg
	return cfg
}

func initKeyManager() {
	if keyMgr != nil {
		return
	}
	cfg := getConfig()
	if cfg == nil {
		return
	}
	keyMgr = keys.NewFileKeyManager(cfg, nil, nil, nil)
}

func initAliasStore() {
	if aliasStore != nil {
		return
	}
	cfg := getConfig()
	if cfg == nil {
		return
	}
	aliasStore, _ = utils.LoadAliasStore(cfg)
}

func resolveAddress(input string, expectedLen int) ([]byte, error) {
	initAliasStore()
	if aliasStore != nil {
		if addr, _, ok := aliasStore.Resolve(input); ok {
			if len(addr) != expectedLen {
				return nil, fmt.Errorf(
					"alias %q resolved to %d bytes, expected %d",
					input, len(addr), expectedLen,
				)
			}
			fmt.Printf("Resolved alias %q to %s\n", input, hex.EncodeToString(addr))
			return addr, nil
		}
	}

	h := strings.TrimPrefix(input, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("must be an alias or hex address: %w", err)
	}
	if len(b) != expectedLen {
		return nil, fmt.Errorf(
			"expected %d bytes (%d hex chars), got %d bytes",
			expectedLen, expectedLen*2, len(b),
		)
	}
	return b, nil
}

func getNodeClient() (protobufs.NodeServiceClient, *grpc.ClientConn, error) {
	cfg := getConfig()
	if cfg == nil {
		return nil, nil, errors.New("no config available")
	}

	conn, err := utils.GetGRPCClient(false, "", cfg)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get node client")
	}

	return protobufs.NewNodeServiceClient(conn), conn, nil
}

var ComputeCmd = &cobra.Command{
	Use:   "compute",
	Short: "Compute operations",
	Long:  `Commands for executing compute operations on the Quilibrium network.`,
}

var ExecuteCmd = &cobra.Command{
	Use:   "execute <FullAddress|Alias> [Rendezvous] [PartyId] [ArgumentKey=ArgumentValue...]",
	Short: "Execute a compute operation",
	Long: `Performs an execution of a given address (or alias), as the given party identifier (1, 2, ..., n)
using the rendezvous address if applicable, and finalizes any settled data outputs to the hypergraph.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse domain (full address or alias)
		domainBytes, err := resolveAddress(args[0], 32)
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}

		var domain [32]byte
		copy(domain[:], domainBytes)

		// Parse optional arguments
		var rendezvousHex, partyIdStr string
		var arguments []string
		for i := 1; i < len(args); i++ {
			if strings.Contains(args[i], "=") {
				arguments = append(arguments, args[i])
			} else if rendezvousHex == "" {
				rendezvousHex = args[i]
			} else if partyIdStr == "" {
				partyIdStr = args[i]
			}
		}

		// Parse or generate rendezvous
		var rendezvous [32]byte
		if rendezvousHex != "" {
			rendezvousBytes, err := hex.DecodeString(strings.TrimPrefix(rendezvousHex, "0x"))
			if err != nil {
				return fmt.Errorf("invalid rendezvous hex: %w", err)
			}
			if len(rendezvousBytes) != 32 {
				return fmt.Errorf("rendezvous must be 32 bytes, got %d bytes", len(rendezvousBytes))
			}
			copy(rendezvous[:], rendezvousBytes)
		} else {
			if _, err := rand.Read(rendezvous[:]); err != nil {
				return fmt.Errorf("generate rendezvous: %w", err)
			}
		}

		// Parse party ID
		_ = partyIdStr // party ID is used for multi-party execution context

		// Init crypto
		initKeyManager()
		if keyMgr == nil {
			return fmt.Errorf("key manager not available")
		}

		cfg := getConfig()
		if cfg == nil {
			return fmt.Errorf("no config available")
		}

		logger, _ := zap.NewProduction()
		_ = bls48581.NewKZGInclusionProver(logger) // inclusionProver for future use
		bulletproofProver := bulletproofs.NewBulletproofProver()

		// Get peer private key for proof of payment
		peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
		if err != nil {
			return fmt.Errorf("decode peer private key: %w", err)
		}

		payerPublicKey := peerPrivKey[57:]
		secretKey := peerPrivKey[:57]

		// Build execute operations
		operations := []*protobufs.ExecuteOperation{}
		mainOp := &protobufs.ExecuteOperation{
			Application: &protobufs.Application{
				Address:          domain[:],
				ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
			},
		}

		// Add argument identifier if provided
		if len(arguments) > 0 {
			var identBytes []byte
			for _, arg := range arguments {
				identBytes = append(identBytes, []byte(arg)...)
			}
			mainOp.Identifier = identBytes
		} else {
			// Use party ID as identifier if available
			if partyIdStr != "" {
				partyID, err := strconv.ParseUint(partyIdStr, 10, 32)
				if err != nil {
					return fmt.Errorf("invalid party ID: %w", err)
				}
				mainOp.Identifier = []byte(fmt.Sprintf("party_%d", partyID))
			} else {
				mainOp.Identifier = []byte("default")
			}
		}

		operations = append(operations, mainOp)

		// Build proof of payment
		proofOfPayment := [][]byte{
			payerPublicKey,
			bulletproofProver.SimpleSign(secretKey, rendezvous[:]),
		}

		// Build CodeExecute message
		codeExecute := &protobufs.CodeExecute{
			ProofOfPayment:    proofOfPayment,
			Domain:            domain[:],
			Rendezvous:        rendezvous[:],
			ExecuteOperations: operations,
		}

		request := &protobufs.MessageRequest{
			Request: &protobufs.MessageRequest_CodeExecute{
				CodeExecute: codeExecute,
			},
		}

		// Send message
		client, conn, err := getNodeClient()
		if err != nil {
			return fmt.Errorf("connect to node: %w", err)
		}
		defer conn.Close()

		bundle := &protobufs.MessageBundle{
			Requests:  []*protobufs.MessageRequest{request},
			Timestamp: time.Now().UnixMilli(),
		}

		payload, err := bundle.ToCanonicalBytes()
		if err != nil {
			return fmt.Errorf("serialize message: %w", err)
		}

		signer, err := keyMgr.GetSigningKey("q-peer-key")
		if err != nil {
			return fmt.Errorf("get signing key: %w", err)
		}

		sig, err := signer.SignWithDomain(
			payload,
			slices.Concat([]byte("NODE_AUTHENTICATION"), domain[:]),
		)
		if err != nil {
			return fmt.Errorf("sign message: %w", err)
		}

		_, err = client.Send(
			context.Background(),
			&protobufs.SendRequest{
				Domain:         domain[:],
				Request:        bundle,
				Authentication: sig,
			},
		)
		if err != nil {
			return fmt.Errorf("send code execute: %w", err)
		}

		fmt.Printf("Code execution submitted successfully\n")
		fmt.Printf("Rendezvous: %s\n", hex.EncodeToString(rendezvous[:]))

		return nil
	},
}

func init() {
	ComputeCmd.AddCommand(ExecuteCmd)
}
