package message

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	aliases "source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	pb "source.quilibrium.com/quilibrium/monorepo/protobufs"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

var (
	rpcAddr   string
	timeout   time.Duration
	asHex     bool
	outFormat string
	limit     int
	since     uint64

	aliasStore *aliases.Store
	conn       *grpc.ClientConn
	dispatch   pb.DispatchServiceClient
)

var MessageCmd = &cobra.Command{
	Use:           "message",
	Short:         "Messaging operations",
	Long:          `Commands for sending and receiving messages in Quilibrium.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := utils.LoadDefaultNodeConfig()
		if err != nil {
			return fmt.Errorf("load node configuration: %w", err)
		}

		aliasStore, _ = utils.LoadAliasStore(cfg)

		if conn != nil && dispatch != nil {
			return nil
		}

		// Determine the dispatch address
		addr := rpcAddr
		if addr == "" {
			// Default to the node's streaming address
			streamAddr := cfg.P2P.StreamListenMultiaddr
			if streamAddr == "" {
				streamAddr = "/ip4/0.0.0.0/tcp/8340"
			}
			ma, err := multiaddr.NewMultiaddr(streamAddr)
			if err != nil {
				return fmt.Errorf("parse stream listen multiaddr: %w", err)
			}
			_, addr, err = mn.DialArgs(ma)
			if err != nil {
				return fmt.Errorf("resolve stream listen addr: %w", err)
			}
			// Replace 0.0.0.0 with localhost for dialing
			addr = strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
		}

		// Obtain peer key for TLS authentication
		key, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
		if err != nil {
			return errors.New("peer privkey not set – do you have a valid config?")
		}

		// Derive peer ID for self-authentication
		privKey, err := libp2pcrypto.UnmarshalEd448PrivateKey(key)
		if err != nil {
			return fmt.Errorf("unmarshal peer private key: %w", err)
		}
		selfPeerID, err := peer.IDFromPublicKey(privKey.GetPublic())
		if err != nil {
			return fmt.Errorf("derive peer id: %w", err)
		}

		// Create PeerAuthenticator for TLS credentials
		logger, _ := zap.NewProduction()
		peerAuth := p2p.NewPeerAuthenticator(
			logger,
			cfg.P2P,
			nil, // peerInfoManager not needed for TLS
			nil, // proverRegistry not needed for TLS
			nil, // signerRegistry not needed for TLS
			nil, // filter not needed for TLS
			nil, // whitelistedPeers not needed for TLS
			nil, // servicePolicies not needed for TLS
			nil, // methodPolicies not needed for TLS
		)

		credentials, err := peerAuth.CreateClientTLSCredentials([]byte(selfPeerID))
		if err != nil {
			return fmt.Errorf("create TLS credentials: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, err := grpc.DialContext(
			ctx,
			addr,
			grpc.WithTransportCredentials(credentials),
			grpc.WithBlock(),
		)
		if err != nil {
			return fmt.Errorf("connect to %s: %w", addr, err)
		}
		conn = c
		dispatch = pb.NewDispatchServiceClient(conn)
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if conn != nil {
			return conn.Close()
		}
		return nil
	},
}

var RetrieveCmd = &cobra.Command{
	Use:   "retrieve [InboxKeyName]",
	Short: "Retrieve messages",
	Long: `Retrieves messages for a given inbox (higher privacy).
Use --all to retrieve across all inboxes (lower privacy, increases correlation risk).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inboxName := ""
		if len(args) > 0 {
			inboxName = args[0]
		}
		all, _ := cmd.Flags().GetBool("all")
		if inboxName == "" && !all {
			return errors.New("either specify <InboxKeyName> or use --all (explicitly acknowledging privacy tradeoffs)")
		}

		fmtMsg := func(b []byte) string {
			switch outFormat {
			case "hex":
				return hex.EncodeToString(b)
			case "json":
				return fmt.Sprintf(`{"data":"%s"}`, hex.EncodeToString(b))
			default:
				return string(b)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Resolve inbox address
		var addressBytes []byte
		if inboxName != "" {
			if aliasStore != nil {
				if addr, _, ok := aliasStore.Resolve(inboxName); ok {
					addressBytes = addr
				}
			}
			if addressBytes == nil {
				decoded, err := hex.DecodeString(strings.TrimPrefix(inboxName, "0x"))
				if err != nil {
					return fmt.Errorf("inbox must be an alias or hex address: %w", err)
				}
				addressBytes = decoded
			}
		}

		// Compute bloom filter from address
		var filter []byte
		if addressBytes != nil && len(addressBytes) >= 32 {
			filter = up2p.GetBloomFilterIndices(addressBytes[:32], 256, 3)
		}

		req := &pb.InboxMessageRequest{
			Filter:        filter,
			Address:       addressBytes,
			FromTimestamp: since,
		}

		resp, err := dispatch.GetInboxMessages(ctx, req)
		if err != nil {
			return fmt.Errorf("GetInboxMessages: %w", err)
		}

		if len(resp.Messages) == 0 {
			if all {
				fmt.Println("No messages across all inboxes.")
			} else {
				fmt.Printf("No messages for inbox %q.\n", inboxName)
			}
			return nil
		}

		for _, m := range resp.Messages {
			fmt.Printf("- ts=%d addr=%s\n",
				m.Timestamp,
				hex.EncodeToString(m.Address),
			)
			fmt.Println(fmtMsg(m.Message))
			fmt.Println()
		}
		return nil
	},
}

var SendCmd = &cobra.Command{
	Use:   "send <InboxKeyName> <RecipientInboxKeyAddress|hex> <Message|->",
	Short: "Send a message",
	Long: `Sends a message to a recipient inbox address.
<Message> can be a literal string or "-" to read from stdin.
Use --hex if the message content is hex-encoded bytes.`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = args[0] // inboxName - for future sender key resolution
		recipientArg := args[1]
		payloadArg := args[2]

		// Resolve recipient address
		var recipientAddr []byte
		if aliasStore != nil {
			if addr, _, ok := aliasStore.Resolve(recipientArg); ok {
				recipientAddr = addr
				fmt.Printf("Resolved alias %q to address %s\n", recipientArg, hex.EncodeToString(recipientAddr))
			}
		}

		if recipientAddr == nil {
			recipient := strings.TrimPrefix(recipientArg, "0x")
			var err error
			recipientAddr, err = hex.DecodeString(recipient)
			if err != nil {
				return fmt.Errorf("recipient must be an alias or hex address: %w", err)
			}
		}

		// Resolve message bytes
		var msg []byte
		if payloadArg == "-" {
			b, err := io.ReadAll(bufio.NewReader(os.Stdin))
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
			msg = bytesTrimSingleNewline(b)
		} else {
			if asHex {
				h := strings.TrimPrefix(payloadArg, "0x")
				b, err := hex.DecodeString(h)
				if err != nil {
					return fmt.Errorf("decode --hex message: %w", err)
				}
				msg = b
			} else {
				msg = []byte(payloadArg)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		put := &pb.InboxMessagePut{
			Message: &pb.InboxMessage{
				Address:   recipientAddr,
				Timestamp: uint64(time.Now().UnixMilli()),
				Message:   msg,
			},
		}

		if _, err := dispatch.PutInboxMessage(ctx, put); err != nil {
			return fmt.Errorf("PutInboxMessage: %w", err)
		}

		fmt.Printf("Sent %d bytes to %s\n", len(msg), hex.EncodeToString(recipientAddr))
		return nil
	},
}

var ShowCmd = &cobra.Command{
	Use:   "show <InboxKeyName>",
	Short: "Display stored messages",
	Long:  `Displays stored messages for a given inbox (local index or via server query).`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RetrieveCmd.RunE(cmd, args)
	},
}

var DeleteMessageCmd = &cobra.Command{
	Use:   "delete <InboxKeyName> <MessageIdHex>",
	Short: "Delete a message",
	Long:  `Messages auto-expire after 7 days. Manual deletion is not currently supported.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Manual deletion is not currently supported by the DispatchService.")
		fmt.Println("Messages auto-expire after 7 days.")
		return nil
	},
}

func init() {
	MessageCmd.PersistentFlags().StringVar(&rpcAddr, "rpc", "", "DispatchService address (host:port)")
	MessageCmd.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Second, "RPC timeout")

	RetrieveCmd.Flags().Bool("all", false, "Retrieve across all inboxes (LOWER PRIVACY)")
	RetrieveCmd.Flags().IntVar(&limit, "limit", 100, "Max messages to retrieve")
	RetrieveCmd.Flags().Uint64Var(&since, "since", 0, "Lower bound filter (schema-dependent: frame or timestamp)")
	RetrieveCmd.Flags().StringVar(&outFormat, "format", "text", "Output format: text|hex|json")

	SendCmd.Flags().BoolVar(&asHex, "hex", false, "Interpret message input as hex")

	MessageCmd.AddCommand(RetrieveCmd)
	MessageCmd.AddCommand(SendCmd)
	MessageCmd.AddCommand(ShowCmd)
	MessageCmd.AddCommand(DeleteMessageCmd)
}

func bytesTrimSingleNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}
