package node

import (
	"fmt"
	"os"

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

const (
	defaultListenGRPCMultiaddr = "/ip4/127.0.0.1/tcp/8337"
	// Matches the REST listener default in node service templates (gRPC 8337, REST 8338).
	defaultListenRestMultiaddr = "/ip4/127.0.0.1/tcp/8338"
)

var (
	grpcEnableAddr string
	restEnableAddr string
)

// NodeGrpcCmd groups gRPC listen settings for the node.
var NodeGrpcCmd = &cobra.Command{
	Use:   "grpc",
	Short: "Configure node gRPC listen multiaddr",
	Long: `Configure the node's gRPC listen address (listenGrpcMultiaddr in config.yml).

Subcommands set or clear the value; restart the node service for changes to take effect.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var nodeGrpcEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable gRPC by setting listenGrpcMultiaddr",
	Long: fmt.Sprintf(`Set listenGrpcMultiaddr to enable the gRPC server.

The default multiaddr is %s. Override with --addr.

Restart the node service after changing this setting.`, defaultListenGRPCMultiaddr),
	Run: func(cmd *cobra.Command, args []string) {
		if err := enableListenGRPC(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

var nodeGrpcDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable gRPC by clearing listenGrpcMultiaddr",
	Long: `Set listenGrpcMultiaddr to empty (disabled).

Restart the node service after changing this setting.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := disableListenGRPC(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

// NodeRestCmd groups REST (HTTP gateway) listen settings for the node.
var NodeRestCmd = &cobra.Command{
	Use:   "rest",
	Short: "Configure node REST listen multiaddr",
	Long: `Configure the node's REST gateway listen address (listenRESTMultiaddr in config.yml).

Subcommands set or clear the value; restart the node service for changes to take effect.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var nodeRestEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable REST by setting listenRESTMultiaddr",
	Long: fmt.Sprintf(`Set listenRESTMultiaddr to enable the HTTP/JSON gateway.

The default multiaddr is %s. Override with --addr.

Restart the node service after changing this setting.`, defaultListenRestMultiaddr),
	Run: func(cmd *cobra.Command, args []string) {
		if err := enableListenRest(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

var nodeRestDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable REST by clearing listenRESTMultiaddr",
	Long: `Set listenRESTMultiaddr to empty (disabled).

Restart the node service after changing this setting.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := disableListenRest(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

func init() {
	nodeGrpcEnableCmd.Flags().StringVar(&grpcEnableAddr, "addr", "", "gRPC listen multiaddr (default "+defaultListenGRPCMultiaddr+")")
	NodeGrpcCmd.AddCommand(nodeGrpcEnableCmd)
	NodeGrpcCmd.AddCommand(nodeGrpcDisableCmd)

	nodeRestEnableCmd.Flags().StringVar(&restEnableAddr, "addr", "", "REST listen multiaddr (default "+defaultListenRestMultiaddr+")")
	NodeRestCmd.AddCommand(nodeRestEnableCmd)
	NodeRestCmd.AddCommand(nodeRestDisableCmd)
}

func ensureNodeConfigLoaded() error {
	if NodeConfig == nil || NodeConfigDir == "" {
		return fmt.Errorf("no active node config loaded. Run `qclient node config create` first, or pass --config <name>")
	}
	return nil
}

func validateMultiaddr(label, s string) error {
	if _, err := multiaddr.NewMultiaddr(s); err != nil {
		return fmt.Errorf("invalid %s multiaddr %q: %w", label, s, err)
	}
	return nil
}

func enableListenGRPC() error {
	if err := ensureNodeConfigLoaded(); err != nil {
		return err
	}
	addr := grpcEnableAddr
	if addr == "" {
		addr = defaultListenGRPCMultiaddr
	}
	if err := validateMultiaddr("gRPC", addr); err != nil {
		return err
	}
	NodeConfig.ListenGRPCMultiaddr = addr
	if err := config.SaveConfig(NodeConfigDir, NodeConfig); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("Set listenGrpcMultiaddr to %s in %s/config.yml\n", addr, NodeConfigDir)
	return nil
}

func disableListenGRPC() error {
	if err := ensureNodeConfigLoaded(); err != nil {
		return err
	}
	NodeConfig.ListenGRPCMultiaddr = ""
	if err := config.SaveConfig(NodeConfigDir, NodeConfig); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("Cleared listenGrpcMultiaddr in %s/config.yml\n", NodeConfigDir)
	return nil
}

func enableListenRest() error {
	if err := ensureNodeConfigLoaded(); err != nil {
		return err
	}
	addr := restEnableAddr
	if addr == "" {
		addr = defaultListenRestMultiaddr
	}
	if err := validateMultiaddr("REST", addr); err != nil {
		return err
	}
	NodeConfig.ListenRestMultiaddr = addr
	if err := config.SaveConfig(NodeConfigDir, NodeConfig); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("Set listenRESTMultiaddr to %s in %s/config.yml\n", addr, NodeConfigDir)
	return nil
}

func disableListenRest() error {
	if err := ensureNodeConfigLoaded(); err != nil {
		return err
	}
	NodeConfig.ListenRestMultiaddr = ""
	if err := config.SaveConfig(NodeConfigDir, NodeConfig); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("Cleared listenRESTMultiaddr in %s/config.yml\n", NodeConfigDir)
	return nil
}
