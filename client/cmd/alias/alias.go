package alias

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var aliasStore *aliases.Store

// Root command for alias management
var AliasCmd = &cobra.Command{
	Use:           "alias",
	Short:         "Manage address aliases",
	Long:          `Commands for managing address aliases in Quilibrium.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load node configuration
		cfg, err := utils.LoadDefaultNodeConfig()
		if err != nil {
			return errors.Wrap(err, "load node configuration")
		}

		// Load or create alias store
		if cfg.Alias != nil && cfg.Alias.AliasFile != nil && cfg.Alias.AliasFile.Path != "" {
			aliasStore, err = aliases.Load(cfg.Alias.AliasFile.Path)
			if err != nil && cfg.Alias.AliasFile.CreateIfMissing {
				aliasStore, err = aliases.NewOnDisk(cfg.Alias.AliasFile.Path)
				if err != nil {
					return errors.Wrap(err, "create alias store")
				}
			} else if err != nil {
				return errors.Wrap(err, "load alias store")
			}
		} else {
			return errors.New("alias configuration not found in config file")
		}
		return nil
	},
}

// alias list
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all aliases",
	RunE: func(cmd *cobra.Command, args []string) error {
		aliases := aliasStore.List()
		if len(aliases) == 0 {
			fmt.Println("No aliases found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ALIAS\tADDRESS\tTYPE")

		for _, name := range aliases {
			addr, typ, ok := aliasStore.Get(name)
			if !ok {
				continue
			}
			addrHex := hex.EncodeToString(addr)
			if len(addrHex) > 64 {
				addrHex = addrHex[:64] + "…"
			}
			if typ == "" {
				typ = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", name, addrHex, typ)
		}
		return w.Flush()
	},
}

// alias add
var AddCmd = &cobra.Command{
	Use:   "add <alias> <address> [type]",
	Short: "Add or update an alias",
	Long:  `Add or update an alias for an address. The address should be provided as hex. Type is optional.`,
	Args:  cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		addressStr := strings.TrimPrefix(args[1], "0x")

		addr, err := hex.DecodeString(addressStr)
		if err != nil {
			return fmt.Errorf("invalid address hex: %w", err)
		}

		typeStr := ""
		if len(args) > 2 {
			typeStr = args[2]
		}

		if err := aliasStore.Put(name, addr, typeStr); err != nil {
			return fmt.Errorf("failed to add alias: %w", err)
		}

		fmt.Printf("Added alias %q for address %s\n", name, hex.EncodeToString(addr))
		if typeStr != "" {
			fmt.Printf("Type: %s\n", typeStr)
		}
		return nil
	},
}

// alias remove
var RemoveCmd = &cobra.Command{
	Use:     "remove <alias>",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove an alias",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		deleted, err := aliasStore.Delete(name)
		if err != nil {
			return fmt.Errorf("failed to remove alias: %w", err)
		}

		if deleted {
			fmt.Printf("Removed alias %q\n", name)
		} else {
			fmt.Printf("Alias %q not found\n", name)
		}
		return nil
	},
}

// alias get
var GetCmd = &cobra.Command{
	Use:   "get <alias>",
	Short: "Get address for an alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		addr, typ, ok := aliasStore.Get(name)
		if !ok {
			return fmt.Errorf("alias %q not found", name)
		}

		fmt.Printf("Alias: %s\n", name)
		fmt.Printf("Address: %s\n", hex.EncodeToString(addr))
		if typ != "" {
			fmt.Printf("Type: %s\n", typ)
		}
		return nil
	},
}

// alias resolve
var ResolveCmd = &cobra.Command{
	Use:   "resolve <alias_or_address>",
	Short: "Resolve an alias or address",
	Long:  `Resolve an alias to an address, or parse a hex address. This shows what address would be used.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]

		addr, typ, ok := aliasStore.Resolve(input)
		if !ok {
			return fmt.Errorf("could not resolve %q as alias or address", input)
		}

		fmt.Printf("Resolved to: %s\n", hex.EncodeToString(addr))
		if typ != "" {
			fmt.Printf("Type: %s\n", typ)
		}

		// Check if this address has an alias
		if name, _, ok := aliasStore.FindByAddress(addr); ok && name != input {
			fmt.Printf("This address has alias: %s\n", name)
		}

		return nil
	},
}

// alias find
var FindCmd = &cobra.Command{
	Use:   "find <address>",
	Short: "Find alias for an address",
	Long:  `Find if an address has an associated alias. Address should be provided as hex.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		addressStr := strings.TrimPrefix(args[0], "0x")

		addr, err := hex.DecodeString(addressStr)
		if err != nil {
			return fmt.Errorf("invalid address hex: %w", err)
		}

		name, typ, ok := aliasStore.FindByAddress(addr)
		if !ok {
			fmt.Printf("No alias found for address %s\n", hex.EncodeToString(addr))
			return nil
		}

		fmt.Printf("Alias: %s\n", name)
		fmt.Printf("Address: %s\n", hex.EncodeToString(addr))
		if typ != "" {
			fmt.Printf("Type: %s\n", typ)
		}
		return nil
	},
}

func init() {
	AliasCmd.AddCommand(ListCmd)
	AliasCmd.AddCommand(AddCmd)
	AliasCmd.AddCommand(RemoveCmd)
	AliasCmd.AddCommand(GetCmd)
	AliasCmd.AddCommand(ResolveCmd)
	AliasCmd.AddCommand(FindCmd)
}