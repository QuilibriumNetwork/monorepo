package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigAliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Manage address aliases",
	Long: `Manage the list of address aliases in the configuration.

	For more information on how to use aliases, see the https://docs.quilibrium.com/docs/run-node/qclient/commands/alias.
	
Examples:
  # Add a new address to the configuration
  qclient config alias add my-friend 0x1234567890abcdef
  
  # List all saved addresses
  qclient config alias list
  
  # Update an existing address
  qclient config alias update my-friend 0xabcdef1234567890
  
  # Remove an address from the configuration
  qclient config alias remove my-friend`,
}

var addAddressCmd = &cobra.Command{
	Use:   "add [name] [address]",
	Short: "Add a new address alias",
	Long:  `Add a new address alias to the configuration with a given name.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		address := args[1]

		if ClientConfig.AddressList == nil {
			ClientConfig.AddressList = make(map[string]string)
		}

		if _, exists := ClientConfig.AddressList[name]; exists {
			fmt.Printf("Alias for %s already exists. Use 'update' to modify it.\n", name)
			os.Exit(1)
		}

		ClientConfig.AddressList[name] = address
		err := utils.SaveClientConfig(ClientConfig)
		if err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added alias %s for %s\n", address, name)
	},
}

var listAddressesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all aliases",
	Long:  `List all aliases in the configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(ClientConfig.AddressList) == 0 {
			fmt.Println("No aliases found in configuration.")
			return
		}
		fmt.Println("Address Aliases:")
		for name, address := range ClientConfig.AddressList {
			fmt.Printf("  %s -> %s\n", name, address)
		}
	},
}

var updateAddressCmd = &cobra.Command{
	Use:   "update [name] [address]",
	Short: "Update an existing alias",
	Long:  `Update an existing alias in the configuration for a given name.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		address := args[1]
		if _, exists := ClientConfig.AddressList[name]; !exists {
			fmt.Printf("Alias for %s does not exist.\n", name)
			os.Exit(1)
		}
		ClientConfig.AddressList[name] = address
		err := utils.SaveClientConfig(ClientConfig)
		if err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Updated address for %s to %s\n", name, address)
	},
}

var deleteAddressCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete an alias",
	Long:  `Delete an alias from the configuration by name.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]

		if _, exists := ClientConfig.AddressList[name]; !exists {
			fmt.Printf("Alias for %s does not exist.\n", name)
			os.Exit(1)
		}

		delete(ClientConfig.AddressList, name)
		err := utils.SaveClientConfig(ClientConfig)
		if err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Deleted alias for %s\n", name)
	},
}

func init() {
	ClientConfigAliasCmd.AddCommand(addAddressCmd)
	ClientConfigAliasCmd.AddCommand(listAddressesCmd)
	ClientConfigAliasCmd.AddCommand(updateAddressCmd)
	ClientConfigAliasCmd.AddCommand(deleteAddressCmd)
}
