package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var symlinkPath = "/usr/local/bin/qclient"

var linkCmd = &cobra.Command{
	Use:   "link",
	Short: "Create a symlink to qclient in PATH",
	Long: `Create a symlink to the qclient binary in the directory /usr/local/bin/.

Example: qclient link`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the path to the current executable
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		IsSudo := utils.IsSudo()
		if IsSudo {
			fmt.Println("Running as sudo, creating symlink at /usr/local/bin/qclient")
		} else {
			fmt.Println("Cannot create symlink at /usr/local/bin/qclient, please run this command with sudo")
			os.Exit(1)
		}

		// Create the symlink (handles existing symlinks)
		if err := utils.CreateSymlink(execPath, symlinkPath); err != nil {
			return err
		}

		fmt.Printf("Symlink created at %s\n", symlinkPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(linkCmd)
}
