package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

		// Check if the current executable is in the expected location
		expectedPrefix := utils.ClientDataPath

		// Check if the current executable is in the expected location
		if !strings.HasPrefix(execPath, expectedPrefix) {
			fmt.Printf("Current executable is not in the expected location: %s\n", execPath)
			fmt.Printf("Expected location should start with: %s\n", expectedPrefix)

			// Ask user if they want to move it
			fmt.Print("Would you like to move the executable to the standard location? (y/n): ")
			var response string
			fmt.Scanln(&response)

			if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
				if err := moveExecutableToStandardLocation(execPath); err != nil {
					return fmt.Errorf("failed to move executable: %w", err)
				}
				// Update execPath to the new location
				execPath, err = os.Executable()
				if err != nil {
					return fmt.Errorf("failed to get new executable path: %w", err)
				}
			} else {
				fmt.Println("Continuing with current location...")
			}
		}

		// Create the symlink (handles existing symlinks)
		if err := utils.CreateSymlink(execPath, symlinkPath); err != nil {
			return err
		}

		fmt.Printf("Symlink created at %s\n", symlinkPath)
		return nil
	},
}

func moveExecutableToStandardLocation(execPath string) error {
	// Get the directory of the current executable
	version, err := GetVersionInfo(false)
	if err != nil {
		return fmt.Errorf("failed to get version info: %w", err)
	}
	destDir := filepath.Join(utils.ClientDataPath, "bin", version.Version)

	// Create the standard location directory if it doesn't exist
	currentUser, err := utils.GetCurrentSudoUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	if err := utils.ValidateAndCreateDir(destDir, currentUser); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Move the executable to the standard location
	if err := os.Rename(execPath, filepath.Join(destDir, StandardizedQClientFileName)); err != nil {
		return fmt.Errorf("failed to move executable: %w", err)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(linkCmd)
}
