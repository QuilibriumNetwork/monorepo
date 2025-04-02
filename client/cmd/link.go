package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var symlinkPath string

var linkCmd = &cobra.Command{
	Use:   "link",
	Short: "Create a symlink to qclient in PATH",
	Long: fmt.Sprintf(`Create a symlink to the qclient binary in a suitable directory in your PATH.
This allows you to run qclient from anywhere without specifying the full path.

By default it will create the symlink in the current directory /usr/local/bin.
You can also specify a custom directory using the --path flag.

Example: qclient link --path /usr/local/bin`),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the path to the current executable
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		// Determine the target directory and path for the symlink
		targetDir, targetPath, err := determineSymlinkLocation()
		if err != nil {
			return err
		}

		// If operation was cancelled by the user
		if targetDir == "" && targetPath == "" {
			return nil
		}

		// Create the symlink (handles existing symlinks)
		if err := utils.CreateSymlink(execPath, targetPath); err != nil {
			return err
		}

		fmt.Printf("Symlink created at %s\n", targetPath)
		return nil
	},
}

// determineSymlinkLocation finds the appropriate location for the symlink
// Returns the target directory, the full path for the symlink, and any error
func determineSymlinkLocation() (string, string, error) {
	// If user provided a custom path
	if symlinkPath != "" {
		return validateUserProvidedPath(symlinkPath)
	}

	// Otherwise, find a suitable directory in PATH
	return utils.DefaultSymlinkDir, utils.DefaultQClientSymlinkPath, nil
}

// isDirectoryInPath checks if a directory is in the PATH environment variable
func isDirectoryInPath(dir string) bool {
	pathEnv := os.Getenv("PATH")
	pathDirs := strings.Split(pathEnv, string(os.PathListSeparator))

	// Normalize paths for comparison
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	for _, pathDir := range pathDirs {
		absPathDir, err := filepath.Abs(pathDir)
		if err != nil {
			continue
		}

		if absDir == absPathDir {
			return true
		}
	}

	return false
}

// validateUserProvidedPath checks if the provided path is a valid directory
func validateUserProvidedPath(path string) (string, string, error) {
	// Check if the provided path is a directory
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("directory does not exist: %s", path)
		}
		return "", "", fmt.Errorf("error checking directory: %w", err)
	}

	if !info.IsDir() {
		return "", "", fmt.Errorf("the specified path is not a directory: %s", path)
	}

	// Check if the directory is in PATH
	if !isDirectoryInPath(path) {
		// Ask user for confirmation to proceed with a directory not in PATH
		fmt.Printf("Warning: The directory '%s' is not in your PATH environment variable.\n", path)
		fmt.Println("The symlink will be created, but you may not be able to run 'qclient' from anywhere.")
		fmt.Print("Do you want to continue? [y/N]: ")

		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" {
			fmt.Println("Operation cancelled.")
			return "", "", nil
		}
	}

	// Use the provided directory
	targetDir := path
	targetPath := filepath.Join(targetDir, "qclient")

	return targetDir, targetPath, nil
}

func init() {
	rootCmd.AddCommand(linkCmd)
	linkCmd.Flags().StringVar(&symlinkPath, "path", "", "Specify a custom directory for the symlink")
}
