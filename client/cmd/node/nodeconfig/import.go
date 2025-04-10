package nodeconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var importCmd = &cobra.Command{
	Use:   "import [name] [source_directory]",
	Short: "Import config.yml and keys.yml from a source directory",
	Long: `Import config.yml and keys.yml from a source directory to the QuilibriumRoot config folder.
	
Example:
  qclient node config import mynode /path/to/source
	
This will copy config.yml and keys.yml from /path/to/source to /home/quilibrium/configs/mynode/`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		sourceDir := args[1]

		// Check if source directory exists
		if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
			fmt.Printf("Source directory does not exist: %s\n", sourceDir)
			os.Exit(1)
		}

		if !HasConfigFiles(sourceDir) {
			fmt.Printf("Source directory does not contain both config.yml and keys.yml files: %s\n", sourceDir)
			os.Exit(1)
		}

		// Create target directory in the standard location
		targetDir := filepath.Join(ConfigDirs, name)
		if err := utils.ValidateAndCreateDir(targetDir, NodeUser); err != nil {
			fmt.Printf("Failed to create target directory: %s\n", err)
			os.Exit(1)
		}

		// Define source file paths
		sourceConfigPath := filepath.Join(sourceDir, "config.yml")
		sourceKeysPath := filepath.Join(sourceDir, "keys.yml")

		// Copy config.yml
		targetConfigPath := filepath.Join(targetDir, "config.yml")
		if err := utils.CopyFile(sourceConfigPath, targetConfigPath); err != nil {
			fmt.Printf("Failed to copy config.yml: %s\n", err)
			os.Exit(1)
		}

		// Copy keys.yml
		targetKeysPath := filepath.Join(targetDir, "keys.yml")
		if err := utils.CopyFile(sourceKeysPath, targetKeysPath); err != nil {
			fmt.Printf("Failed to copy keys.yml: %s\n", err)
			os.Exit(1)
		}

		if SetDefault {
			// Create the symlink
			if err := utils.CreateSymlink(targetDir, NodeConfigToRun); err != nil {
				fmt.Printf("Failed to create symlink: %s\n", err)
				os.Exit(1)
			}

			fmt.Printf("Successfully imported config files to %s and symlinked to default\n", name)
		} else {
			fmt.Printf("Successfully imported config files to %s\n", targetDir)
		}
	},
}

func init() {

}
