package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var (
	osType = runtime.GOOS
	arch   = runtime.GOARCH
)

// updateCmd represents the command to update the Quilibrium client
var updateCmd = &cobra.Command{
	Use:   "update [version]",
	Short: "Update Quilibrium client",
	Long: `Update Quilibrium client to a specified version or the latest version.
If no version is specified, the latest version will be installed.

If the current version is already the latest version, the command will exit with a message.

Examples:
  # Update to the latest version
  qclient update

  # Update to a specific version
  qclient update 2.1.0`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get system information and validate
		localOsType, localArch, err := utils.GetSystemInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		osType = localOsType
		arch = localArch

		// Determine version to install
		version := determineVersion(args)

		fmt.Fprintf(os.Stdout, "Updating Quilibrium client for %s-%s, version: %s\n", osType, arch, version)

		// Update the client
		updateClient(version)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

// determineVersion gets the version to install from args or defaults to "latest"
func determineVersion(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "latest"
}

// updateClient handles the client update process
func updateClient(version string) {

	currentVersion := config.GetVersionString()

	// If version is "latest", get the latest version
	if version == "latest" {
		latestVersion, err := utils.GetLatestVersion(utils.ReleaseTypeQClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting latest version: %v\n", err)
			return
		}
		version = latestVersion
		fmt.Fprintf(os.Stdout, "Latest version: %s\n", version)
	}

	if version == currentVersion {
		fmt.Fprintf(os.Stdout, "Already on version %s\n", currentVersion)
		return
	}

	// Check if we need sudo privileges
	if err := utils.CheckAndRequestSudo(fmt.Sprintf("Updating client at %s requires root privileges", utils.ClientInstallPath)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Create version-specific installation directory
	versionDir := filepath.Join(utils.ClientInstallPath, version)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating installation directory: %v\n", err)
		return
	}

	// Create data directory
	versionDataDir := filepath.Join(utils.ClientDataPath, version)
	if err := os.MkdirAll(versionDataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		return
	}

	// Construct the expected filename for the specified version
	// Remove 'v' prefix if present for filename construction
	versionWithoutV := strings.TrimPrefix(version, "v")

	// Download the release directly
	err := utils.DownloadRelease(utils.ReleaseTypeQClient, versionWithoutV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading version %s: %v\n", version, err)
		fmt.Fprintf(os.Stderr, "The specified version %s does not exist for %s-%s\n", version, osType, arch)
		// Clean up the created directories since installation failed
		os.RemoveAll(versionDir)
		os.RemoveAll(versionDataDir)
		return
	}

	// Download signature files
	if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeQClient, versionWithoutV); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to download signature files: %v\n", err)
		fmt.Fprintf(os.Stdout, "Continuing with installation...\n")
	}

	// Successfully downloaded the specific version
	finishInstallation(version)
}

// finishInstallation completes the update process
func finishInstallation(version string) {

	// Construct executable path
	execPath := filepath.Join(utils.ClientDataPath, version, "qclient-"+version+"-"+osType+"-"+arch)

	// Make the binary executable
	if err := os.Chmod(execPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error making binary executable: %v\n", err)
		return
	}

	// Create symlink to the new version
	symlinkPath := utils.DefaultQClientSymlinkPath

	// Check if we need sudo privileges for creating symlink in system directory
	if strings.HasPrefix(symlinkPath, "/usr/") || strings.HasPrefix(symlinkPath, "/bin/") || strings.HasPrefix(symlinkPath, "/sbin/") {
		if err := utils.CheckAndRequestSudo(fmt.Sprintf("Creating symlink at %s requires root privileges", symlinkPath)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to get sudo privileges: %v\n", err)
			return
		}
	}

	// Create symlink
	if err := utils.CreateSymlink(execPath, symlinkPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating symlink: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Successfully updated qclient to version %s\n", version)
	fmt.Fprintf(os.Stdout, "Executable: %s\n", execPath)
	fmt.Fprintf(os.Stdout, "Symlink: %s\n", symlinkPath)
}
