package node

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// installCmd represents the command to install the Quilibrium node
var InstallCmd = &cobra.Command{
	Use:   "install [version]",
	Short: "Install Quilibrium node",
	Long: `Install Quilibrium node binary and create a service to run it.

	## Service Management

	You can start, stop, and restart the service with:

		qclient node service start
		qclient node service stop
		qclient node service restart
		qclient node service status
		qclient node service enable
		qclient node service disable

	### Mac OS Notes

	On Mac OS, the service is managed by launchd (installed by default)

	### Linux Notes

	On Linux, the service is managed by systemd (will be installed by this command).

	## Config Management

	A config directory will be created in the user's home directory at .quilibrium/configs/.

	To create a default config, run the following command:
	
		qclient node config create-default [name-for-config]

	or, you can import existing configs one at a timefrom a directory:

		qclient node config import [name-for-config] /path/to/src/config/dir/

	You can then select the config to use when running the node with:

		qclient node set-default [name-for-config]

	## Binary Management
	Binaries and signatures are installed to /var/quilibrium/bin/node/[version]/

	You can update the node binary with:

		qclient node update [version]

	### Auto-update

	You can enable auto-update with:

		qclient node auto-update enable

	You can disable auto-update with:	

		qclient node auto-update disable

	You can check the auto-update status with:

		qclient node auto-update status

	## Log Management
	Logging uses system logging with logrotate installed by default.

	Logs are installed to /var/log/quilibrium

	The logrotate config is installed to /etc/logrotate.d/quilibrium

	You can view the logs with:

		qclient node logs [version]

When installing with this command, if no version is specified, the latest version will be installed.

Sudo is required to install the node to install the node binary, logging,systemd (on Linux), and create the config directory.

Examples:

  	# Install the latest version
  	qclient node install

  	# Install a specific version
  	qclient node install 2.1.0
`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get system information and validate
		osType, arch, err := utils.GetSystemInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		if !utils.IsSudo() {
			fmt.Println("This command must be run with sudo: sudo qclient node install")
			fmt.Println("Sudo is required to install the node binary, logging, systemd (on Linux) service, and create the config directory.")
			os.Exit(1)
		}

		// Determine version to install
		version := determineVersion(args)

		// Download and install the node
		if version == "latest" {
			latestVersion, err := utils.GetLatestVersion(utils.ReleaseTypeNode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting latest version: %v\n", err)
				return
			}

			version = latestVersion
			fmt.Fprintf(os.Stdout, "Found latest version: %s\n", version)
		}

		// do a pre-flight check to ensure the release file exists
		fileName := fmt.Sprintf("%s-%s-%s-%s", utils.ReleaseTypeNode, version, osType, arch)
		url := fmt.Sprintf("%s/%s", utils.BaseReleaseURL, fileName)

		if !utils.DoesRemoteFileExist(url) {
			fmt.Printf("The release file %s does not exist on the release server\n", fileName)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stdout, "Installing Quilibrium node for %s-%s, version: %s\n", osType, arch, version)

		// Install the node
		InstallNode(version)
	},
}

// installNode installs the Quilibrium node
func InstallNode(version string) {
	// Create installation directory
	if err := utils.ValidateAndCreateDir(utils.NodeDataPath, NodeUser); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating installation directory: %v\n", err)
		return
	}

	if utils.IsExistingNodeVersion(version) {
		fmt.Fprintf(os.Stderr, "Error: Node version %s already exists\n", version)
		os.Exit(1)
	}

	if err := InstallByVersion(version); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing specific version: %v\n", err)
		os.Exit(1)
	}

	createService()

	finishInstallation(version)
}

// installByVersion installs a specific version of the Quilibrium node
func InstallByVersion(version string) error {

	versionDir := filepath.Join(utils.NodeDataPath, version)
	if err := utils.ValidateAndCreateDir(versionDir, NodeUser); err != nil {
		return fmt.Errorf("failed to create version directory: %w", err)
	}

	// Download the release
	if err := utils.DownloadRelease(utils.ReleaseTypeNode, version); err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}

	// Download signature files
	if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeNode, version); err != nil {
		return fmt.Errorf("failed to download signature files: %w", err)
	}

	return nil
}
