package node

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// Install-time flags that let the user override the persisted install
// directories. Empty string means "unchanged" (leave the existing config
// value, or its default, alone).
var (
	installDirFlag  string
	logDirFlag      string
	symlinkDirFlag  string
	configsDirFlag  string
)

// installCmd represents the command to install the Quilibrium node
var NodeInstallCmd = &cobra.Command{
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

	## Install Directories

	The following paths can be overridden at install time and are persisted
	to the qclient config, so later commands (service, log, clean, etc.)
	read the same values automatically:

		--install-dir   Root install directory (defaults to /var/quilibrium).
		                Binaries go to <install-dir>/bin/node/<version>/ and
		                the systemd EnvironmentFile lives at
		                <install-dir>/quilibrium.env.
		--log-dir       Log directory (defaults to /var/log/quilibrium).
		--symlink-dir   Directory holding the quilibrium-node symlink
		                (defaults to /usr/local/bin). Make sure this is on
		                your $PATH if you change it.
		--configs-dir   Directory holding named node configs (defaults to
		                ~/.quilibrium/configs).

	Passing a flag updates the saved config. If the node is already
	installed and the new value differs from the current one, the new
	value is saved but takes effect only on the next install/update.

	## Binary Management
	Binaries and signatures are installed to <install-dir>/bin/node/[version]/

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

  	# Install into a custom directory tree
  	qclient node install --install-dir /opt/quilibrium --log-dir /var/log/quil
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

		// Apply any --install-dir / --log-dir / --symlink-dir / --configs-dir
		// overrides to the persisted client config before we start laying
		// files down, so every subsequent path lookup reads the new value.
		if err := applyInstallDirFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
	if err := utils.ValidateAndCreateDir(utils.GetNodeBinaryDir(), NodeUser); err != nil {
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

	versionDir := filepath.Join(utils.GetNodeBinaryDir(), version)
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

// applyInstallDirFlags persists any --install-dir/--log-dir/--symlink-dir
// /--configs-dir overrides to the client config. It validates that each
// supplied path is absolute and warns (but does not block) when an
// existing installation would need to be rebuilt for the change to take
// full effect.
func applyInstallDirFlags() error {
	cfg, err := utils.LoadClientConfig()
	if err != nil {
		return fmt.Errorf("loading client config: %w", err)
	}

	nodeInstalled := utils.FileExists(utils.GetNodeSymlinkPath())

	updates := []struct {
		name      string
		flagValue string
		current   *string
		// prevResolvedPath describes the currently effective path we print
		// in the "already installed" warning, to help the user understand
		// what would be rebuilt.
		prevResolved string
	}{
		{"install-dir", installDirFlag, &cfg.NodeInstallDir, utils.GetNodeInstallDir()},
		{"log-dir", logDirFlag, &cfg.NodeLogDir, utils.GetNodeLogDir()},
		{"symlink-dir", symlinkDirFlag, &cfg.NodeSymlinkDir, utils.GetNodeSymlinkDir()},
		{"configs-dir", configsDirFlag, &cfg.NodeConfigsDir, utils.GetNodeConfigsDir()},
	}

	changed := false
	for _, u := range updates {
		if u.flagValue == "" {
			continue
		}
		if !filepath.IsAbs(u.flagValue) {
			return fmt.Errorf(
				"--%s must be an absolute path, got %q", u.name, u.flagValue,
			)
		}
		if u.flagValue == *u.current {
			continue
		}

		if nodeInstalled && u.flagValue != u.prevResolved {
			fmt.Fprintf(os.Stderr,
				"Warning: --%s changes %s -> %s, but an existing node "+
					"installation was detected. The new value has been "+
					"saved to the qclient config and will take effect on "+
					"the next install/update; existing files at the old "+
					"path have not been moved.\n",
				u.name, u.prevResolved, u.flagValue,
			)
		}

		*u.current = u.flagValue
		changed = true
	}

	if !changed {
		return nil
	}

	if err := utils.SaveClientConfig(cfg); err != nil {
		return fmt.Errorf("saving client config: %w", err)
	}
	return nil
}

func init() {
	NodeInstallCmd.Flags().StringVar(
		&installDirFlag, "install-dir", "",
		"Root install directory for node binaries and the env file "+
			"(defaults to /var/quilibrium). Persisted to qclient config.",
	)
	NodeInstallCmd.Flags().StringVar(
		&logDirFlag, "log-dir", "",
		"Directory for node logs (defaults to /var/log/quilibrium). "+
			"Persisted to qclient config.",
	)
	NodeInstallCmd.Flags().StringVar(
		&symlinkDirFlag, "symlink-dir", "",
		"Directory for the quilibrium-node symlink (defaults to "+
			"/usr/local/bin). Persisted to qclient config.",
	)
	NodeInstallCmd.Flags().StringVar(
		&configsDirFlag, "configs-dir", "",
		"Directory holding named node configs (defaults to "+
			"~/.quilibrium/configs). Persisted to qclient config.",
	)
}
