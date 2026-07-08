package node

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// Install-time flags that let the user override the persisted install
// directories. Empty string means "unchanged" (leave the existing config
// value, or its default, alone).
var (
	installDirFlag   string
	stateDirFlag     string
	symlinkDirFlag   string
	configsDirFlag   string
	serviceNameFlag  string
	interactiveFlag  bool
)

// ExitUnlessSudoForInstall exits immediately if the process is not running
// with elevated privileges. NodeCmd.PersistentPreRun calls this for install
// before any other node setup (config load, default config creation, etc.).
func ExitUnlessSudoForInstall() {
	if utils.IsSudo() {
		return
	}
	osLabel, details := sudoInstallMessageForGOOS(runtime.GOOS)
	fmt.Fprintf(os.Stderr, "This command must be run with sudo on %s before any install steps.\n\n", osLabel)
	fmt.Fprintln(os.Stderr, "  sudo qclient node install")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, details)
	os.Exit(1)
}

func sudoInstallMessageForGOOS(goos string) (osLabel string, details string) {
	switch goos {
	case "linux":
		return "Linux", "Sudo is required to write binaries under /opt/quilibrium (default install root), write the environment file under /var/lib/quilibrium (default state root), install a systemd unit, place the quilibrium-node symlink (often under /usr/local/bin), and set ownership for binaries and logs."
	case "darwin":
		return "macOS", "Sudo is required to write binaries under /usr/local/quilibrium (default install root), write the environment file under /usr/local/var/quilibrium (default state root), install a launchd plist, place the quilibrium-node symlink (often under /usr/local/bin), and set ownership for binaries and logs."
	default:
		return goos, fmt.Sprintf("Sudo is required on %s to install system paths, the node service, binaries, and related config.", goos)
	}
}

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

		--install-dir   Root install directory for node binaries (defaults
		                to /opt/quilibrium on Linux and
		                /usr/local/quilibrium on macOS). Binaries go to
		                <install-dir>/bin/node/<version>/.
		--state-dir     Root directory for mutable node state (defaults
		                to /var/lib/quilibrium on Linux and
		                /usr/local/var/quilibrium on macOS). The systemd
		                EnvironmentFile lives at
		                <state-dir>/quilibrium.env.
		--symlink-dir   Directory holding the quilibrium-node symlink
		                (defaults to /usr/local/bin). Make sure this is on
		                your $PATH if you change it.
		--configs-dir   Directory holding named node configs (defaults to
		                ~/.quilibrium/configs).
		--service-name  Name of the systemd service unit for the node
		                (defaults to "quilibrium-node"). Can also be
		                changed later via 'qclient config service-name'.

	The node log directory is not a qclient setting; it lives in the
	node config's logger.path. On install, qclient ensures the active
	node config has a logger block pointing to a .logs directory next to
	that config's config.yml and creates that directory with the correct
	ownership. Change the log location later with:

		qclient node config set logger.path /custom/log/dir

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
	Logs are controlled by the active node config's logger block and
	written (and rotated) by the node itself via its lumberjack-based
	logger. qclient does not install a separate logrotate rule.

	The default log directory is <config-dir>/.logs/.

	You can view and clean logs with:

		qclient node log view
		qclient node log clean

When installing with this command, if no version is specified, the latest version will be installed.

Sudo is required to install the node to install the node binary, logging,systemd (on Linux), and create the config directory.

Examples:

  	# Install the latest version
  	qclient node install

  	# Install a specific version
  	qclient node install 2.1.0

  	# Install into a custom directory tree
  	qclient node install --install-dir /opt/quilibrium

  	# Interactively prompt for every install setting
  	qclient node install --interactive
  	qclient node install -i
`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get system information and validate
		osType, arch, err := utils.GetSystemInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		// If --interactive was passed, prompt the user for every
		// install-time setting before we persist anything. The prompts
		// write back into the same flag variables so the rest of this
		// command sees them exactly as if they'd been passed on the CLI.
		var interactiveVersion string
		if interactiveFlag {
			v, err := runInteractiveInstallPrompts(args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			interactiveVersion = v
		}

		// Apply any --install-dir / --state-dir / --symlink-dir /
		// --configs-dir overrides to the persisted client config before
		// we start laying files down, so every subsequent path lookup
		// reads the new value.
		if err := applyInstallDirFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		warnLegacyInstallLayout()

		// Determine version to install. Interactive mode wins over
		// positional args when the user selected something there.
		var version string
		if interactiveVersion != "" {
			version = interactiveVersion
		} else {
			version = determineVersion(args)
		}

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

// applyInstallDirFlags persists any --install-dir/--symlink-dir/
// --configs-dir overrides to the client config. It validates that each
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
		{"state-dir", stateDirFlag, &cfg.NodeStateDir, utils.GetNodeStateDir()},
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

	if serviceNameFlag != "" {
		if err := utils.ValidateNodeServiceName(serviceNameFlag); err != nil {
			return fmt.Errorf("--service-name: %w", err)
		}
		if cfg.NodeServiceName != serviceNameFlag {
			if nodeInstalled {
				fmt.Fprintf(os.Stderr,
					"Warning: --service-name changes %s -> %s, but an "+
						"existing node installation was detected. The new "+
						"value has been saved to the qclient config and "+
						"will take effect on the next install/update; the "+
						"previously installed service unit has not been "+
						"renamed. Use 'qclient config service-name' to "+
						"migrate an installed unit in place.\n",
					cfg.NodeServiceName, serviceNameFlag,
				)
			}
			cfg.NodeServiceName = serviceNameFlag
			changed = true
		}
	}

	if !changed {
		return nil
	}

	if err := utils.SaveClientConfig(cfg); err != nil {
		return fmt.Errorf("saving client config: %w", err)
	}
	return nil
}

// warnLegacyInstallLayout emits a one-shot warning when the install
// would land in (or leave behind) the pre-FHS-split /var/quilibrium
// layout. No files are moved; the user is told how to opt in to the
// new defaults or explicitly pin to the old path.
func warnLegacyInstallLayout() {
	cfg, err := utils.LoadClientConfig()
	if err != nil {
		return
	}

	resolvedInstall := utils.GetNodeInstallDir()
	resolvedState := utils.GetNodeStateDir()

	pinnedLegacyInstall := cfg.NodeInstallDir == utils.LegacyNodeInstallDir
	pinnedLegacyState := cfg.NodeStateDir == utils.LegacyNodeInstallDir
	legacyTreeExists := utils.FileExists(
		filepath.Join(utils.LegacyNodeInstallDir, "bin", "node"),
	) || utils.FileExists(
		filepath.Join(utils.LegacyNodeInstallDir, "quilibrium.env"),
	)

	if !pinnedLegacyInstall && !pinnedLegacyState && !legacyTreeExists {
		return
	}

	defaultInstall := utils.DefaultNodeInstallDir()
	defaultState := utils.DefaultNodeStateDir()

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr,
		"Notice: the default install layout has moved off "+
			utils.LegacyNodeInstallDir+".")
	fmt.Fprintf(os.Stderr,
		"  New defaults: binaries at %s, env/state at %s.\n",
		defaultInstall, defaultState,
	)
	if pinnedLegacyInstall || pinnedLegacyState {
		var pins []string
		var flagsToDrop []string
		if pinnedLegacyInstall {
			pins = append(pins, fmt.Sprintf("install-dir=%s", resolvedInstall))
			flagsToDrop = append(flagsToDrop, "--install-dir")
		}
		if pinnedLegacyState {
			pins = append(pins, fmt.Sprintf("state-dir=%s", resolvedState))
			flagsToDrop = append(flagsToDrop, "--state-dir")
		}
		fmt.Fprintf(os.Stderr,
			"  Your qclient config currently pins %s to the legacy layout;\n"+
				"  this install will keep writing there.\n",
			strings.Join(pins, ", "),
		)
		fmt.Fprintf(os.Stderr,
			"  To adopt the new default(s), run 'sudo qclient node uninstall' "+
				"then reinstall without %s.\n",
			strings.Join(flagsToDrop, "/"),
		)
	} else if legacyTreeExists {
		fmt.Fprintf(os.Stderr,
			"  A legacy install tree was detected under %s but this install "+
				"will use the new defaults (%s and %s).\n",
			utils.LegacyNodeInstallDir, resolvedInstall, resolvedState,
		)
		fmt.Fprintf(os.Stderr,
			"  To stay on the legacy layout, rerun with "+
				"--install-dir %s --state-dir %s.\n",
			utils.LegacyNodeInstallDir, utils.LegacyNodeInstallDir,
		)
		fmt.Fprintf(os.Stderr,
			"  Files under %s are NOT moved automatically; remove them "+
				"manually once you've verified the new install.\n",
			utils.LegacyNodeInstallDir,
		)
	}
	fmt.Fprintln(os.Stderr)
}

func init() {
	NodeInstallCmd.Flags().StringVar(
		&installDirFlag, "install-dir", "",
		"Root install directory for node binaries (defaults to "+
			"/opt/quilibrium on Linux, /usr/local/quilibrium on macOS). "+
			"Persisted to qclient config.",
	)
	NodeInstallCmd.Flags().StringVar(
		&stateDirFlag, "state-dir", "",
		"Root directory for mutable node state / env file (defaults "+
			"to /var/lib/quilibrium on Linux, /usr/local/var/quilibrium "+
			"on macOS). Persisted to qclient config.",
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
	NodeInstallCmd.Flags().StringVar(
		&serviceNameFlag, "service-name", "",
		"Name of the systemd service unit for the node (defaults to "+
			"\"quilibrium-node\"). Persisted to qclient config.",
	)
	NodeInstallCmd.Flags().BoolVarP(
		&interactiveFlag, "interactive", "i", false,
		"Prompt for each install setting (version and directories) "+
			"instead of requiring flags. Pressing Enter at a prompt "+
			"keeps the current/default value.",
	)
}

// runInteractiveInstallPrompts walks the user through each install-time
// setting and writes the answers back into the same package-level flag
// variables that --install-dir / --state-dir / --symlink-dir /
// --configs-dir populate. It returns the version string the user
// selected (or "" to fall back to the positional arg / "latest").
//
// Each prompt shows the currently effective value in brackets; an empty
// response keeps that value.
func runInteractiveInstallPrompts(args []string) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintln(os.Stdout, "Interactive install. Press Enter to accept the shown default.")
	fmt.Fprintln(os.Stdout)

	versionDefault := "latest"
	if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
		versionDefault = strings.TrimSpace(args[0])
	}
	version, err := promptString(reader, "Node version to install", versionDefault)
	if err != nil {
		return "", err
	}

	dirPrompts := []struct {
		label  string
		target *string
		cur    string
	}{
		{"Install directory (binaries)", &installDirFlag, utils.GetNodeInstallDir()},
		{"State directory (env file / mutable state)", &stateDirFlag, utils.GetNodeStateDir()},
		{"Symlink directory (must be on $PATH)", &symlinkDirFlag, utils.GetNodeSymlinkDir()},
		{"Configs directory (named node configs)", &configsDirFlag, utils.GetNodeConfigsDir()},
	}

	for _, p := range dirPrompts {
		val, err := promptAbsPath(reader, p.label, p.cur)
		if err != nil {
			return "", err
		}
		if val != p.cur {
			*p.target = val
		}
	}

	curServiceName := utils.GetNodeServiceName()
	svcName, err := promptServiceName(
		reader, "Service name (systemd unit name)", curServiceName,
	)
	if err != nil {
		return "", err
	}
	if svcName != curServiceName {
		serviceNameFlag = svcName
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Summary:\n")
	fmt.Fprintf(os.Stdout, "  version       : %s\n", version)
	fmt.Fprintf(os.Stdout, "  install-dir   : %s\n", effective(installDirFlag, utils.GetNodeInstallDir()))
	fmt.Fprintf(os.Stdout, "  state-dir     : %s\n", effective(stateDirFlag, utils.GetNodeStateDir()))
	fmt.Fprintf(os.Stdout, "  symlink-dir   : %s\n", effective(symlinkDirFlag, utils.GetNodeSymlinkDir()))
	fmt.Fprintf(os.Stdout, "  configs-dir   : %s\n", effective(configsDirFlag, utils.GetNodeConfigsDir()))
	fmt.Fprintf(os.Stdout, "  service-name  : %s\n", effective(serviceNameFlag, utils.GetNodeServiceName()))
	fmt.Fprintln(os.Stdout)

	ok, err := promptYesNo(reader, "Proceed with these settings?", true)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("install cancelled by user")
	}

	return version, nil
}

func effective(flagVal, current string) string {
	if flagVal != "" {
		return flagVal
	}
	return current
}

func promptString(r *bufio.Reader, label, def string) (string, error) {
	fmt.Fprintf(os.Stdout, "%s [%s]: ", label, def)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

func promptAbsPath(r *bufio.Reader, label, def string) (string, error) {
	for {
		val, err := promptString(r, label, def)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(val) {
			fmt.Fprintf(os.Stderr, "  path must be absolute, got %q\n", val)
			continue
		}
		return val, nil
	}
}

func promptServiceName(r *bufio.Reader, label, def string) (string, error) {
	for {
		val, err := promptString(r, label, def)
		if err != nil {
			return "", err
		}
		if err := utils.ValidateNodeServiceName(val); err != nil {
			fmt.Fprintf(os.Stderr, "  %v\n", err)
			continue
		}
		return val, nil
	}
}

func promptYesNo(r *bufio.Reader, label string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(os.Stdout, "%s %s: ", label, hint)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("reading input: %w", err)
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return def, nil
	}
	return line == "y" || line == "yes", nil
}
