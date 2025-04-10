package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

// Version information - fallback if executable name doesn't contain version
var (
	DefaultVersion = config.GetVersionString()
)

// VersionInfo holds version and hash information
type VersionInfo struct {
	Version string
	SHA256  string
	MD5     string
}

// GetVersionInfo extracts version from executable and optionally calculates hashes
func GetVersionInfo(calcChecksum bool) (VersionInfo, error) {
	executable, err := os.Executable()
	if err != nil {
		return VersionInfo{Version: DefaultVersion}, fmt.Errorf("error getting executable path: %v", err)
	}

	// Extract version from executable name (e.g. qclient-2.0.3-linux-amd)
	baseName := filepath.Base(executable)
	versionPattern := regexp.MustCompile(`qclient-([0-9]+\.[0-9]+\.[0-9]+)`)
	matches := versionPattern.FindStringSubmatch(baseName)

	version := DefaultVersion
	if len(matches) > 1 {
		version = matches[1]
	}

	// If version not found or checksum requested, calculate hash
	if len(matches) <= 1 || calcChecksum {
		sha256Hash, md5Hash, err := utils.CalculateFileHashes(executable)
		if err != nil {
			return VersionInfo{Version: version}, fmt.Errorf("error calculating file hashes: %v", err)
		}

		return VersionInfo{
			Version: version,
			SHA256:  sha256Hash,
			MD5:     md5Hash,
		}, nil
	}

	return VersionInfo{
		Version: version,
	}, nil
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the qclient version",
	Long:  `Display the qclient version and optionally calculate SHA256 and MD5 hashes of the executable.`,
	Run: func(cmd *cobra.Command, args []string) {
		showChecksum, _ := cmd.Flags().GetBool("checksum")

		info, err := GetVersionInfo(showChecksum)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("%s\n", info.Version)

		if showChecksum {
			if info.SHA256 != "" && info.MD5 != "" {
				fmt.Printf("SHA256: %s\n", info.SHA256)
				fmt.Printf("MD5: %s\n", info.MD5)
			}
		}
	},
}

func init() {
	versionCmd.Flags().Bool("checksum", false, "Show SHA256 and MD5 checksums of the executable")
	rootCmd.AddCommand(versionCmd)
}
