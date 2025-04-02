package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var versionFlag string

var downloadSignaturesCmd = &cobra.Command{
	Use:   "download-signatures",
	Short: "Download signature files for the current binary",
	Long: `Download signature files for the current binary. This command will download
the digest file and all signature files needed for verification. If --version is specified,
it will download signatures for that version. Otherwise, it will download signatures for
the latest version.`,
	Run: func(cmd *cobra.Command, args []string) {
		var version string

		if versionFlag != "" {
			// Use specified version
			version = versionFlag
		} else {
			// Get the current version
			version = config.GetVersionString()
		}

		// Download signature files
		if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeQClient, version); err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading signature files: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully downloaded signature files for version %s\n", version)
	},
}

func init() {
	downloadSignaturesCmd.Flags().StringVarP(
		&versionFlag,
		"version",
		"v",
		"",
		"Version to download signatures for (defaults to latest version)",
	)
	rootCmd.AddCommand(downloadSignaturesCmd)
}
