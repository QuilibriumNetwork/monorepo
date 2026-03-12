package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var versionFlag string

var DownloadSignaturesCmd = &cobra.Command{
	Use:   "download-signatures",
	Short: "Download signature files for the current QClient binary",
	Long: `Download signature files for the current QClient binary. 
	
	This command will download the digest file and all signature files needed for verification. 
	
	Optionally, if --version is specified, it will download signatures for that version. 
	Otherwise, by default it will download signatures for the latest version.
	
	Example:
	
		qclient download-signatures --version 1.0.0
	`,
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
	DownloadSignaturesCmd.Flags().StringVar(&versionFlag, "version", "", "Version to download signatures for")
}
