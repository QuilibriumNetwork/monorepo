package backup

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable node backups",
	Long: `Enable node backups to the configured S3-compatible endpoint.

Requires that ` + "`qclient node backup config`" + ` has been run first so that
bucket, credentials, and endpoint are set.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
		if err := validateBackupConfigured(&cfg.Backup); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot enable backups: %v\n", err)
			fmt.Fprintln(os.Stderr, "Run `qclient node backup config` first.")
			os.Exit(1)
		}
		cfg.Backup.Enabled = true
		if err := utils.SaveClientConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Node backups enabled.")
	},
}

func validateBackupConfigured(b *utils.NodeBackupConfig) error {
	if b.Bucket == "" {
		return fmt.Errorf("bucket is not set")
	}
	if b.AccessKeyID == "" || b.SecretAccessKey == "" {
		return fmt.Errorf("credentials are not set")
	}
	return nil
}
