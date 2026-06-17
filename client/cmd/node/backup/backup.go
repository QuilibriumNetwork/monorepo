package backup

import (
	"github.com/spf13/cobra"
)

// BackupCmd is the root of `qclient node backup`.
var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Manage node backups to S3-compatible object storage",
	Long: `Configure and control node backups to any S3-compatible endpoint
(AWS S3, Quilibrium qstorage, MinIO, Backblaze B2, etc.).

Typical flow:

  qclient node backup config          # interactive setup (credentials, bucket, etc.)
  qclient node backup config print    # show the persisted configuration
  qclient node backup enable          # turn backups on
  qclient node backup disable         # turn backups off
  qclient node backup schedule "0 * * * *"   # install hourly cron
  qclient node backup run             # back up now (config + store + worker-store)
  qclient node backup restore         # download a backup to its original paths`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	BackupCmd.AddCommand(enableCmd)
	BackupCmd.AddCommand(disableCmd)
	BackupCmd.AddCommand(configCmd)
	BackupCmd.AddCommand(scheduleCmd)
	BackupCmd.AddCommand(runCmd)
	BackupCmd.AddCommand(restoreCmd)
}
