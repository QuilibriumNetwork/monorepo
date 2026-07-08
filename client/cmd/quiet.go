package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var QuietCmd = &cobra.Command{
	Use:   "quiet [enable|disable]",
	Short: "Hide informational output when signature verification succeeds",
	Long: `When quiet mode is enabled, qclient does not print progress lines for a successful
signature check, and does not print the banner when signature verification is bypassed.
Verification errors and prompts are always shown.

With no argument, the current setting is toggled.`,
	Run: func(_ *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		if len(args) > 0 {
			switch strings.ToLower(args[0]) {
			case "enable":
				cfg.Quiet = true
			case "disable":
				cfg.Quiet = false
			default:
				fmt.Printf("Error: Invalid value '%s'. Please use 'enable' or 'disable'.\n", args[0])
				os.Exit(1)
			}
		} else {
			cfg.Quiet = !cfg.Quiet
		}

		if err := utils.SaveClientConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}

		status := "disabled"
		if cfg.Quiet {
			status = "enabled"
		}
		fmt.Printf("Quiet mode has been %s and will apply to future commands.\n", status)
	},
}
