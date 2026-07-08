package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var DevCmd = &cobra.Command{
	Use:   "dev [enable|disable]",
	Short: "Toggle developer-friendly defaults for custom qclient builds",
	Long: `Dev mode applies sane defaults for locally-built / unsigned qclient binaries:

  enable:
    - signatureCheck = false  (skip signature verification)
    - quiet          = true   (suppress informational output)

  disable:
    - signatureCheck = true   (restore signature verification)
    - quiet          = false  (restore informational output)

With no argument, the current state is toggled based on the signatureCheck flag
(dev mode is considered "enabled" when signatureCheck is false).`,
	Run: func(_ *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		var enable bool
		if len(args) > 0 {
			switch strings.ToLower(args[0]) {
			case "enable":
				enable = true
			case "disable":
				enable = false
			default:
				fmt.Printf("Error: Invalid value '%s'. Please use 'enable' or 'disable'.\n", args[0])
				os.Exit(1)
			}
		} else {
			enable = cfg.SignatureCheck
		}

		if enable {
			cfg.SignatureCheck = false
			cfg.Quiet = true
		} else {
			cfg.SignatureCheck = true
			cfg.Quiet = false
		}

		if err := utils.SaveClientConfig(cfg); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}

		status := "disabled"
		if enable {
			status = "enabled"
		}
		fmt.Printf("Dev mode has been %s (signatureCheck=%v, quiet=%v).\n",
			status, cfg.SignatureCheck, cfg.Quiet)

		if enable {
			maybeLinkDevBinary()
		}
	},
}

func maybeLinkDevBinary() {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Skipping link prompt: cannot resolve current executable: %v\n", err)
		return
	}

	if existing, err := os.Readlink(symlinkPath); err == nil && existing == execPath {
		fmt.Printf("%s already points at this binary.\n", symlinkPath)
		return
	}

	fmt.Printf("Link this dev binary at %s -> %s? (y/n): ", symlinkPath, execPath)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		fmt.Println("Skipping symlink.")
		return
	}

	if !utils.IsSudo() {
		fmt.Printf("Cannot create symlink at %s without sudo. Re-run: sudo qclient link\n", symlinkPath)
		return
	}

	if err := utils.CreateSymlink(execPath, symlinkPath); err != nil {
		fmt.Printf("Failed to create symlink: %v\n", err)
		return
	}
	fmt.Printf("Symlink created at %s\n", symlinkPath)
}
