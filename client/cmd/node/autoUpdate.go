package node

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// autoUpdateCmd represents the command to setup automatic updates
var autoUpdateCmd = &cobra.Command{
	Use:   "auto-update",
	Short: "Setup automatic update checks",
	Long: `Setup a cron job to automatically check for Quilibrium node updates every 10 minutes.

This command will create a cron entry that runs 'qclient node update' every 10 minutes
to check for and apply any available updates.

Example:
  # Setup automatic update checks
  qclient node auto-update`,
	Run: func(cmd *cobra.Command, args []string) {
		setupCronJob()
	},
}

func init() {
	NodeCmd.AddCommand(autoUpdateCmd)
}

func setupCronJob() {
	// Get full path to qclient executable
	qclientPath, err := exec.LookPath("qclient")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: qclient executable not found in PATH: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please ensure qclient is properly installed and in your PATH (use 'sudo qclient link')\n")
		return
	}

	// Absolute path for qclient
	qclientAbsPath, err := filepath.Abs(qclientPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path for qclient: %v\n", err)
		return
	}

	// OS-specific setup
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		setupUnixCron(qclientAbsPath)
	} else {
		fmt.Fprintf(os.Stderr, "Error: auto-update is only supported on macOS and Linux\n")
		return
	}
}

func isCrontabInstalled() bool {
	// Check if crontab is installed
	_, err := exec.LookPath("crontab")
	return err == nil
}

func installCrontab() {
	fmt.Fprintf(os.Stdout, "Installing cron package...\n")
	// Install crontab
	installCmd := exec.Command("sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "cron")
	if err := installCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing cron package: %v\n", err)
		return
	}

	if isCrontabInstalled() {
		fmt.Fprintf(os.Stdout, "Cron package installed\n")
	} else {
		fmt.Fprintf(os.Stderr, "Error: cron package not installed\n")
		os.Exit(1)
	}
}

func setupUnixCron(qclientPath string) {
	if !isCrontabInstalled() {
		fmt.Fprintf(os.Stdout, "Crontab command not found, attempting to install cron package...\n")
		installCrontab()
	}

	fmt.Fprintf(os.Stdout, "Setting up cron job...\n")
	// Create cron expression: run every 10 minutes
	cronExpression := fmt.Sprintf("*/10 * * * * %s node update > /dev/null 2>&1", qclientPath)

	// Check existing crontab
	checkCmd := exec.Command("crontab", "-l")
	checkOutput, err := checkCmd.CombinedOutput()

	var currentCrontab string
	if err != nil {
		// If there's no crontab yet, this is fine, start with empty crontab
		currentCrontab = ""
	} else {
		currentCrontab = string(checkOutput)
	}

	// Check if our update command is already in crontab
	if strings.Contains(currentCrontab, "qclient node update") {
		fmt.Fprintf(os.Stdout, "Automatic update check is already configured in crontab\n")
		return
	}

	// Add new cron entry
	newCrontab := currentCrontab
	if strings.TrimSpace(newCrontab) != "" && !strings.HasSuffix(newCrontab, "\n") {
		newCrontab += "\n"
	}
	newCrontab += cronExpression + "\n"

	// Write to temporary file
	tempFile, err := os.CreateTemp("", "qclient-crontab")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temporary file: %v\n", err)
		return
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.WriteString(newCrontab); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to temporary file: %v\n", err)
		return
	}
	tempFile.Close()

	// Install new crontab
	installCmd := exec.Command("crontab", tempFile.Name())
	if err := installCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing crontab: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Successfully configured cron job to check for updates every 10 minutes\n")
	fmt.Fprintf(os.Stdout, "Added: %s\n", cronExpression)
}
