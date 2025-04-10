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
	Use:   "auto-update [enable|disable|status]",
	Short: "Setup automatic update checks",
	Long: `Setup, remove, or check status of a cron job to automatically check for Quilibrium node updates every 10 minutes.

This command will create, remove, or check a cron entry that runs 'qclient node update' every 10 minutes
to check for and apply any available updates.

Example:
  # Setup automatic update checks
  qclient node auto-update enable
  
  # Remove automatic update checks
  qclient node auto-update disable
  
  # Check if automatic update is enabled
  qclient node auto-update status`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 || (args[0] != "enable" && args[0] != "disable" && args[0] != "status") {
			fmt.Fprintf(os.Stderr, "Error: must specify 'enable', 'disable', or 'status'\n")
			cmd.Help()
			return
		}

		if args[0] == "enable" {
			setupCronJob()
		} else if args[0] == "disable" {
			removeCronJob()
		} else if args[0] == "status" {
			checkAutoUpdateStatus()
		}
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

func removeCronJob() {
	// OS-specific removal
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		removeUnixCron()
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
	updateCmd := exec.Command("sudo", "apt-get", "update")
	updateCmd.Stdout = nil
	updateCmd.Stderr = nil
	if err := updateCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating package lists: %v\n", err)
		return
	}

	installCmd := exec.Command("sudo", "apt-get", "install", "-y", "cron")
	installCmd.Stdout = nil
	installCmd.Stderr = nil
	if err := installCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing cron package: %v\n", err)
		return
	}

	// verify crontab is installed
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
	if strings.Contains(currentCrontab, "### qclient-auto-update") {
		fmt.Fprintf(os.Stdout, "Automatic update check is already configured in crontab\n")
		return
	}

	// Add new cron entry with indicators
	newCrontab := currentCrontab
	if strings.TrimSpace(newCrontab) != "" && !strings.HasSuffix(newCrontab, "\n") {
		newCrontab += "\n"
	}
	newCrontab += "### qclient-auto-update\n" +
		cronExpression + "\n" +
		"### end-qclient-auto-update\n"

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

func removeUnixCron() {
	if !isCrontabInstalled() {
		fmt.Fprintf(os.Stderr, "Error: crontab command not found\n")
		return
	}

	fmt.Fprintf(os.Stdout, "Removing auto-update cron job...\n")

	// Check existing crontab
	checkCmd := exec.Command("crontab", "-l")
	checkOutput, err := checkCmd.CombinedOutput()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking existing crontab: %v\n", err)
		return
	}

	currentCrontab := string(checkOutput)

	// No crontab or doesn't contain our section
	if currentCrontab == "" || !strings.Contains(currentCrontab, "### qclient-auto-update") {
		fmt.Fprintf(os.Stdout, "No auto-update job found in crontab\n")
		return
	}

	// Remove our section
	startMarker := "### qclient-auto-update"
	endMarker := "### end-qclient-auto-update"

	startIdx := strings.Index(currentCrontab, startMarker)
	endIdx := strings.Index(currentCrontab, endMarker)

	var newCrontab string
	if startIdx >= 0 && endIdx >= 0 {
		endIdx += len(endMarker)
		// Remove the section including markers
		newCrontab = currentCrontab[:startIdx] + currentCrontab[endIdx:]
	} else {
		newCrontab = currentCrontab
	}

	// Clean up any leftover double newlines
	newCrontab = strings.ReplaceAll(newCrontab, "\n\n\n", "\n\n")
	if strings.TrimSpace(newCrontab) != "" && !strings.HasSuffix(newCrontab, "\n") {
		newCrontab += "\n"
	}

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
		fmt.Fprintf(os.Stderr, "Error updating crontab: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Successfully removed auto-update cron job\n")
}

func checkAutoUpdateStatus() {
	if !isCrontabInstalled() {
		fmt.Fprintf(os.Stderr, "Error: crontab command not found\n")
		fmt.Fprintf(os.Stdout, "Auto-update is not enabled (crontab not installed)\n")
		return
	}

	// Check existing crontab
	checkCmd := exec.Command("crontab", "-l")
	checkOutput, err := checkCmd.CombinedOutput()

	if err != nil {
		fmt.Fprintf(os.Stdout, "Auto-update is not enabled (no crontab found)\n")
		return
	}

	currentCrontab := string(checkOutput)

	if strings.Contains(currentCrontab, "### qclient-auto-update") {
		// Extract the cron expression
		startMarker := "### qclient-auto-update"
		endMarker := "### end-qclient-auto-update"

		startIdx := strings.Index(currentCrontab, startMarker) + len(startMarker)
		endIdx := strings.Index(currentCrontab, endMarker)

		if startIdx >= 0 && endIdx >= 0 {
			cronSection := currentCrontab[startIdx:endIdx]
			cronLines := strings.Split(strings.TrimSpace(cronSection), "\n")
			if len(cronLines) > 0 {
				fmt.Fprintf(os.Stdout, "Auto-update is enabled.")
				fmt.Fprintf(os.Stdout, "The installed schedule is: %s\n", strings.TrimSpace(cronLines[0]))
			} else {
				fmt.Fprintf(os.Stdout, "Auto-update is enabled\n")
			}
		} else {
			fmt.Fprintf(os.Stdout, "Auto-update is enabled\n")
		}
	} else {
		fmt.Fprintf(os.Stdout, "Auto-update is not enabled\n")
	}
}
