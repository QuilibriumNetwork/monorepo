package backup

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// DefaultBackupCronSchedule runs hourly at minute 0.
const DefaultBackupCronSchedule = "0 * * * *"

// cronMarker tags the crontab line managed by qclient so we can update
// or remove it without disturbing other user cron entries.
const cronMarker = "# managed-by: qclient node backup"

var scheduleCmd = &cobra.Command{
	Use:   "schedule [cron-expression]",
	Short: "Configure a cron schedule that runs `qclient node backup run`",
	Long: `Install or show the cron schedule for periodic node backups.

Examples:
  qclient node backup schedule                 # print current schedule (or default)
  qclient node backup schedule "0 * * * *"     # hourly (default)
  qclient node backup schedule "*/15 * * * *"  # every 15 minutes
  qclient node backup schedule "0 3 * * *"     # daily at 03:00
  qclient node backup schedule disable         # remove the managed cron entry

The cron entry invokes the current qclient binary as the invoking user and
runs ` + "`qclient node backup run`" + ` with signature checks disabled (the
binary path resolved at install time is written into the cron line).`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			if err := printSchedule(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		arg := strings.TrimSpace(args[0])
		if strings.EqualFold(arg, "disable") || strings.EqualFold(arg, "remove") {
			if err := removeSchedule(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if err := installSchedule(arg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func printSchedule() error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	line := findManagedLine(existing)
	if line == "" {
		fmt.Printf("No qclient-managed backup schedule installed.\n")
		fmt.Printf("Default suggestion: %q\n", DefaultBackupCronSchedule)
		return nil
	}
	expr, cmdStr := parseManagedLine(line)
	fmt.Printf("Schedule: %s\n", expr)
	fmt.Printf("Command:  %s\n", cmdStr)
	return nil
}

func installSchedule(expr string) error {
	if err := ValidateCronExpression(expr); err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve qclient binary path: %w", err)
	}
	// Use signature-check=false because a cron job runs
	// non-interactively and the daily signature rotation would
	// otherwise break scheduled runs.
	cmdStr := fmt.Sprintf("%s --signature-check=false node backup run", execPath)
	newLine := fmt.Sprintf("%s %s %s", expr, cmdStr, cronMarker)

	existing, err := readCrontab()
	if err != nil {
		return err
	}
	updated := replaceOrAppendManagedLine(existing, newLine)
	if err := writeCrontab(updated); err != nil {
		return err
	}
	fmt.Printf("Installed backup schedule: %s\n", expr)
	fmt.Printf("  %s\n", cmdStr)
	return nil
}

func removeSchedule() error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	if findManagedLine(existing) == "" {
		fmt.Println("No qclient-managed backup schedule to remove.")
		return nil
	}
	updated := removeManagedLine(existing)
	if err := writeCrontab(updated); err != nil {
		return err
	}
	fmt.Println("Removed qclient-managed backup schedule.")
	return nil
}

// readCrontab returns the current user crontab content (empty string
// when no crontab exists).
func readCrontab() (string, error) {
	if _, err := exec.LookPath("crontab"); err != nil {
		return "", fmt.Errorf("crontab command not found in PATH")
	}
	cmd := exec.Command("crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// `crontab -l` exits non-zero when there is no crontab; treat
		// that specific message as empty rather than an error.
		msg := stderr.String()
		if strings.Contains(msg, "no crontab") || strings.Contains(strings.ToLower(msg), "no crontab for") {
			return "", nil
		}
		if stdout.Len() == 0 && stderr.Len() == 0 {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %w: %s", err, strings.TrimSpace(msg))
	}
	return stdout.String(), nil
}

func writeCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab write: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func findManagedLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, cronMarker) {
			return line
		}
	}
	return ""
}

func parseManagedLine(line string) (expr, cmdStr string) {
	// 5 cron fields + command + marker
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return line, ""
	}
	expr = strings.Join(fields[:5], " ")
	rest := strings.TrimSpace(strings.TrimSuffix(strings.Join(fields[5:], " "), cronMarker))
	return expr, rest
}

func replaceOrAppendManagedLine(content, newLine string) string {
	lines := strings.Split(content, "\n")
	replaced := false
	for i, line := range lines {
		if strings.Contains(line, cronMarker) {
			lines[i] = newLine
			replaced = true
		}
	}
	if !replaced {
		// Drop trailing empty line to avoid double blanks.
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, newLine)
	}
	// Ensure trailing newline.
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func removeManagedLine(content string) string {
	lines := strings.Split(content, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, cronMarker) {
			continue
		}
		filtered = append(filtered, line)
	}
	out := strings.Join(filtered, "\n")
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

// ValidateCronExpression checks that expr is a well-formed 5-field
// classic-vixie cron expression: minute hour day-of-month month day-of-week.
// It supports *, */n, a-b, a,b,c, and plain integers. It does not support
// macros (@hourly, @daily, etc.) or seconds fields.
func ValidateCronExpression(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("expected 5 fields, got %d", len(fields))
	}
	ranges := [5][2]int{
		{0, 59}, // minute
		{0, 23}, // hour
		{1, 31}, // day of month
		{1, 12}, // month
		{0, 6},  // day of week (0 or 7 = Sunday; we accept 0-6)
	}
	names := [5]string{"minute", "hour", "day-of-month", "month", "day-of-week"}
	for i, f := range fields {
		if err := validateCronField(f, ranges[i][0], ranges[i][1]); err != nil {
			return fmt.Errorf("%s field: %w", names[i], err)
		}
	}
	return nil
}

var cronTokenRe = regexp.MustCompile(`^[\d\*/,\-]+$`)

func validateCronField(f string, min, max int) error {
	if f == "" {
		return fmt.Errorf("empty")
	}
	if !cronTokenRe.MatchString(f) {
		return fmt.Errorf("unsupported characters in %q", f)
	}
	for _, part := range strings.Split(f, ",") {
		if err := validateCronPart(part, min, max); err != nil {
			return err
		}
	}
	return nil
}

func validateCronPart(part string, min, max int) error {
	step := 1
	rangeStr := part
	if idx := strings.Index(part, "/"); idx >= 0 {
		rangeStr = part[:idx]
		stepStr := part[idx+1:]
		s, err := strconv.Atoi(stepStr)
		if err != nil || s <= 0 {
			return fmt.Errorf("bad step %q", stepStr)
		}
		step = s
	}
	if rangeStr == "*" {
		_ = step
		return nil
	}
	if strings.Contains(rangeStr, "-") {
		parts := strings.SplitN(rangeStr, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("bad range %q", rangeStr)
		}
		if lo < min || hi > max || lo > hi {
			return fmt.Errorf("range %d-%d out of bounds [%d,%d]", lo, hi, min, max)
		}
		return nil
	}
	n, err := strconv.Atoi(rangeStr)
	if err != nil {
		return fmt.Errorf("bad number %q", rangeStr)
	}
	if n < min || n > max {
		return fmt.Errorf("%d out of bounds [%d,%d]", n, min, max)
	}
	return nil
}
