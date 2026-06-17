package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var symlinkPath = "/usr/local/bin/qclient"

var LinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Create a symlink to the QClient binary (requires sudo)",
	Long: `Create a symlink to the qclient binary in the directory /usr/local/bin/ and 
	allows a user to run qclient from anywhere using the shortened 'qclient' command.

Example: qclient link`,
	RunE: func(cmd *cobra.Command, args []string) error {
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		if utils.IsSudo() {
			fmt.Printf("Running as sudo, creating symlink at %s\n", symlinkPath)
		} else {
			fmt.Printf("Cannot create symlink at %s, please run this command with sudo\n", symlinkPath)
			os.Exit(1)
		}

		expectedPrefix := utils.GetQClientBinaryDir()

		if !strings.HasPrefix(execPath, expectedPrefix) {
			newPath, err := promptRelocateExecutable(execPath, expectedPrefix)
			if err != nil {
				return err
			}
			if newPath == "" {
				fmt.Println("Aborted. No symlink created.")
				return nil
			}
			execPath = newPath
		}

		if err := utils.CreateSymlink(execPath, symlinkPath); err != nil {
			return err
		}

		fmt.Printf("Symlink created at %s -> %s\n", symlinkPath, execPath)
		return nil
	},
}

// promptRelocateExecutable asks the user how to handle a qclient binary that
// lives outside the standard install tree. Returns the path the symlink
// should target, or "" if the user aborted.
func promptRelocateExecutable(execPath, expectedPrefix string) (string, error) {
	standardDir := filepath.Join(expectedPrefix, "bin", "<version>")

	fmt.Println()
	fmt.Println("Current executable is not in the standard location.")
	fmt.Printf("  Current path:  %s\n", execPath)
	fmt.Printf("  Standard path: %s/\n", standardDir)
	fmt.Println()
	fmt.Println("Choose how to link this binary:")
	fmt.Printf("  [1] Link the current file path as-is  (recommended for dev builds)\n")
	fmt.Printf("      symlink -> %s\n", execPath)
	fmt.Printf("  [2] Copy into the standard location, then link  (install this build, non-destructive)\n")
	fmt.Printf("  [3] Move into the standard location, then link  (removes binary from current path)\n")
	fmt.Printf("  [4] Copy into a custom directory, then link\n")
	fmt.Printf("  [a] Abort\n")
	fmt.Print("Choice [1/2/3/4/a] (default 1): ")

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	choice := strings.ToLower(strings.TrimSpace(line))
	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1", "y", "yes":
		fmt.Printf("Linking current file path as-is: %s\n", execPath)
		return execPath, nil

	case "2", "copy":
		destDir, err := standardVersionedDir()
		if err != nil {
			return "", err
		}
		return relocateExecutable(execPath, destDir, false)

	case "3", "move", "n", "no":
		destDir, err := standardVersionedDir()
		if err != nil {
			return "", err
		}
		return relocateExecutable(execPath, destDir, true)

	case "4", "custom":
		fmt.Print("Enter destination directory: ")
		dirLine, _ := reader.ReadString('\n')
		destDir := strings.TrimSpace(dirLine)
		if destDir == "" {
			return "", fmt.Errorf("no destination directory provided")
		}
		return relocateExecutable(execPath, destDir, false)

	case "a", "abort", "q", "quit":
		return "", nil

	default:
		return "", fmt.Errorf("invalid choice %q", choice)
	}
}

// standardVersionedDir returns <qclient install dir>/bin/<version>/, creating
// it (with the invoking sudo user as owner) if necessary.
func standardVersionedDir() (string, error) {
	version, err := GetVersionInfo(false)
	if err != nil {
		return "", fmt.Errorf("failed to get version info: %w", err)
	}
	// NB: historical layout — keep the extra "bin" segment to match
	// what older qclient link behavior produced.
	return filepath.Join(utils.GetQClientBinaryDir(), "bin", version.Version), nil
}

// relocateExecutable copies or moves the qclient binary (and any
// .dgst / .dgst.sig.N sidecar files sitting next to it) into destDir,
// renaming the binary to StandardizedQClientFileName. Returns the new
// path to the binary.
func relocateExecutable(execPath, destDir string, move bool) (string, error) {
	currentUser, err := utils.GetCurrentSudoUser()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}
	if err := utils.ValidateAndCreateDir(destDir, currentUser); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", destDir, err)
	}

	verb := "Copying"
	if move {
		verb = "Moving"
	}

	destBinary := filepath.Join(destDir, StandardizedQClientFileName)
	fmt.Printf("%s binary: %s -> %s\n", verb, execPath, destBinary)
	if err := relocateFile(execPath, destBinary, move); err != nil {
		return "", fmt.Errorf("failed to relocate executable: %w", err)
	}

	// Relocate sidecar digest / signature files if they exist next to
	// the source binary. These share the binary's basename.
	sidecarSuffixes := []string{".dgst"}
	// Pick up any .dgst.sig.* siblings too.
	if matches, err := filepath.Glob(execPath + ".dgst.sig.*"); err == nil {
		for _, m := range matches {
			sidecarSuffixes = append(sidecarSuffixes, strings.TrimPrefix(m, execPath))
		}
	}

	for _, suffix := range sidecarSuffixes {
		srcSidecar := execPath + suffix
		if _, err := os.Stat(srcSidecar); err != nil {
			continue
		}
		dstSidecar := filepath.Join(destDir, StandardizedQClientFileName+suffix)
		fmt.Printf("%s sidecar: %s -> %s\n", verb, srcSidecar, dstSidecar)
		if err := relocateFile(srcSidecar, dstSidecar, move); err != nil {
			return "", fmt.Errorf("failed to relocate sidecar %s: %w", srcSidecar, err)
		}
	}

	return destBinary, nil
}

// relocateFile moves or copies a single file, preserving the source's
// permission bits (important for the executable).
func relocateFile(src, dst string, move bool) error {
	if move {
		if err := os.Rename(src, dst); err == nil {
			return nil
		}
		// Fall through to copy+remove in case of cross-device rename.
		if err := copyFilePreservePerms(src, dst); err != nil {
			return err
		}
		return os.Remove(src)
	}
	return copyFilePreservePerms(src, dst)
}

func copyFilePreservePerms(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode().Perm())
}
