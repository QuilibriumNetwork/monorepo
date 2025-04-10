package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
)

var ClientInstallPath = filepath.Join("/opt/quilibrium/", string(ReleaseTypeQClient))
var RootQuilibriumPath = filepath.Join("/var/quilibrium/")
var BinaryPath = filepath.Join(RootQuilibriumPath, "bin")
var ClientDataPath = filepath.Join(BinaryPath, string(ReleaseTypeQClient))
var NodeDataPath = filepath.Join(BinaryPath, string(ReleaseTypeNode))
var DefaultSymlinkDir = "/usr/local/bin"
var DefaultNodeSymlinkPath = filepath.Join(DefaultSymlinkDir, string(ReleaseTypeNode))
var DefaultQClientSymlinkPath = filepath.Join(DefaultSymlinkDir, string(ReleaseTypeQClient))
var osType = runtime.GOOS
var arch = runtime.GOARCH

// CalculateFileHashes calculates SHA256 and MD5 hashes for a file
func CalculateFileHashes(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Calculate SHA256
	sha256Hash := sha256.New()
	if _, err := io.Copy(sha256Hash, file); err != nil {
		return "", "", fmt.Errorf("error calculating SHA256: %w", err)
	}

	// Reset file position to beginning for MD5 calculation
	if _, err := file.Seek(0, 0); err != nil {
		return "", "", fmt.Errorf("error seeking file: %w", err)
	}

	// Calculate MD5
	md5Hash := md5.New()
	if _, err := io.Copy(md5Hash, file); err != nil {
		return "", "", fmt.Errorf("error calculating MD5: %w", err)
	}

	return hex.EncodeToString(sha256Hash.Sum(nil)), hex.EncodeToString(md5Hash.Sum(nil)), nil
}

// CreateSymlink creates a symlink, handling the case where it already exists
func CreateSymlink(execPath, targetPath string) error {
	// Check if the symlink already exists
	if _, err := os.Lstat(targetPath); err == nil {
		// Symlink exists, ask if user wants to overwrite
		if !ConfirmSymlinkOverwrite(targetPath) {
			fmt.Println("Operation cancelled.")
			return nil
		}

		// Remove existing symlink
		if err := os.Remove(targetPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	fmt.Printf("Creating symlink %s -> %s\n", targetPath, execPath)

	// Create the symlink
	if err := os.Symlink(execPath, targetPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	return nil
}

// ValidateAndCreateDir validates a directory path and creates it if it doesn't exist
func ValidateAndCreateDir(path string, user *user.User) error {
	// Check if the directory exists
	info, err := os.Stat(path)
	if err == nil {
		// Path exists, check if it's a directory
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", path)
		}
		return nil
	}

	// Directory doesn't exist, try to create it
	if os.IsNotExist(err) {
		fmt.Printf("Creating directory %s\n", path)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
		if user != nil {
			ChownPath(path, user, false)
		}
		return nil
	}

	// Some other error occurred
	return fmt.Errorf("error checking directory %s: %v", path, err)
}

// IsWritable checks if a directory is writable
func IsWritable(dir string) bool {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if directory is writable by creating a temporary file
	tempFile := filepath.Join(dir, ".quilibrium_write_test")
	file, err := os.Create(tempFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(tempFile)
	return true
}

// CanCreateAndWrite checks if we can create and write to a directory
func CanCreateAndWrite(dir string) bool {
	// Try to create the directory
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false
	}

	// Check if we can write to it
	return IsWritable(dir)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func IsSudo() bool {
	user, err := user.Current()
	if err != nil {
		return false
	}
	return user.Username == "root"
}

// ChownPath changes the owner of a file or directory to the specified user
func ChownPath(path string, user *user.User, isRecursive bool) error {
	// Change ownership of the path
	if isRecursive {
		fmt.Printf("Changing ownership of %s (recursive) to %s\n", path, user.Username)
		if err := exec.Command("chown", "-R", user.Uid+":"+user.Gid, path).Run(); err != nil {
			return fmt.Errorf("failed to change ownership of %s to %s (requires sudo): %v", path, user.Uid, err)
		}
	} else {
		fmt.Printf("Changing ownership of %s to %s\n", path, user.Username)
		if err := exec.Command("chown", user.Uid+":"+user.Gid, path).Run(); err != nil {
			return fmt.Errorf("failed to change ownership of %s to %s (requires sudo): %v", path, user.Uid, err)
		}
	}

	return nil
}

func ChmodPath(path string, mode os.FileMode, description string) error {
	fmt.Printf("Changing path: %s to %s (%s)\n", path, mode, description)
	return os.Chmod(path, mode)
}

func WriteFile(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// WriteFileAuto writes content to a file, automatically using sudo only if necessary
func WriteFileAuto(path string, content string) error {
	// First check if file exists and is writable
	if FileExists(path) {
		// Try to open the file for writing to check permissions
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			// File is writable, close it and write normally
			file.Close()
			fmt.Printf("Writing to file %s using normal permissions\n", path)
			return os.WriteFile(path, []byte(content), 0644)
		}
	} else {
		// Check if parent directory is writable
		dir := filepath.Dir(path)
		if IsWritable(dir) {
			fmt.Printf("Writing to file %s using normal permissions\n", path)
			return os.WriteFile(path, []byte(content), 0644)
		}
	}

	// If we reach here, sudo is needed
	fmt.Printf("Writing to file %s using sudo\n", path)
	cmd := exec.Command("sudo", "tee", path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sudo command: %w", err)
	}

	// Write content to stdin
	if _, err := io.WriteString(stdin, content); err != nil {
		return fmt.Errorf("failed to write to stdin: %w", err)
	}
	stdin.Close()

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("sudo tee command failed: %w", err)
	}

	return nil
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	fmt.Printf("Copying file from %s to %s\n", src, dst)
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, sourceData, 0600)
}
