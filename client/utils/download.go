package utils

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var BaseReleaseURL = "https://releases.quilibrium.com"

// DownloadRelease downloads a specific release file
func DownloadRelease(releaseType ReleaseType, version string) error {
	fileName := fmt.Sprintf("%s-%s-%s-%s", releaseType, version, osType, arch)
	fmt.Printf("Getting binary %s...\n", fileName)
	fmt.Println("Will save to", filepath.Join(BinaryPath, string(releaseType), version))
	url := fmt.Sprintf("%s/%s", BaseReleaseURL, fileName)

	if !DoesRemoteFileExist(url) {
		fmt.Printf("the release file %s does not exist on the release server\n", fileName)
		os.Exit(1)
	}

	return DownloadReleaseFile(releaseType, fileName, version, true)
}

// GetLatestVersion fetches the latest version from the releases API
func GetLatestVersion(releaseType ReleaseType) (string, error) {
	// Determine the appropriate URL based on the release type
	releaseURL := fmt.Sprintf("%s/release", BaseReleaseURL)
	if releaseType == ReleaseTypeQClient {
		releaseURL = fmt.Sprintf("%s/qclient-release", BaseReleaseURL)
	}

	resp, err := http.Get(releaseURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest version: %w", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() {
		return "", fmt.Errorf("no response data found")
	}

	// Get the first line which contains the filename
	filename := scanner.Text()

	// Split the filename by "-" and get the version part
	parts := strings.Split(filename, "-")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid filename format: %s", filename)
	}

	// The version is the second part (index 1)
	version := parts[1]
	return version, nil
}

// DownloadReleaseFile downloads a release file from the Quilibrium releases server
func DownloadReleaseFile(releaseType ReleaseType, fileName string, version string, showError bool) error {
	url := fmt.Sprintf("%s/%s", BaseReleaseURL, fileName)
	destDir := filepath.Join(BinaryPath, string(releaseType), version)
	os.MkdirAll(destDir, 0755)
	destPath := filepath.Join(destDir, fileName)

	fmt.Printf("Downloading %s...", fileName)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if showError {
			return fmt.Errorf("failed to download file: %s", resp.Status)
		} else {
			return nil
		}
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	fmt.Print(" done\n")
	return nil
}

// DownloadReleaseSignatures downloads signature files for a release
func DownloadReleaseSignatures(releaseType ReleaseType, version string) error {
	var files []string
	baseName := fmt.Sprintf("%s-%s-%s-%s", releaseType, version, osType, arch)
	fmt.Printf("Searching for signatures for %s from %s\n", baseName, BaseReleaseURL)
	fmt.Println("Will save to", filepath.Join(BinaryPath, string(releaseType), version))

	// Add digest file URL
	files = append(files, baseName+".dgst")

	// Add signature file URLs
	signerNums := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}
	for _, num := range signerNums {
		// Check if the remote signature file exists
		sigFile := fmt.Sprintf("%s.dgst.sig.%d", baseName, num)
		remoteURL := fmt.Sprintf("%s/%s", BaseReleaseURL, sigFile)

		if !DoesRemoteFileExist(remoteURL) {
			continue
		}
		fmt.Printf("Found signature file %s\n", sigFile)
		files = append(files, fmt.Sprintf("%s.dgst.sig.%d", baseName, num))
	}

	if len(files) == 0 {
		fmt.Printf("No signature files found for %s\n", baseName)
		return nil
	}

	for _, file := range files {
		err := DownloadReleaseFile(releaseType, file, version, false)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetLatestReleaseFiles fetches the list of available release files
func GetLatestReleaseFiles(releaseType ReleaseType) ([]string, error) {
	releaseURL := fmt.Sprintf("%s/release", BaseReleaseURL)
	if releaseType == ReleaseTypeQClient {
		releaseURL = fmt.Sprintf("%s/qclient-release", BaseReleaseURL)
	}
	resp, err := http.Get(releaseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch releases: %s", resp.Status)
	}

	// Read the response body and parse it
	var releases []string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		releases = append(releases, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return releases, nil
}

// FilterReleasesByOSArch filters releases by OS and architecture
func FilterReleasesByOSArch(releases []string, osType, arch string) []string {
	var filtered []string
	for _, release := range releases {
		if strings.Contains(release, osType) && strings.Contains(release, arch) {
			filtered = append(filtered, release)
		}
	}
	return filtered
}

// ExtractVersionFromFileName extracts the version from a release filename
func ExtractVersionFromFileName(releaseType ReleaseType, fileName, osType, arch string) string {
	version := strings.TrimPrefix(fileName, string(releaseType)+"-")
	version = strings.TrimSuffix(version, "-"+osType+"-"+arch)
	return version
}

// DownloadAllReleaseFiles downloads all release files
func DownloadAllReleaseFiles(releaseType ReleaseType, fileNames []string, installDir string) bool {
	for _, fileName := range fileNames {
		filePath := filepath.Join(installDir, fileName)
		if err := DownloadReleaseFile(releaseType, fileName, filePath, true); err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading release file %s: %v\n", fileName, err)
			return false
		}
	}
	return true
}

func DoesRemoteFileExist(url string) bool {
	resp, err := http.Head(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	return true
}
