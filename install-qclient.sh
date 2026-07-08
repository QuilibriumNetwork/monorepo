#!/bin/bash

# Install script for Quilibrium client

# This is intended to be run via url:
# curl -sSL https://raw.githubusercontent.com/QuilibriumNetwork/ceremonyclient/refs/heads/develop/install-qclient.sh | sudo bash

# Check if the script is run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo) to install the Quilibrium client under the system install root and create /usr/local/bin/qclient"
    exit 1
fi

BASE_URL="https://releases.quilibrium.com"

# Legacy pre-FHS-split install root. Used only to detect existing
# installs so we can warn the user; new installs do not land here.
LEGACY_QCLIENT_BIN_DIR="/var/quilibrium/bin/qclient"

# default_install_root prints the OS-appropriate default install root
# for qclient. Matches DefaultQClientInstallDir() in client/utils/paths.go:
#   Linux: /opt/quilibrium  (FHS)
#   macOS: /usr/local/quilibrium (Homebrew-style)
default_install_root() {
    case "$(uname -s)" in
        Darwin) echo "/usr/local/quilibrium" ;;
        *)      echo "/opt/quilibrium" ;;
    esac
}

# Function to detect OS and architecture
detect_os_arch() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case $OS in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    echo "$OS-$ARCH"
}

# Function to get the latest release filename
get_latest_release() {
    local os_arch=$1
    RELEASE_URL="$BASE_URL/qclient-release"
    RELEASE_FILES=$(curl -s "$RELEASE_URL")
    if [ -z "$RELEASE_FILES" ]; then
        exit 1
    fi
    # Filter releases by OS and architecture
    LATEST_FILENAME=$(echo "$RELEASE_FILES" | grep "$os_arch" | head -n 1)
    if [ -z "$LATEST_FILENAME" ]; then
        exit 1
    fi
    # Extract version from filename (e.g., qclient-2.1.0-linux-amd64 -> 2.1.0)
    VERSION=$(echo "$LATEST_FILENAME" | cut -d'-' -f2)
    echo "$VERSION"
}

get_release_files() {
    local os_arch=$1
    RELEASE_URL="$BASE_URL/qclient-release"
    RELEASE_FILES=$(curl -s "$RELEASE_URL")
    if [ -z "$RELEASE_FILES" ]; then
        echo "Failed to fetch release files"
        exit 1
    fi
    # Filter releases by OS and architecture
    echo "$RELEASE_FILES" | grep "$os_arch" | sort -V
}

download_release_file() {
    local filename=$1
    local output_dir=$2
    local dry_run=${3:-false}
    if [ "$dry_run" = true ]; then
        echo "[DRY RUN] Download $filename to $output_dir"
        return
    fi
    printf "Downloading $filename to $output_dir... "
    sudo curl -L -s -o "$output_dir/$filename" "$BASE_URL/$filename"
    if [ $? -ne 0 ]; then
        echo "Failed to download file: $BASE_URL/$filename"
        exit 1
    fi
    printf "done.\n"
}

# Parse command line arguments
DRY_RUN=false
INSTALL_ROOT_OVERRIDE=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            echo "[DRY RUN] enabled"
            shift
            ;;
        --install-dir)
            INSTALL_ROOT_OVERRIDE="$2"
            shift 2
            ;;
        --install-dir=*)
            INSTALL_ROOT_OVERRIDE="${1#*=}"
            shift
            ;;
        -h|--help)
            cat <<EOF
Usage: install-qclient.sh [options]

Options:
  --install-dir PATH  Install root (defaults to /opt/quilibrium on Linux,
                      /usr/local/quilibrium on macOS). Binaries go to
                      <install-dir>/bin/qclient/<version>/.
  --dry-run           Print actions without downloading or modifying files.
  -h, --help          Show this help.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Main script
echo "Detecting OS and architecture..."
OS_ARCH=$(detect_os_arch)
echo "Detected OS and architecture: $OS_ARCH"

LATEST_VERSION=$(get_latest_release "$OS_ARCH")
echo "Latest release version: $LATEST_VERSION"

# Resolve the install root. Precedence:
#   1. --install-dir flag
#   2. OS-appropriate default (Linux: /opt/quilibrium, macOS: /usr/local/quilibrium)
if [ -n "$INSTALL_ROOT_OVERRIDE" ]; then
    INSTALL_ROOT="$INSTALL_ROOT_OVERRIDE"
else
    INSTALL_ROOT="$(default_install_root)"
fi

QCLIENT_BIN_DIR="$INSTALL_ROOT/bin/qclient"
INSTALL_DIR="$QCLIENT_BIN_DIR/$LATEST_VERSION"

echo "Install root: $INSTALL_ROOT"
echo "QClient binary dir: $QCLIENT_BIN_DIR"

# Warn if a pre-FHS-split install is still on disk. Files are NOT moved.
if [ "$QCLIENT_BIN_DIR" != "$LEGACY_QCLIENT_BIN_DIR" ] && [ -d "$LEGACY_QCLIENT_BIN_DIR" ]; then
    echo
    echo "Notice: a legacy qclient install was detected under $LEGACY_QCLIENT_BIN_DIR."
    echo "  This install will use the new default ($QCLIENT_BIN_DIR)."
    echo "  Files under $LEGACY_QCLIENT_BIN_DIR are NOT moved automatically;"
    echo "  remove them manually once you've verified the new install."
    echo
fi

# Ensure the install directory exists
if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] mkdir -p $INSTALL_DIR"
else
    sudo mkdir -p "$INSTALL_DIR"
fi

# Get the list of release files for the detected OS and architecture
echo "Fetching release files for $OS_ARCH..."
RELEASE_FILES=$(get_release_files "$OS_ARCH")

if [ -z "$RELEASE_FILES" ]; then
    echo "No release files found for $OS_ARCH"
    exit 1
fi

QCLIENT_BINARY="qclient-$LATEST_VERSION-$OS_ARCH"

# Loop through the release files and download them
echo "Processing release files..."
while IFS= read -r file; do
    if [ -n "$file" ]; then
       
        FILE_OUTPUT="$INSTALL_DIR/$file"
        download_release_file "$file" "$INSTALL_DIR" "$DRY_RUN"
        if [ $? -ne 0 ]; then
            echo "Failed to download file: $BASE_URL/$file"
            exit 1
        fi
        
        # Make the binary file executable
        if [[ "$file" == "$QCLIENT_BINARY" ]]; then
            if [ "$DRY_RUN" = true ]; then
                echo "[DRY RUN] Make $FILE_OUTPUT executable"
            else
                sudo chmod +x "$FILE_OUTPUT"
            fi
        fi
    fi
done <<< "$RELEASE_FILES"

echo "All release files processed successfully."


if [ "$DRY_RUN" = false ]; then
    # Create a symlink to the latest version
    sudo ln -sf "$INSTALL_DIR/$QCLIENT_BINARY" "/usr/local/bin/qclient"

    echo "Symlink created to the latest version: /usr/local/bin/qclient -> $INSTALL_DIR/$QCLIENT_BINARY"
else
    echo "[DRY RUN] Symlink to be created: /usr/local/bin/qclient -> $INSTALL_DIR/$QCLIENT_BINARY"
fi

echo "Installation complete. You can now start the Quilibrium client with the following command:"
echo "qclient version"
