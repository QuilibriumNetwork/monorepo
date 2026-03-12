#!/bin/bash
set -e


# Source the test utilities
source "$(dirname "$0")/test_utils.sh"

# Get distribution information
DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
VERSION=$(lsb_release -sr 2>/dev/null || echo "Unknown")

echo "Starting Quilibrium node installation test on $DISTRO $VERSION..."

# Test: Link the qclient binary to ensure it's in the PATH
echo "Linking qclient binary for testing..."
if [ -f "/opt/quilibrium/bin/qclient" ]; then
    echo "qclient binary already exists at /opt/quilibrium/bin/qclient"
else
    echo "qclient binary not found at /opt/quilibrium/bin/qclient"
    exit 1
fi

# Test: Link the qclient binary to the system PATH
echo "Testing qclient link command..."
run_test_with_format "sudo /opt/quilibrium/bin/qclient link"

# Verify qclient is now in PATH
echo "Verifying qclient is in PATH after link command..."
run_test_with_format "which qclient" | grep -q "/usr/local/bin/qclient" && echo "SUCCESS: qclient found in PATH" || echo "FAILURE: qclient not found in PATH"

# Test qclient can be executed directly
echo "Testing qclient can be executed directly..."
run_test_with_format "qclient --help" | grep -q "Usage:" && echo "SUCCESS: qclient executable works" || echo "FAILURE: qclient executable not working properly"


# Test: Ensure no config file exists initially
echo "Testing no config file exists initially..."
run_test_with_format "test ! -f /etc/quilibrium/config/qclient.yaml"

# Test: Create default config
echo "Testing default config creation..."
run_test_with_format "qclient config create-default --signature-check=false"

# Test: Verify config file was created
echo "Verifying config file was created..."
run_test_with_format "test -f /etc/quilibrium/config/qclient.yaml"

# Test: Excec arbitrary qclient command and verify signature check
echo "Testing config print command..."
run_test_with_format "qclient config print" | grep -v "Checking signature for"

# Test: Toggle signature check
echo "Testing toggle-signature-check command..."
run_test_with_format "qclient config toggle-signature-check --signature-check=false"
run_test_with_format "qclient config print" | grep -v "Checking signature for"


# Test: Ensure qclient is in the PATH
echo "Testing qclient in PATH..."
run_test_with_format "sudo /opt/quilibrium/bin/qclient link"
run_test_with_format "which qclient"
run_test_with_format "qclient version"

run_test_with_format "qclient config print"


# Test 0: Install latest version
# Check if download-signatures command exists in qclient help
run_test_with_format "qclient help | grep -q 'download-signatures'"

# Test downloading signatures
run_test_with_format "sudo qclient download-signatures"

# Test 1: Install latest version
run_test_with_format "sudo qclient node install"

get_latest_version() {
    # Fetch the latest version from the releases API
    local latest_version=$(curl -s https://releases.quilibrium.com/release | head -n 1 | cut -d'-' -f2)
    echo "$latest_version"
}

LATEST_VERSION=$(get_latest_version)

# Verify installation
run_test_with_format "test -f /opt/quilibrium/$LATEST_VERSION/node-$LATEST_VERSION-linux-amd64"

# Verify latest version matches
run_test_with_format "get_latest_version"

# Test 2: Install specific version
run_test_with_format "qclient node install '2.0.6.2' --signature-check=false"

# Verify specific version installation
run_test_with_format "test -f /opt/quilibrium/2.0.6.2/node-2.0.6.2-linux-amd64"

# Test 3: Verify service file creation
run_test_with_format "test -f /etc/systemd/system/quilibrium-node.service"

# Verify service file content
run_test_with_format "grep -q 'EnvironmentFile=/etc/default/quilibrium-node' /etc/systemd/system/quilibrium-node.service"

# Test 4: Verify environment file
run_test_with_format "test -f /etc/default/quilibrium-node"

# Verify environment file permissions
run_test_with_format "test '$(stat -c %a /etc/default/quilibrium-node)' = '640'"

# Test 5: Verify data directory
run_test_with_format "test -d /var/lib/quilibrium"

# Verify data directory permissions
run_test_with_format "test '$(stat -c %a /var/lib/quilibrium)' = '755'"

# Test 6: Verify config file
run_test_with_format "test -f /var/lib/quilibrium/config/node.yaml"

# Verify config file permissions
run_test_with_format "test '$(stat -c %a /var/lib/quilibrium/config/node.yaml)' = '644'"

# Test 7: Verify binary symlink
run_test_with_format "test -L /usr/local/bin/quilibrium-node"

# Test 8: Verify binary execution
run_test_with_format "quilibrium-node --version"

echo "All tests passed successfully on $DISTRO $VERSION!" 