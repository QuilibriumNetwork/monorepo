#!/bin/bash
set -e

# Get distribution information
DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
VERSION=$(lsb_release -sr 2>/dev/null || echo "Unknown")

echo "Starting Quilibrium node installation test on $DISTRO $VERSION..."

# Test 1: Install latest version
echo "Test 1: Installing latest version..."
qclient node install

get_latest_version() {
    # Fetch the latest version from the releases API
    local latest_version=$(curl -s https://releases.quilibrium.com/release | head -n 1 | cut -d'-' -f2)

    echo "$latest_version"
}

LATEST_VERSION=$(get_latest_version)

# Verify installation
echo "Verifying installation..."
if [ ! -f "/opt/quilibrium/$LATEST_VERSION/node-$LATEST_VERSION-linux-amd64" ]; then
    echo "Error: Latest version binary not found"
    exit 1
fi

# Verify latest version matches
echo "Verifying latest version matches..."
get_latest_version

# Test 2: Install specific version
echo "Test 2: Installing specific version..."
qclient node install "2.0.6.2"

# Verify specific version installation
echo "Verifying specific version installation..."
if [ ! -f "/opt/quilibrium/2.0.6.2/node-2.0.6.2-linux-amd64" ]; then
    echo "Error: Specific version binary not found"
    exit 1
fi

# Test 3: Verify service file creation
echo "Test 3: Verifying service file creation..."
if [ ! -f "/etc/systemd/system/quilibrium-node.service" ]; then
    echo "Error: Service file not found"
    exit 1
fi

# Verify service file content
echo "Verifying service file content..."
if ! grep -q "EnvironmentFile=/etc/default/quilibrium-node" /etc/systemd/system/quilibrium-node.service; then
    echo "Error: Service file missing EnvironmentFile directive"
    exit 1
fi

# Test 4: Verify environment file
echo "Test 4: Verifying environment file..."
if [ ! -f "/etc/default/quilibrium-node" ]; then
    echo "Error: Environment file not found"
    exit 1
fi

# Verify environment file permissions
echo "Verifying environment file permissions..."
if [ "$(stat -c %a /etc/default/quilibrium-node)" != "640" ]; then
    echo "Error: Environment file has incorrect permissions"
    exit 1
fi

# Test 5: Verify data directory
echo "Test 5: Verifying data directory..."
if [ ! -d "/var/lib/quilibrium" ]; then
    echo "Error: Data directory not found"
    exit 1
fi

# Verify data directory permissions
echo "Verifying data directory permissions..."
if [ "$(stat -c %a /var/lib/quilibrium)" != "755" ]; then
    echo "Error: Data directory has incorrect permissions"
    exit 1
fi

# Test 6: Verify config file
echo "Test 6: Verifying config file..."
if [ ! -f "/var/lib/quilibrium/config/node.yaml" ]; then
    echo "Error: Config file not found"
    exit 1
fi

# Verify config file permissions
echo "Verifying config file permissions..."
if [ "$(stat -c %a /var/lib/quilibrium/config/node.yaml)" != "644" ]; then
    echo "Error: Config file has incorrect permissions"
    exit 1
fi

# Test 7: Verify binary symlink
echo "Test 7: Verifying binary symlink..."
if [ ! -L "/usr/local/bin/quilibrium-node" ]; then
    echo "Error: Binary symlink not found"
    exit 1
fi

# Test 8: Verify binary execution
echo "Test 8: Verifying binary execution..."
if ! quilibrium-node --version > /dev/null 2>&1; then
    echo "Error: Binary execution failed"
    exit 1
fi

echo "All tests passed successfully on $DISTRO $VERSION!" 