#!/bin/bash
set -e
CLIENT_DIR="${CLIENT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

echo "CLIENT_DIR: $CLIENT_DIR"

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Run tests on specified Linux distributions"
    echo ""
    echo "Options:"
    echo "  -d, --distro DISTRO    Specify the distribution (e.g., ubuntu, debian)"
    echo "  -v, --version VERSION  Specify the version (e.g., 22.04, 12)"
    echo "  -t, --tag TAG         Specify a custom tag for the test container"
    echo "  -h, --help           Show this help message"
    echo "  --no-cache          Disable all Docker build cache"
    echo ""
    echo "If no arguments are provided, runs tests on all supported distributions"
    exit 0
}

# Parse command line arguments
DISTRO=""
VERSION=""
TAG=""
NO_CACHE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--distro)
            DISTRO="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Function to run tests for a specific distribution
run_distro_test() {
    local distro=$1
    local version=$2
    local tag=$3
    echo "Testing on $distro $version..."
    
    # Build the base stage first (this can be cached)
    docker build \
        $NO_CACHE \
        --build-arg DISTRO=$distro \
        --build-arg VERSION=$version \
        -t quil-test-$tag-base \
        --target base \
        -f client/test/Dockerfile .
    
    # Build the final test stage
    docker build \
        --build-arg DISTRO=$distro \
        --build-arg VERSION=$version \
        -t quil-test-$tag \
        --target qclient-test \
        -f client/test/Dockerfile .
        
    # Ensure test files are executable
    chmod +x "$CLIENT_DIR/test/test_install.sh"
    chmod +x "$CLIENT_DIR/test/test_utils.sh"
    chmod +x "$CLIENT_DIR/build/amd64_linux/qclient"
    
    # Set ownership to match testuser (uid:gid 1000:1000)
    chown 1000:1000 "$CLIENT_DIR/build/amd64_linux/qclient"
    
    # Run the container with mounted test directory and binary
    docker run --rm \
        -v "$CLIENT_DIR/test:/app" \
        -v "$CLIENT_DIR/build/amd64_linux/qclient:/opt/quilibrium/bin/qclient" \
        quil-test-$tag
}

# If custom distro/version/tag is provided, run single test
if [ ! -z "$DISTRO" ] && [ ! -z "$VERSION" ]; then
    if [ -z "$TAG" ]; then
        TAG="${DISTRO}${VERSION//./}"
    fi
    echo "Running custom test configuration..."
    run_distro_test "$DISTRO" "$VERSION" "$TAG"
else
    # Run tests on all distributions simultaneously
    echo "Running tests on all distributions simultaneously..."
    run_distro_test "ubuntu" "22.04" "ubuntu22" &
    UBUNTU22_PID=$!

    run_distro_test "ubuntu" "24.04" "ubuntu24" &
    UBUNTU24_PID=$!

    run_distro_test "debian" "12" "debian12" &
    DEBIAN12_PID=$!

    # Wait for all tests to complete
    wait $UBUNTU22_PID $UBUNTU24_PID $DEBIAN12_PID

    # Check exit status of each test
    if [ $? -ne 0 ]; then
        echo "One or more tests failed!"
        exit 1
    fi
fi

echo "All distribution tests completed!" 
