#!/bin/bash
set -e

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
    echo ""
    echo "If no arguments are provided, runs tests on all supported distributions"
    exit 0
}

# Parse command line arguments
DISTRO=""
VERSION=""
TAG=""
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
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Build the client binary using Dockerfile.qclient
echo "Building client binary using Dockerfile.qclient..."
docker build -t quil-qclient-builder -f Dockerfile.qclient ..
docker create --name quil-qclient-temp quil-qclient-builder
docker cp quil-qclient-temp:/usr/local/bin/qclient ./qclient
docker rm quil-qclient-temp

# Function to run tests for a specific distribution
run_distro_test() {
    local distro=$1
    local version=$2
    local tag=$3
    echo "Testing on $distro $version..."
    docker build \
        --build-arg DISTRO=$distro \
        --build-arg VERSION=$version \
        -t quil-test-$tag \
        -f Dockerfile .
    docker run --rm quil-test-$tag
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
