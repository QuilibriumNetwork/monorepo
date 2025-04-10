# Quil Test Runner Documentation

This document describes the usage and functionality of the Quil test runner script (`run_tests.sh`), which is designed to run tests across different Linux distributions using Docker containers.

## Overview

The test runner allows you to:
- Run tests on multiple Linux distributions simultaneously
- Test on a specific distribution and version
- Customize container tags for test runs
- Build the client binary using a standardized Docker build process

## Prerequisites

- Docker installed and running on your system
- Bash shell
- Access to the Quil client source code
- Sufficient disk space for building the client (approximately 2GB recommended)

## Build Environment

The test runner uses a multi-stage build process based on `Dockerfile.qclient` which includes:

### Base Build Environment
- Ubuntu 24.04 as the base image
- Essential build tools (gcc, g++, make, etc.)
- GMP 6.2 and MPFR libraries
- Go 1.22.0 (amd64)
- Rust toolchain (via rustup)
- FLINT library (version 3.0)
- uniffi-bindgen-go (v0.2.1+v0.25.0)

### Build Process
1. Generates Rust bindings for:
   - VDF (Verifiable Delay Function)
   - BLS48581 (Boneh-Lynn-Shacham signature scheme)
   - VerEnc (Verifiable Encryption)
2. Builds and installs:
   - qclient binary

## Usage

### Basic Usage

To run tests on all supported distributions (Ubuntu 22.04, Ubuntu 24.04, and Debian 12):

```bash
./run_tests.sh
```

### Custom Test Configuration

To run tests on a specific distribution and version:

```bash
./run_tests.sh -d DISTRO -v VERSION [-t TAG]
```

#### Parameters:
- `-d, --distro`: The Linux distribution to test (e.g., ubuntu, debian)
- `-v, --version`: The version of the distribution (e.g., 22.04, 12)
- `-t, --tag`: (Optional) Custom tag for the test container. If not provided, a tag will be automatically generated

#### Examples:

```bash
# Test Ubuntu 22.04 with auto-generated tag
./run_tests.sh -d ubuntu -v 22.04

# Test Debian 12 with custom tag
./run_tests.sh -d debian -v 12 -t my-custom-test

# Show help message
./run_tests.sh --help
```

## Supported Distributions

By default, the script tests the following distributions:
- Ubuntu 22.04
- Ubuntu 24.04
- Debian 12

## How It Works

1. The script first builds the client binary using `Dockerfile.qclient`:
   - Creates a build container with all required dependencies
   - Generates necessary Rust bindings
   - Builds the qclient binary
   - Extracts the binary to the test directory
   - Cleans up the build container

2. For each test run:
   - Creates a Docker container using the specified distribution and version
   - Copies the built client binary into the test container
   - Builds the test environment
   - Runs the tests
   - Cleans up the container after completion

## Error Handling

- The script uses `set -e` to exit on any error
- If any test fails, the script will exit with status code 1
- Docker containers are automatically removed after test completion using the `--rm` flag
- Build errors in `Dockerfile.qclient` will be clearly displayed in the output

## Notes

- When running all tests simultaneously, the script uses background processes to parallelize the test runs
- The script automatically generates container tags if not specified, using the format `distroversion` (e.g., `ubuntu2204`)
- Make sure you have sufficient system resources when running multiple tests simultaneously
- The build process requires significant disk space due to the multi-stage build and dependencies
- The client binary is built specifically for amd64 architecture

## Troubleshooting

If you encounter issues:

1. Ensure Docker is running:
   ```bash
   systemctl status docker
   ```

2. Check Docker logs for container-specific issues:
   ```bash
   docker logs quil-test-[tag]
   ```

3. Verify you have sufficient disk space and memory for running multiple containers

4. For build-related issues:
   - Check if all required dependencies are available in the target distribution
   - Verify the build environment has sufficient resources
   - Check the build logs for specific error messages
   - Ensure you're running on an amd64 system or using appropriate Docker platform settings

## Direct Docker Build

If you just want to build the qclient in a Docker container without running the tests (useful if you can't build for the target testing environment):

```bash
# in the project root directory
## Will take awhile to build flint on initial build
sudo task build_qclient_amd64_linux
sudo task build_qclient_arm64_linux
# for mac, you will need to build on a mac
```

## Run a test container

```
sudo docker run -it \
   -v "/home/user/ceremonyclient/client/test/:/app" \ 
   -v "/home/user/ceremenoyclient/client/build/amd64_linux/qclient:/opt/quilibrium/bin/qclient" \
   quil-test /bin/bash


This command builds the Docker image with the qclient binary according to the specifications in `Dockerfile.source`. The resulting image will be tagged as `qclient`.

## Contributing

When adding new distributions or versions:
1. Update the default test configurations in the script
2. Ensure the corresponding Dockerfile supports the new distribution/version
3. Test the changes thoroughly before committing
