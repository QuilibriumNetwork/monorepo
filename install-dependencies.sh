#!/bin/bash

set -e

# Function to install dependencies
install_dependencies() {
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    # Install dependencies
    if [[ "$OS" == "linux" ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq curl build-essential libgmp-dev wget cpulimit
    elif [[ "$OS" == "darwin" ]]; then
        if ! command -v brew &> /dev/null; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" > /dev/null
        fi
        brew install -q curl gmp wget cpulimit
    else
        echo "Unsupported operating system: $OS"
        exit 1
    fi
}

# Function to install Rust and Go
install_rust_and_go() {
    # Check if Rust is installed
    if ! command -v rustc &> /dev/null; then
        echo "Rust not found. Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
        echo 'export PATH=$PATH:$HOME/.cargo/env' >> $HOME/.bashrc
        echo 'export PATH=$PATH:$HOME/.cargo/env' >> $HOME/.zshrc
    else
        echo "Rust is already installed."
    fi

    # Install uniffi-bindgen-go 
    if ! command -v uniffi-bindgen-go &> /dev/null; then
        echo "uniffi-bindgen-go not found. Installing..."
        cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0
    else
        echo "uniffi-bindgen-go is already installed."
    fi

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo "Go not found. Installing Go..."
        GO_VERSION="1.22.4"
        if [[ "$OS" == "linux" ]]; then
            if [[ "$ARCH" == "x86_64" ]]; then
                GO_ARCH="amd64"
            elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
                GO_ARCH="arm64"
            else
                echo "Unsupported architecture: $ARCH"
                exit 1
            fi
            wget "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
            sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
            rm "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        elif [[ "$OS" == "darwin" ]]; then
            if [[ "$ARCH" == "x86_64" ]]; then
                GO_ARCH="amd64"
            elif [[ "$ARCH" == "arm64" ]]; then
                GO_ARCH="arm64"
            else
                echo "Unsupported architecture: $ARCH"
                exit 1
            fi
            wget "https://go.dev/dl/go${GO_VERSION}.darwin-${GO_ARCH}.tar.gz"
            sudo tar -C /usr/local -xzf "go${GO_VERSION}.darwin-${GO_ARCH}.tar.gz"
            rm "go${GO_VERSION}.darwin-${GO_ARCH}.tar.gz"
        fi

        echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.bashrc
        echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.zshrc
        source $HOME/.bashrc

        # Install grpcurl for RPC testing
        go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
    else
        echo "Go is already installed."
    fi
}

# Run the installation functions
install_dependencies
install_rust_and_go

echo "All dependencies have been installed successfully."
