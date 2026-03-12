# Use build argument to specify the base image
ARG DISTRO=ubuntu
ARG VERSION=24.04

# Base stage with common setup
FROM --platform=$BUILDPLATFORM ${DISTRO}:${VERSION} AS base

ARG TARGETARCH
ARG TARGETOS

RUN echo "TARGETARCH: $TARGETARCH"
RUN echo "TARGETOS: $TARGETOS"

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    bash-completion \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for testing
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Final test stage
FROM base AS qclient-test
WORKDIR /app


CMD ["/app/test_install.sh"] 