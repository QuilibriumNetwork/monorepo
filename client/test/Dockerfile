# Use build argument to specify the base image
ARG DISTRO=ubuntu
ARG VERSION=24.04

# Use the specified distribution as the base image
FROM --platform=$BUILDPLATFORM ${DISTRO}:${VERSION}

ARG TARGETARCH
ARG TARGETOS

RUN echo "TARGETARCH: $TARGETARCH"
RUN echo "TARGETOS: $TARGETOS"

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for testing
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy the client binary and test script
COPY build/qclient/${TARGETARCH}_${TARGETOS}/qclient /opt/quilibrium/bin/qclient
COPY test_install.sh /app/

# Set permissions
RUN chmod +x /opt/quilibrium/bin/qclient /app/test_install.sh

# Switch to test user
USER testuser

# Run the test script
CMD ["/app/test_install.sh"] 