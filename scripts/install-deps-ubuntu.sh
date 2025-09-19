#!/bin/bash

sudo apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    cmake \
    libgmp-dev \
    libmpfr-dev \
    libmpfr6 \
    wget \
    m4 \
    pkg-config \
    gcc \
    g++ \
    make \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    python3 \
    python-is-python3 \
    wget

sudo apt update && apt install -y wget && \
ARCH=$(dpkg --print-architecture) && \
case ${ARCH} in \
    amd64) GOARCH=amd64 ;; \
    arm64) GOARCH=arm64 ;; \
    *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
esac && \
wget https://go.dev/dl/go1.23.5.linux-${GOARCH}.tar.gz && \
sudo rm -rf /usr/local/go && \
sudo tar -C /usr/local -xzf go1.23.5.linux-${GOARCH}.tar.gz && \
rm go1.23.5.linux-${GOARCH}.tar.gz

git clone https://github.com/flintlib/flint.git && \
cd flint && \
git checkout flint-3.0 && \
./bootstrap.sh && \
./configure \
    --prefix=/usr/local \
    --with-gmp=/usr/local \
    --with-mpfr=/usr/local \
    --enable-static \
    --disable-shared \
    CFLAGS="-O3" && \
make && \
sudo make install && \
cd .. && \
rm -rf flint

./docker/rustup-init.sh -y --profile minimal

cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0

python emp-install.py --install --tool --ot

cd emp-tool && \
sed -i 's/add_library(${NAME} SHARED ${sources})/add_library(${NAME} STATIC ${sources})/g' CMakeLists.txt && \
mkdir build && \
cd build && \
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
cd .. && \
make && \
sudo make install && \
cd ..

cd emp-ot && \
mkdir build && \
cd build && \
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
cd .. && \
make && \
sudo make install && \
cd ..

cd vdf && \
./generate.sh && \
cd ..

cd ferret && \
./generate.sh && \
cd ..

cd bls48581 && \
./generate.sh && \
cd ..

cd bulletproofs && \
./generate.sh && \
cd ..

cd verenc && \
./generate.sh && \
cd ..

echo "Source dependencies installed."
