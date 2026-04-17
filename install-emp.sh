#!/bin/bash

TOOLS=("emp-tool" "emp-ot")

if [ "$(uname)" == "Darwin" ]; then
    brew install openssl pkg-config cmake
else
    if command -v apt-get >/dev/null; then
        sudo apt-get update
        sudo apt-get install -y software-properties-common cmake git build-essential libssl-dev
    elif command -v yum >/dev/null; then
        sudo yum install -y python3 gcc make git cmake gcc-c++ openssl-devel
    else
        echo "System not supported yet!"
    fi
fi

for tool in ${TOOLS[@]};do
    cd $tool
    # Drop stale configure output (e.g. host paths after repo move or COPY into Docker).
    rm -rf CMakeCache.txt CMakeFiles Makefile cmake_install.cmake CTestTestfile.cmake install_manifest.txt
    cmake .
    make -j4
    make install
    cd ..
    echo "Successfully installed $tool"
done
