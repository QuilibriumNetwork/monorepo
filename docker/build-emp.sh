#!/bin/bash
set -euo pipefail

# Dependencies are installed by the Docker base stage. Build each in-tree
# toolkit once, out of tree, preserving static linkage and caller CFLAGS.
# CMake variables must remain literal in the replacement.
# shellcheck disable=SC2016
sed -i 's/add_library(${NAME} SHARED ${sources})/add_library(${NAME} STATIC ${sources})/g' emp-tool/CMakeLists.txt
for tool in emp-tool emp-ot; do
    cmake -S "$tool" -B "$tool/build" -DCMAKE_INSTALL_PREFIX=/usr/local
    cmake --build "$tool/build" --parallel "$(nproc)"
    cmake --install "$tool/build"
done
