#!/bin/bash

# --- Firmware Version ---
FIRMWARE_VERSION_MAJOR=1
FIRMWARE_VERSION_MINOR=0
FIRMWARE_VERSION_PATCH=4

# Check for "clean" argument FIRST (before building)
if [ "$1" == "clean" ]; then
    echo "--- Performing a clean build ---"
    echo "Cleaning Rust build artifacts..."
    (cd ../ && cargo clean --target=thumbv8m.main-none-eabihf --release)
    echo "Cleaning CMake build directory..."
    rm -rf build
fi

# 1. Build the Rust crypto library first
echo "Building Rust crypto library..."
(cd ../ && \
    cargo build --target=thumbv8m.main-none-eabihf --no-default-features --features "ffi, alloc" --release)

# Exit if the rust build failed
if [ $? -ne 0 ]; then
    echo "Rust build failed. Exiting."
    exit 1
fi

# Create build directory if it doesn't exist, and enter it
mkdir -p build
cd build

cmake .. \
    -DPICO_BOARD=pimoroni_pico_plus2_w_rp2350 \
    -DFIRMWARE_VERSION_MAJOR=$FIRMWARE_VERSION_MAJOR \
    -DFIRMWARE_VERSION_MINOR=$FIRMWARE_VERSION_MINOR \
    -DFIRMWARE_VERSION_PATCH=$FIRMWARE_VERSION_PATCH

make cat_rp2350

# Rename the output file
FIRMWARE_VERSION="v${FIRMWARE_VERSION_MAJOR}.${FIRMWARE_VERSION_MINOR}.${FIRMWARE_VERSION_PATCH}"
OUTPUT_FILE="app/cat_rp2350.uf2"
RENAMED_FILE="app/cat_rp2350_${FIRMWARE_VERSION}.uf2"

if [ -f "$OUTPUT_FILE" ]; then
    mv "$OUTPUT_FILE" "$RENAMED_FILE"
    echo "Built: $RENAMED_FILE"
else
    echo "Error: Build failed, could not find $OUTPUT_FILE"
    exit 1
fi
