#!/bin/bash

# 1. Build the Rust crypto library first
(cd ../ && \
    cargo build --target=thumbv8m.main-none-eabihf --no-default-features --features "ffi, alloc" --release)

# Exit if the rust build failed
if [ $? -ne 0 ]; then
    echo "Rust build failed. Exiting."
    exit 1
fi


# Check for "clean" argument
if [ "$1" == "clean" ]; then
    echo "--- Performing a clean build ---"
    rm -rf build
fi

# Create build directory if it doesn't exist, and enter it
mkdir -p build
cd build

cmake .. -DPICO_BOARD=pimoroni_pico_plus2_w_rp2350
make pico_project

echo "Built: pico_project/pico_project.uf2"
