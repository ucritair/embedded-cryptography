#!/bin/bash

# Docker build script for RP2350 firmware
# Builds firmware in Docker container with source mounted from host

set -e  # Exit on error

# --- Firmware Version ---
FIRMWARE_VERSION_MAJOR=1
FIRMWARE_VERSION_MINOR=0
FIRMWARE_VERSION_PATCH=5

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Parse arguments
DOCKER_IMAGE_NAME="rp2350-builder"
CLEAN_BUILD=""
REBUILD_IMAGE=""
LOCAL_BUILD_ONLY=""

for arg in "$@"; do
    case $arg in
        --rebuild-image)
            REBUILD_IMAGE="yes"
            ;;
        clean)
            CLEAN_BUILD="yes"
            ;;
        --local)
            # Hidden flag for internal use by Docker container
            LOCAL_BUILD_ONLY="yes"
            ;;
        *)
            echo -e "${RED}Unknown argument: $arg${NC}"
            echo "Usage: $0 [--rebuild-image] [clean]"
            echo "  --rebuild-image  Rebuild Docker image"
            echo "  clean            Perform clean build"
            exit 1
            ;;
    esac
done

# If --local flag (internal use only), skip Docker and do local build
if [ "$LOCAL_BUILD_ONLY" == "yes" ]; then
    echo -e "${BLUE}=== RP2350 Local Build ===${NC}"

    # Get the script directory (embedded-cryptography/)
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

    # Check for "clean" argument FIRST (before building)
    if [ "$CLEAN_BUILD" == "yes" ]; then
        echo "--- Performing a clean build ---"
        echo "Cleaning Rust build artifacts..."
        cargo clean --target=thumbv8m.main-none-eabihf --release
        echo "Cleaning CMake build directory..."
        rm -rf rp2350/build
    fi

    # 1. Build the Rust crypto library first
    echo "Building Rust crypto library..."
    cargo build --target=thumbv8m.main-none-eabihf --no-default-features --features "ffi, alloc" --release

    # Exit if the rust build failed
    if [ $? -ne 0 ]; then
        echo "Rust build failed. Exiting."
        exit 1
    fi

    # Create build directory if it doesn't exist, and enter it
    mkdir -p rp2350/build
    cd rp2350/build

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
        echo -e "${GREEN}Built: rp2350/build/$RENAMED_FILE${NC}"
    elif [ -f "$RENAMED_FILE" ]; then
        echo -e "${GREEN}Built: rp2350/build/$RENAMED_FILE${NC}"
    else
        echo "Error: Build failed, could not find $OUTPUT_FILE or $RENAMED_FILE"
        exit 1
    fi

    exit 0
fi

# Docker build path (default)
echo -e "${BLUE}=== RP2350 Docker Build ===${NC}"

# Get the script directory (embedded-cryptography/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

# Initialize git submodules if not already initialized
echo -e "${BLUE}Checking git submodules...${NC}"
if git submodule status | grep -q '^-'; then
    echo -e "${YELLOW}Submodules not initialized. Initializing...${NC}"
    git submodule update --init --recursive
    echo -e "${GREEN}Submodules initialized${NC}"
else
    echo -e "${GREEN}Submodules already initialized${NC}"
fi

# Build Docker image if needed
if [ "$REBUILD_IMAGE" == "yes" ] || ! docker image inspect $DOCKER_IMAGE_NAME &> /dev/null; then
    echo -e "${BLUE}Building Docker image...${NC}"
    docker build -t $DOCKER_IMAGE_NAME "$SCRIPT_DIR"
    echo -e "${GREEN}Docker image built successfully${NC}"
fi

# Prepare build arguments
BUILD_ARGS=""
if [ "$CLEAN_BUILD" == "yes" ]; then
    BUILD_ARGS="clean"
    echo -e "${BLUE}Performing clean build...${NC}"
fi

# Run the build inside Docker container
echo -e "${BLUE}Running build inside Docker container...${NC}"
docker run --rm \
    -v "$SCRIPT_DIR:/build" \
    -w /build \
    $DOCKER_IMAGE_NAME \
    bash -c "./build.sh --local $BUILD_ARGS"

# Show results
if [ $? -eq 0 ]; then
    echo -e "${GREEN}=== Build Complete ===${NC}"
    FIRMWARE_VERSION="v${FIRMWARE_VERSION_MAJOR}.${FIRMWARE_VERSION_MINOR}.${FIRMWARE_VERSION_PATCH}"
    echo -e "Firmware output: ${GREEN}rp2350/build/app/cat_rp2350_${FIRMWARE_VERSION}.uf2${NC}"
    ls -lh "$SCRIPT_DIR/rp2350/build/app/"*.uf2 2>/dev/null || echo "No .uf2 file found"
else
    echo -e "${RED}=== Build Failed ===${NC}"
    exit 1
fi
