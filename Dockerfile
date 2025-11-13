# Dockerfile for building RP2350 embedded cryptography firmware
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc-arm-none-eabi \
    libnewlib-arm-none-eabi \
    libstdc++-arm-none-eabi-newlib \
    git \
    python3 \
    python3-pip \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Rust and ARM target
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add thumbv8m.main-none-eabihf

# Install cbindgen for generating C bindings from Rust
RUN cargo install cbindgen

# Set working directory
WORKDIR /build

# Default command (can be overridden)
CMD ["/bin/bash"]
