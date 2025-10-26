#!/bin/bash

# Pico2 WiFi TCP Client Build Script
# Edit these values for your network:
WIFI_SSID="Zaviyar-Home-2G"
WIFI_PASSWORD="ZaviyarWasim"
SERVER_IP="192.168.0.11"

# Check for "clean" argument
if [ "$1" == "clean" ]; then
    echo "--- Performing a clean build ---"
    rm -rf build
fi

# Create build directory if it doesn't exist, and enter it
mkdir -p build
cd build

cmake .. -DPICO_BOARD=pimoroni_pico_plus2_w_rp2350 -DWIFI_SSID="$WIFI_SSID" -DWIFI_PASSWORD="$WIFI_PASSWORD" -DTEST_TCP_SERVER_IP="$SERVER_IP"

make pico_project

echo "Built: pico_project/pico_project.uf2"