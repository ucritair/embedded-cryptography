cmake_minimum_required(VERSION 3.13)

# Set the SDK path directly to the local submodule
set(PICO_SDK_PATH ${CMAKE_CURRENT_SOURCE_DIR}/pico-sdk)

# Pull in SDK (must be before project)
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)

project(pico_top_level_project C CXX ASM)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# --- TinyFrame ---
add_library(tinyframe STATIC
    TinyFrame/TinyFrame.c
)
target_include_directories(tinyframe PUBLIC
    TinyFrame
    src
)

# Add the subdirectory for our project
add_subdirectory(src)