cmake_minimum_required(VERSION 3.13)

# Set the SDK path directly to the local submodule
set(PICO_SDK_PATH ${CMAKE_CURRENT_SOURCE_DIR}/pico-sdk)

# Pull in SDK (must be before project)
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)

project(pico_top_level_project C CXX ASM)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# XXX: horrible kludge to fix the pico-sdk hard coding -mfloat-abi=softfp (pico-sdk/cmake/preload/toolchains/pico_arm_cortex_m33_gcc.cmake)
#	we need to change from "softfp" to "hard" to be compatible with the rust compiler settings for the rp2350 platform
string(REPLACE "-mfloat-abi=softfp" "-mfloat-abi=hard" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
string(REPLACE "-mfloat-abi=softfp" "-mfloat-abi=hard" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
string(REPLACE "-mfloat-abi=softfp" "-mfloat-abi=hard" CMAKE_ASM_FLAGS ${CMAKE_ASM_FLAGS})

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