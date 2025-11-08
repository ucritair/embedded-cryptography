#ifndef PSRAM_CONFIG_H
#define PSRAM_CONFIG_H

#include "hardware/gpio.h"
#include "hardware/structs/xip_ctrl.h"

// Base address of the PSRAM/Flash mapped in XIP (cached)
// 0x15000000 for uncached
#define PSRAM_BASE_ADDRESS   0x11000000
#define UCPSRAM_BASE_ADDRESS 0x15000000

// Size of the PSRAM (8 MB = 8 * 1024 * 1024 bytes)
#define PSRAM_SIZE_BYTES (8 * 1024 * 1024)

// PSRAM Memory Layout (8MB total):
// ┌─────────────────────────────────────────┐ 0x11000000
// │ Rust Heap (6MB)                         │
// │ For dynamic crypto allocations          │
// ├─────────────────────────────────────────┤ 0x11600000
// │ Shared Memory (1MB)                     │
// │ For Core0 <-> Core1 communication       │
// ├─────────────────────────────────────────┤ 0x11700000
// │ Core1 Stack (1MB)                       │
// │ Stack grows downward from top           │
// └─────────────────────────────────────────┘ 0x117FFFFF

// Rust heap: 6MB for dynamic crypto operations
#define RUST_HEAP_BASE      PSRAM_BASE_ADDRESS
#define RUST_HEAP_SIZE      (6 * 1024 * 1024)

// Shared memory: 1MB for inter-core communication
#define SHARED_MEM_BASE     (RUST_HEAP_BASE + RUST_HEAP_SIZE)
#define SHARED_MEM_SIZE     (1 * 1024 * 1024)

// Core1 stack: 1MB at top of PSRAM
#define PSRAM_STACK_SIZE    (1 * 1024 * 1024)
#define PSRAM_STACK_BOT     (SHARED_MEM_BASE + SHARED_MEM_SIZE)
#define PSRAM_STACK_TOP     (PSRAM_STACK_BOT + PSRAM_STACK_SIZE - 1)

// RP2350B pin 58 is GPIO 47
// GPIO 47 as CS
#define PSRAM_CS_PIN 47

// Pointers to PSRAM regions
extern uint8_t* psram;
extern uint8_t* uc_psram;

// Initialize PSRAM hardware
static inline void init_psram(void)
{
    gpio_set_function(PSRAM_CS_PIN, GPIO_FUNC_XIP_CS1); // Set GPIO 47 as CS pin
    xip_ctrl_hw->ctrl |= XIP_CTRL_WRITABLE_M1_BITS;     // Configure XIP controller for writable M1 region
}

#endif // PSRAM_CONFIG_H
