#ifndef BUFFER_CONFIG_H
#define BUFFER_CONFIG_H

/**
 * @file buffer_config.h
 * @brief Centralized buffer size configuration for SRAM and PSRAM usage
 * 
 * This file contains all buffer size definitions used throughout the application.
 * Modify these values to adjust memory usage based on available SRAM/PSRAM.
 */

// =============================================================================
// HTTP CLIENT BUFFERS (SRAM)
// =============================================================================

/** HTTP response buffer size - must fit largest expected response */
#define HTTP_RESPONSE_BUFFER_SIZE       21000   // 21KB for JSON config (20625 bytes actual)

// =============================================================================
// TFHE CRYPTOGRAPHY BUFFERS
// =============================================================================

/** Base64-encoded TFHE public key size */
#define TFHE_PUBLIC_KEY_B64_SIZE        20480   // 20KB (actual key is 20476 bytes)

/** Binary TFHE public key size (after base64 decode) */
#define TFHE_PUBLIC_KEY_BINARY_SIZE     16384   // 16KB (decoded ~15KB)

/** Base64-encoded ciphertext size per sensor */
#define TFHE_CIPHERTEXT_B64_SIZE        24576   // 24KB per ciphertext

// =============================================================================
// SHARED MEMORY BUFFERS (PSRAM)
// =============================================================================

/** TFHE public key buffer in shared memory */
#define SHARED_TFHE_PK_B64_SIZE         24576   // 24KB

/** Number of sensor ciphertext slots */
#define SHARED_CIPHERTEXT_SLOTS         5

/** Size of each ciphertext slot in shared memory */
#define SHARED_CIPHERTEXT_SIZE          24576   // 24KB each

// =============================================================================
// NETWORK CONFIGURATION
// =============================================================================

/** TCP receive window size (affects large response handling) */
#define TCP_RECEIVE_WINDOW_SIZE         (24 * 1024)    // 24KB

#endif // BUFFER_CONFIG_H
