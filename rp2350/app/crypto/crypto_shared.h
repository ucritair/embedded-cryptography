#ifndef CRYPTO_SHARED_H
#define CRYPTO_SHARED_H

#include <stdint.h>
#include <stdbool.h>
#include "psram_config.h"
#include "buffer_config.h"

// Shared memory structure for Core0 <-> Core1 communication
// Lives at the start of the SHARED_MEM region in PSRAM
typedef struct {
    // Output from parent computation
    uint8_t parent[32];

    // Inputs for proof generation (base64 encoded)
    char witness_b64[32768];  // Max 24KB witness
    char nonce_b64[64];       // 32 bytes base64 = ~44 chars
    char secret_b64[128];     // Base64 secret (64 bytes -> ~88 chars base64)

    // Output from proof generation (binary)
    uint8_t proof[435898];    // ~425KB buffer for binary proof
    size_t proof_len;

    // Base64 encoded proof (for sending to server)
    // ~425KB binary -> ~567KB base64
    char proof_b64[579746];   // ~566KB buffer for base64 proof
    size_t proof_b64_len;

    // TFHE encryption inputs/outputs (for sensor data)
    char tfhe_pk_b64[SHARED_TFHE_PK_B64_SIZE];      // Base64 TFHE public key
    uint32_t sensor_values[5];    // 5 sensor values to encrypt
    char ct_b64[SHARED_CIPHERTEXT_SLOTS][SHARED_CIPHERTEXT_SIZE];        // 5 base64-encoded ciphertexts
    size_t ct_b64_lens[5];        // Length of each base64 ciphertext

    // Control flags
    volatile bool compute_done;
    volatile int error_code;
} crypto_shared_t;

// Place shared memory at the start of SHARED_MEM region
#define CRYPTO_SHARED_ADDR SHARED_MEM_BASE

// Global pointer to shared memory
extern crypto_shared_t *crypto_shared;

// Core1 entry points
void core1_compute_parent_entry(void);
void core1_generate_proof_entry(void);
void core1_tfhe_encrypt_sensors_entry(void);

#endif // CRYPTO_SHARED_H
