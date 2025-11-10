#include "crypto_shared.h"
#include "include/battery.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <stdio.h>

// Global shared memory pointer (initialized at runtime after PSRAM init)
crypto_shared_t *crypto_shared = NULL;

// Hardcoded secret (base64: AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==)
// This is 64 bytes representing two concatenated leaves
static const char* SECRET_B64 = "AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==";

// Core1 entry point for computing parent commitment
void core1_compute_parent_entry(void) {
    // Initialize pointer to shared memory (in case it's not set)
    if (crypto_shared == NULL) {
        crypto_shared = (crypto_shared_t*)CRYPTO_SHARED_ADDR;
    }

    printf("[Core1] Starting parent computation\n");

    crypto_shared->compute_done = false;
    crypto_shared->error_code = 0;

    // Decode secret from base64
    uint32_t secret16_u32[16];
    size_t secret_olen = 0;
    int ret = mbedtls_base64_decode(
        (unsigned char*)secret16_u32,
        sizeof(secret16_u32),
        &secret_olen,
        (const unsigned char*)SECRET_B64,
        strlen(SECRET_B64)
    );

    if (ret != 0 || secret_olen != 64) {
        printf("[Core1] Base64 decode failed: ret=%d, len=%zu\n", ret, secret_olen);
        crypto_shared->error_code = -1;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] Secret decoded successfully (%zu bytes)\n", secret_olen);

    // Compute parent using Poseidon2
    uint32_t parent8_u32[8];
    int rc = zkp_parent_from_secret(secret16_u32, parent8_u32);
    if (rc != BATTERY_OK) {
        printf("[Core1] zkp_parent_from_secret failed: %d\n", rc);
        crypto_shared->error_code = -2;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] Parent computed successfully\n");

    // Copy parent to shared memory (8 u32 = 32 bytes)
    memcpy(crypto_shared->parent, parent8_u32, 32);

    crypto_shared->error_code = 0;
    crypto_shared->compute_done = true;

    printf("[Core1] Done, spinning...\n");
    // Spin forever
    while (true) {
        __wfi();  // Wait for interrupt
    }
}

// Core1 entry point for generating ZKP proof
void core1_generate_proof_entry(void) {
    // Initialize pointer to shared memory (in case it's not set)
    if (crypto_shared == NULL) {
        crypto_shared = (crypto_shared_t*)CRYPTO_SHARED_ADDR;
    }

    printf("[Core1] Starting ZKP proof generation\n");

    crypto_shared->compute_done = false;
    crypto_shared->error_code = 0;
    crypto_shared->proof_len = 0;

    // Decode secret from base64
    uint32_t secret16_u32[16];
    size_t secret_olen = 0;
    int ret = mbedtls_base64_decode(
        (unsigned char*)secret16_u32,
        sizeof(secret16_u32),
        &secret_olen,
        (const unsigned char*)SECRET_B64,
        strlen(SECRET_B64)
    );

    if (ret != 0 || secret_olen != 64) {
        printf("[Core1] Secret decode failed: ret=%d, len=%zu\n", ret, secret_olen);
        crypto_shared->error_code = -1;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    // Decode witness from base64 (args for zkp_generate_proof)
    // Allocate on Core1 stack (we have 1MB)
    uint8_t witness_args[65536];  // 64KB buffer
    size_t witness_olen = 0;
    ret = mbedtls_base64_decode(
        witness_args,
        sizeof(witness_args),
        &witness_olen,
        (const unsigned char*)crypto_shared->witness_b64,
        strlen(crypto_shared->witness_b64)
    );

    if (ret != 0) {
        printf("[Core1] Witness decode failed: ret=%d\n", ret);
        crypto_shared->error_code = -2;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] Witness decoded: %zu bytes\n", witness_olen);

    // Decode nonce from base64
    uint8_t nonce32[32];
    size_t nonce_olen = 0;
    ret = mbedtls_base64_decode(
        nonce32,
        sizeof(nonce32),
        &nonce_olen,
        (const unsigned char*)crypto_shared->nonce_b64,
        strlen(crypto_shared->nonce_b64)
    );

    if (ret != 0 || nonce_olen != 32) {
        printf("[Core1] Nonce decode failed: ret=%d, len=%zu\n", ret, nonce_olen);
        crypto_shared->error_code = -3;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] Nonce decoded: %zu bytes\n", nonce_olen);

    uint64_t bench_start, bench_stop;
#define B_START bench_start = time_us_64();
#define B_STOP  bench_stop = time_us_64() - bench_start;

B_START
    // Generate proof
    printf("[Core1] Calling zkp_generate_proof...\n");
    size_t proof_written = 0;
    int rc = zkp_generate_proof(
        secret16_u32,
        witness_args,
        witness_olen,
        nonce32,
        crypto_shared->proof,
        sizeof(crypto_shared->proof),
        &proof_written
    );
B_STOP
    printf("ZKP TOOK %llu \n", bench_stop - bench_start);

    if (rc != BATTERY_OK) {
        printf("[Core1] zkp_generate_proof failed: %d\n", rc);
        crypto_shared->error_code = -4;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] Proof generated: %zu bytes\n", proof_written);
    crypto_shared->proof_len = proof_written;

    crypto_shared->error_code = 0;
    crypto_shared->compute_done = true;

    printf("[Core1] Proof generation complete, spinning...\n");
    // Spin forever
    while (true) {
        __wfi();
    }
}

// Core1 entry point for TFHE encryption of sensor data (5×8 encoding)
void core1_tfhe_encrypt_sensors_entry(void) {
    // Initialize pointer to shared memory
    if (crypto_shared == NULL) {
        crypto_shared = (crypto_shared_t*)CRYPTO_SHARED_ADDR;
    }

    printf("[Core1] Starting TFHE sensor encryption (5×8)\n");
    printf("[Core1] DEBUG: Shared memory pointer: %p\n", crypto_shared);
    printf("[Core1] DEBUG: About to set compute_done = false\n");

    crypto_shared->compute_done = false;
    crypto_shared->error_code = 0;

    // Decode base64 TFHE public key
    uint8_t pk_bytes[8192];
    size_t pk_len = 0;
    int ret = mbedtls_base64_decode(
        pk_bytes,
        sizeof(pk_bytes),
        &pk_len,
        (const unsigned char*)crypto_shared->tfhe_pk_b64,
        strlen(crypto_shared->tfhe_pk_b64)
    );

    if (ret != 0) {
        printf("[Core1] TFHE PK decode failed: %d\n", ret);
        crypto_shared->error_code = -1;
        crypto_shared->compute_done = true;
        while (true) { __wfi(); }
    }

    printf("[Core1] TFHE PK decoded: %zu bytes\n", pk_len);

    // Encrypt each sensor value as a full byte (8 bits), then extract individual bit ciphertexts
    // tfhe_pk_encrypt encodes bits LSB-first, so we need to reverse bit order before encrypting
    for (int sensor_idx = 0; sensor_idx < 5; sensor_idx++) {
        uint32_t sensor_value = crypto_shared->sensor_values[sensor_idx];
        printf("[Core1] Sensor %d = %u (0x%02x)\n", sensor_idx, sensor_value, sensor_value & 0xFF);

        // We want MSB-first in output, but tfhe_pk_encrypt uses LSB-first encoding
        // So we need to bit-reverse the byte before encryption
        uint8_t byte_to_encrypt = (uint8_t)(sensor_value & 0xFF);

        // Bit-reverse: swap bit 0↔7, 1↔6, 2↔5, 3↔4
        uint8_t reversed = 0;
        for (int i = 0; i < 8; i++) {
            if (byte_to_encrypt & (1 << i)) {
                reversed |= (1 << (7 - i));
            }
        }

        printf("[Core1]   Original: 0x%02x, Reversed: 0x%02x\n", byte_to_encrypt, reversed);

        // Generate random seed
        uint8_t seed[32];
        uint64_t rng_seed = time_us_64() + sensor_idx;
        for (int i = 0; i < 32; i++) {
            rng_seed = rng_seed * 1103515245 + 12345;  // LCG
            seed[i] = (uint8_t)(rng_seed >> 8);
        }

        // Encrypt the full byte (8 bits encoded LSB-first into TRLWE)
        uint8_t ct_bytes[8192];
        size_t ct_written = 0;
        ret = tfhe_pk_encrypt(
            pk_bytes, pk_len,
            &reversed, 1,  // Encrypt 1 byte = 8 bits
            seed, 32,
            ct_bytes, sizeof(ct_bytes),
            &ct_written
        );

        if (ret != BATTERY_OK) {
            printf("[Core1] TFHE encrypt failed: sensor=%d, err=%d\n", sensor_idx, ret);
            crypto_shared->error_code = -2;
            crypto_shared->compute_done = true;
            while (true) { __wfi(); }
        }

        printf("[Core1]   Encrypted to %zu bytes\n", ct_written);

        // Base64 encode the ciphertext (one ciphertext per sensor)
        size_t b64_len = 0;
        ret = mbedtls_base64_encode(
            (unsigned char*)crypto_shared->ct_b64[sensor_idx],
            sizeof(crypto_shared->ct_b64[sensor_idx]),
            &b64_len,
            ct_bytes,
            ct_written
        );

        if (ret != 0) {
            printf("[Core1] Base64 encode failed: sensor=%d, err=%d\n", sensor_idx, ret);
            crypto_shared->error_code = -3;
            crypto_shared->compute_done = true;
            while (true) { __wfi(); }
        }

        crypto_shared->ct_b64[sensor_idx][b64_len] = '\0';
        crypto_shared->ct_b64_lens[sensor_idx] = b64_len;

        printf("[Core1]   Base64 encoded: %zu chars\n", b64_len);
    }

    printf("[Core1] All 5 ciphertexts generated successfully\n");
    crypto_shared->error_code = 0;
    crypto_shared->compute_done = true;

    // Spin forever
    while (true) {
        __wfi();
    }
}
