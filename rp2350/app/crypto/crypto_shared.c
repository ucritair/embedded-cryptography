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
