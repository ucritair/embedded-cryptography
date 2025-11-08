#include "zkp_auth.h"
#include "battery.h"
#include "httpss_client.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// Auth state storage
typedef struct {
    bool initialized;
    uint32_t secret16_u32[16];          // Device secret (two leaves)
    uint32_t parent8_u32[8];            // Parent commitment
    uint8_t witness[ZKP_WITNESS_MAX];   // Merkle witness from server
    size_t witness_len;
    uint8_t nonce[ZKP_NONCE_SIZE];      // Current epoch nonce
    size_t proof_len;
    char access_token[ZKP_TOKEN_MAX];   // Bearer token
    uint64_t token_expiry;              // Token expiry (epoch timestamp)
    bool has_witness;
    bool has_nonce;
    bool has_proof;
    bool has_token;
} zkp_auth_state_t;

static zkp_auth_state_t auth_state = {0};

int zkp_auth_init(const char* secret_b64) {
    if (!secret_b64) {
        return ZKP_AUTH_ERR_INIT;
    }

    // Decode base64 secret
    size_t olen = 0;
    int ret = mbedtls_base64_decode(
        (unsigned char*)auth_state.secret16_u32,
        sizeof(auth_state.secret16_u32),
        &olen,
        (const unsigned char*)secret_b64,
        strlen(secret_b64)
    );

    if (ret != 0 || olen != 64) {
        printf("[zkp_auth] Failed to decode secret: ret=%d, olen=%zu (expected 64)\n", ret, olen);
        return ZKP_AUTH_ERR_DECODE;
    }

    printf("[zkp_auth] Secret initialized (%zu bytes)\n", olen);
    printf("[zkp_auth] Secret u32[0-3]: %u %u %u %u\n",
           auth_state.secret16_u32[0], auth_state.secret16_u32[1],
           auth_state.secret16_u32[2], auth_state.secret16_u32[3]);

    auth_state.initialized = true;
    auth_state.has_witness = false;
    auth_state.has_nonce = false;
    auth_state.has_proof = false;
    auth_state.has_token = false;

    return ZKP_AUTH_OK;
}

int zkp_auth_compute_parent(char* parent_b64_out, size_t out_len) {
    if (!auth_state.initialized) {
        printf("[zkp_auth] Not initialized\n");
        return ZKP_AUTH_ERR_INIT;
    }

    // Compute parent commitment using Poseidon2
    int rc = zkp_parent_from_secret(auth_state.secret16_u32, auth_state.parent8_u32);
    if (rc != BATTERY_OK) {
        printf("[zkp_auth] zkp_parent_from_secret failed: %d\n", rc);
        return ZKP_AUTH_ERR_PROOF;
    }

    printf("[zkp_auth] Parent commitment (u32[0-3]): %u %u %u %u\n",
           auth_state.parent8_u32[0], auth_state.parent8_u32[1],
           auth_state.parent8_u32[2], auth_state.parent8_u32[3]);

    // Encode parent as base64
    size_t olen = 0;
    int ret = mbedtls_base64_encode(
        (unsigned char*)parent_b64_out,
        out_len,
        &olen,
        (const unsigned char*)auth_state.parent8_u32,
        sizeof(auth_state.parent8_u32)
    );

    if (ret != 0) {
        printf("[zkp_auth] Failed to encode parent: %d\n", ret);
        return ZKP_AUTH_ERR_DECODE;
    }

    printf("[zkp_auth] Parent base64: %s\n", parent_b64_out);
    return ZKP_AUTH_OK;
}

int zkp_auth_get_witness(const char* hostname) {
    if (!auth_state.initialized) {
        return ZKP_AUTH_ERR_INIT;
    }

    // Compute parent commitment
    char parent_b64[128];
    int rc = zkp_auth_compute_parent(parent_b64, sizeof(parent_b64));
    if (rc != ZKP_AUTH_OK) {
        return rc;
    }

    // Request witness from server
    witness_response_t witness_resp = {0};
    int http_rc = balvi_api_get_witness(hostname, parent_b64, &witness_resp);

    if (http_rc != 0 || !witness_resp.valid) {
        printf("[zkp_auth] Failed to get witness from server\n");
        return ZKP_AUTH_ERR_HTTP;
    }

    // Decode witness from base64
    size_t olen = 0;
    int ret = mbedtls_base64_decode(
        auth_state.witness,
        sizeof(auth_state.witness),
        &olen,
        (const unsigned char*)witness_resp.witness_b64,
        strlen(witness_resp.witness_b64)
    );

    if (ret != 0) {
        printf("[zkp_auth] Failed to decode witness: %d\n", ret);
        return ZKP_AUTH_ERR_DECODE;
    }

    auth_state.witness_len = olen;
    auth_state.has_witness = true;

    printf("[zkp_auth] Witness retrieved and decoded (%zu bytes)\n", olen);
    return ZKP_AUTH_OK;
}

int zkp_auth_get_nonce(const char* hostname) {
    if (!auth_state.initialized) {
        return ZKP_AUTH_ERR_INIT;
    }

    // Request nonce from server
    nonce_response_t nonce_resp = {0};
    int http_rc = balvi_api_get_nonce(hostname, &nonce_resp);

    if (http_rc != 0 || !nonce_resp.valid) {
        printf("[zkp_auth] Failed to get nonce from server\n");
        return ZKP_AUTH_ERR_HTTP;
    }

    // Decode nonce from base64
    size_t olen = 0;
    int ret = mbedtls_base64_decode(
        auth_state.nonce,
        sizeof(auth_state.nonce),
        &olen,
        (const unsigned char*)nonce_resp.nonce,
        strlen(nonce_resp.nonce)
    );

    if (ret != 0 || olen != ZKP_NONCE_SIZE) {
        printf("[zkp_auth] Failed to decode nonce: ret=%d, olen=%zu (expected %d)\n",
               ret, olen, ZKP_NONCE_SIZE);
        return ZKP_AUTH_ERR_DECODE;
    }

    auth_state.has_nonce = true;

    printf("[zkp_auth] Nonce retrieved (expires: %s)\n", nonce_resp.expires_at);
    return ZKP_AUTH_OK;
}

int zkp_auth_generate_proof(void) {
    if (!auth_state.initialized) {
        return ZKP_AUTH_ERR_INIT;
    }

    if (!auth_state.has_witness) {
        printf("[zkp_auth] No witness available, call zkp_auth_get_witness() first\n");
        return ZKP_AUTH_ERR_PROOF;
    }

    if (!auth_state.has_nonce) {
        printf("[zkp_auth] No nonce available, call zkp_auth_get_nonce() first\n");
        return ZKP_AUTH_ERR_PROOF;
    }

    printf("[zkp_auth] Generating ZKP proof...\n");

    // Generate proof using witness and nonce
    uint8_t auth_state_proof[ZKP_PROOF_MAX];       // Generated proof bundle
    size_t proof_written = 0;
    int rc = zkp_generate_proof(
        auth_state.secret16_u32,
        auth_state.witness,
        auth_state.witness_len,
        auth_state.nonce,
        auth_state_proof,
        sizeof(auth_state_proof),
        &proof_written
    );

    if (rc != BATTERY_OK) {
        printf("[zkp_auth] zkp_generate_proof failed: %d\n", rc);
        return ZKP_AUTH_ERR_PROOF;
    }

    auth_state.proof_len = proof_written;
    auth_state.has_proof = true;

    printf("[zkp_auth] Proof generated (%zu bytes)\n", proof_written);
    return ZKP_AUTH_OK;
}

int zkp_auth_verify(const char* hostname) {
    if (!auth_state.initialized) {
        return ZKP_AUTH_ERR_INIT;
    }

    if (!auth_state.has_proof) {
        printf("[zkp_auth] No proof available, call zkp_auth_generate_proof() first\n");
        return ZKP_AUTH_ERR_PROOF;
    }

    // Encode nonce and proof as base64 for JSON
    char nonce_b64[128];
    char proof_b64[ZKP_PROOF_MAX * 2];  // Base64 can expand up to 4/3 original size
    size_t olen;

    int ret = mbedtls_base64_encode(
        (unsigned char*)nonce_b64,
        sizeof(nonce_b64),
        &olen,
        auth_state.nonce,
        ZKP_NONCE_SIZE
    );
    if (ret != 0) {
        printf("[zkp_auth] Failed to encode nonce: %d\n", ret);
        return ZKP_AUTH_ERR_DECODE;
    }

    // ret = mbedtls_base64_encode(
    //     (unsigned char*)proof_b64,
    //     sizeof(proof_b64),
    //     &olen,
    //     auth_state.proof,
    //     auth_state.proof_len
    // );
    if (ret != 0) {
        printf("[zkp_auth] Failed to encode proof: %d\n", ret);
        return ZKP_AUTH_ERR_DECODE;
    }

    // Submit proof for verification
    auth_verify_response_t verify_resp = {0};
    int http_rc = balvi_api_verify_proof(hostname, nonce_b64, proof_b64, &verify_resp);

    if (http_rc != 0 || !verify_resp.valid) {
        printf("[zkp_auth] Proof verification failed\n");
        return ZKP_AUTH_ERR_HTTP;
    }

    // Store access token
    strncpy(auth_state.access_token, verify_resp.access_token, sizeof(auth_state.access_token) - 1);
    auth_state.access_token[sizeof(auth_state.access_token) - 1] = '\0';
    auth_state.has_token = true;

    // TODO: Parse expires_at timestamp into uint64_t
    auth_state.token_expiry = 0;  // Placeholder

    printf("[zkp_auth] Authentication successful! Token expires: %s\n", verify_resp.expires_at);
    return ZKP_AUTH_OK;
}

int zkp_auth_authenticate(const char* hostname) {
    int rc;

    // Get nonce
    rc = zkp_auth_get_nonce(hostname);
    if (rc != ZKP_AUTH_OK) {
        return rc;
    }

    // Generate proof
    rc = zkp_auth_generate_proof();
    if (rc != ZKP_AUTH_OK) {
        return rc;
    }

    // Verify and get token
    rc = zkp_auth_verify(hostname);
    if (rc != ZKP_AUTH_OK) {
        return rc;
    }

    return ZKP_AUTH_OK;
}

const char* zkp_auth_get_token(void) {
    if (!auth_state.has_token) {
        return NULL;
    }

    if (!zkp_auth_is_token_valid()) {
        return NULL;
    }

    return auth_state.access_token;
}

bool zkp_auth_is_token_valid(void) {
    if (!auth_state.has_token) {
        return false;
    }

    // TODO: Implement proper time checking
    // For now, assume token is valid if we have one
    return true;
}

uint64_t zkp_auth_get_token_expiry(void) {
    if (!auth_state.has_token) {
        return 0;
    }

    return auth_state.token_expiry;
}
