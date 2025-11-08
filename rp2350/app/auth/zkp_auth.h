#ifndef ZKP_AUTH_H
#define ZKP_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Auth status codes
#define ZKP_AUTH_OK 0
#define ZKP_AUTH_ERR_INIT -1
#define ZKP_AUTH_ERR_DECODE -2
#define ZKP_AUTH_ERR_HTTP -3
#define ZKP_AUTH_ERR_PROOF -4
#define ZKP_AUTH_ERR_NO_TOKEN -5
#define ZKP_AUTH_ERR_EXPIRED -6

// Buffer sizes
#define ZKP_PARENT_SIZE 32        // 8 u32 = 32 bytes
#define ZKP_NONCE_SIZE 32         // 32 bytes
#define ZKP_WITNESS_MAX 16384     // 16KB max witness data
#define ZKP_PROOF_MAX 524288      // 512KB max proof bundle
#define ZKP_TOKEN_MAX 512         // Max bearer token length

/**
 * Initialize the ZKP auth module with the device secret.
 * The secret is base64-encoded (64 bytes decoded = 16 u32 words).
 *
 * @param secret_b64 Base64-encoded secret (two leaves)
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_init(const char* secret_b64);

/**
 * Compute the parent commitment from the stored secret.
 * Must be called after zkp_auth_init().
 *
 * @param parent_b64_out Buffer to receive base64-encoded parent (min 64 bytes)
 * @param out_len Length of output buffer
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_compute_parent(char* parent_b64_out, size_t out_len);

/**
 * Request the Merkle witness from the server using the parent commitment.
 * Stores the witness internally for later proof generation.
 *
 * @param hostname API hostname (e.g., "air.gp.xyz")
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_get_witness(const char* hostname);

/**
 * Get the current epoch nonce from the server.
 *
 * @param hostname API hostname
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_get_nonce(const char* hostname);

/**
 * Generate the ZKP proof using stored secret, witness, and nonce.
 * Must be called after zkp_auth_get_witness() and zkp_auth_get_nonce().
 *
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_generate_proof(void);

/**
 * Submit the proof to the server for verification and obtain an access token.
 * Must be called after zkp_auth_generate_proof().
 *
 * @param hostname API hostname
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_verify(const char* hostname);

/**
 * Complete authentication flow: get nonce, generate proof, verify, and obtain token.
 * Assumes witness has already been retrieved via zkp_auth_get_witness().
 *
 * @param hostname API hostname
 * @return ZKP_AUTH_OK on success, error code otherwise
 */
int zkp_auth_authenticate(const char* hostname);

/**
 * Get the current access token if valid.
 *
 * @return Pointer to token string, or NULL if no valid token
 */
const char* zkp_auth_get_token(void);

/**
 * Check if the current token is still valid (not expired).
 *
 * @return true if token is valid, false otherwise
 */
bool zkp_auth_is_token_valid(void);

/**
 * Get the token expiry timestamp.
 *
 * @return Expiry time_t, or 0 if no token
 */
uint64_t zkp_auth_get_token_expiry(void);

#endif // ZKP_AUTH_H
