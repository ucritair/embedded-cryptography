#ifndef HTTPSS_CLIENT_H
#define HTTPSS_CLIENT_H

#include "balvi_config.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Auth response structures
typedef struct {
    char root_b64[256];
    char witness_b64[32768];  // Max 24KB base64
    bool valid;
} witness_response_t;

typedef struct {
    char nonce[64];  // 32 bytes base64 = ~44 chars
    char expires_at[32];
    bool valid;
} nonce_response_t;

typedef struct {
    char access_token[512];
    char expires_at[32];
    bool valid;
} auth_verify_response_t;

void balvi_api_health_check(const char* hostname);
void balvi_api_get_config(const char* hostname);
balvi_config_t* get_current_config(void);

// Auth endpoints
int balvi_api_get_witness(const char* hostname, const char* parent_b64, witness_response_t* response);
int balvi_api_get_nonce(const char* hostname, nonce_response_t* response);
int balvi_api_verify_proof(const char* hostname, const char* nonce_b64, const char* proof_b64, auth_verify_response_t* response);

#endif
