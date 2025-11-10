#ifndef BALVI_CONFIG_H
#define BALVI_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char tfhe_public_key_b64[10240];  // Base64 encoded TFHE public key (increased from 8192 to 10240)
    char merkle_root_b64[256];        // Base64 encoded Merkle root
    bool valid;                       // True if config was successfully parsed
} balvi_config_t;

// Parse JSON config response into structure
int parse_balvi_config(const char* json_str, size_t json_len, balvi_config_t* config);

#endif
