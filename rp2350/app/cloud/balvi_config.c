#include "balvi_config.h"
#include <string.h>
#include <stdbool.h>

#define JSMN_STATIC
#include "jsmn.h"

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

int parse_balvi_config(const char* json_str, size_t json_len, balvi_config_t* config) {
    jsmn_parser p;
    jsmntok_t t[16]; // Enough tokens for simple config object

    memset(config, 0, sizeof(balvi_config_t));

    jsmn_init(&p);
    int r = jsmn_parse(&p, json_str, json_len, t, sizeof(t)/sizeof(t[0]));

    if (r < 0 || r < 1 || t[0].type != JSMN_OBJECT) {
        return -1;
    }

    for (int i = 1; i < r; i++) {
        if (jsoneq(json_str, &t[i], "tfhe_public_key_b64") == 0) {
            int len = t[i+1].end - t[i+1].start;
            if (len < sizeof(config->tfhe_public_key_b64)) {
                strncpy(config->tfhe_public_key_b64, json_str + t[i+1].start, len);
                config->tfhe_public_key_b64[len] = '\0';
            }
            i++;
        } else if (jsoneq(json_str, &t[i], "merkle_root_b64") == 0) {
            int len = t[i+1].end - t[i+1].start;
            if (len < sizeof(config->merkle_root_b64)) {
                strncpy(config->merkle_root_b64, json_str + t[i+1].start, len);
                config->merkle_root_b64[len] = '\0';
            }
            i++;
        }
    }

    config->valid = (strlen(config->tfhe_public_key_b64) > 0 && strlen(config->merkle_root_b64) > 0);
    return config->valid ? 0 : -1;
}
