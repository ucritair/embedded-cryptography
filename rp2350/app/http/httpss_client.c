#include "httpss_client.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/altcp_tls.h"
#include "lwip/netif.h"
#include "http_client_util.h"
#include "http_post_client.h"
#include "psram_config.h"
#include "crypto_shared.h"
#include "buffer_config.h"
#include <string.h>

// Access to global auth token from http_post_client.c
extern const char* g_current_auth_token;

#define JSMN_STATIC
#include "jsmn.h"

// Response buffer for storing API responses
static char response_buffer[HTTP_RESPONSE_BUFFER_SIZE];
static size_t response_len = 0;
static balvi_config_t current_config;

// Google Trust Services root certificate for air.gp.xyz
#define GTS_ROOT_CERT "-----BEGIN CERTIFICATE-----\n\
MIIDejCCAmKgAwIBAgIQf+UwvzMTQ77dghYQST2KGzANBgkqhkiG9w0BAQsFADBX\n\
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE\n\
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIzMTEx\n\
NTAzNDMyMVoXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT\n\
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFI0\n\
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE83Rzp2iLYK5DuDXFgTB7S0md+8Fhzube\n\
Rr1r1WEYNa5A3XP3iZEwWus87oV8okB2O6nGuEfYKueSkWpz6bFyOZ8pn6KY019e\n\
WIZlD6GEZQbR3IvJx3PIjGov5cSr0R2Ko4H/MIH8MA4GA1UdDwEB/wQEAwIBhjAd\n\
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAd\n\
BgNVHQ4EFgQUgEzW63T/STaj1dj8tT7FavCUHYwwHwYDVR0jBBgwFoAUYHtmGkUN\n\
l8qJUC99BM00qP/8/UswNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzAChhpodHRw\n\
Oi8vaS5wa2kuZ29vZy9nc3IxLmNydDAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8v\n\
Yy5wa2kuZ29vZy9yL2dzcjEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqG\n\
SIb3DQEBCwUAA4IBAQAYQrsPBtYDh5bjP2OBDwmkoWhIDDkic574y04tfzHpn+cJ\n\
odI2D4SseesQ6bDrarZ7C30ddLibZatoKiws3UL9xnELz4ct92vID24FfVbiI1hY\n\
+SW6FoVHkNeWIP0GCbaM4C6uVdF5dTUsMVs/ZbzNnIdCp5Gxmx5ejvEau8otR/Cs\n\
kGN+hr/W5GvT1tMBjgWKZ1i4//emhA1JG1BbPzoLJQvyEotc03lXjTaCzv8mEbep\n\
8RqZ7a2CPsgRbuvTPBwcOMBBmuFeU88+FSBX6+7iP0il8b4Z0QFqIwwMHfs/L6K1\n\
vepuoxtGzi4CZ68zJpiq1UvSqTbFJjtbD4seiMHl\n\
-----END CERTIFICATE-----\n"

void balvi_api_health_check(const char* hostname) {
    static const uint8_t gts_cert[] = GTS_ROOT_CERT;
    static EXAMPLE_HTTP_REQUEST_T req = {0};
    req.hostname = hostname;
    req.url = "/health/live";
    req.headers_fn = NULL;  // No header debug output
    req.recv_fn = NULL;     // No response debug output
    req.tls_config = altcp_tls_create_config_client(gts_cert, sizeof(gts_cert));

    printf("Checking balvi-api health at %s/health/live\n", hostname);
    int result = http_client_request_sync(cyw43_arch_async_context(), &req);
    altcp_tls_free_config(req.tls_config);

    if (result != 0) {
        printf("Balvi API health check failed\n");
    } else {
        printf("Balvi API health check successful\n");
    }
}

// Custom callback to store response data
err_t store_response_callback(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err) {
    static int packet_count = 0;
    
    if (p != NULL) {
        packet_count++;
        printf("Packet %d: %u bytes, total so far: %zu\n", packet_count, p->tot_len, response_len);
        
        if (response_len < sizeof(response_buffer) - 1) {
            size_t copy_len = p->tot_len;
            if (copy_len > sizeof(response_buffer) - response_len - 1) {
                printf("WARNING: Response truncated! Buffer full (%zu bytes), need %zu more\n",
                       response_len, p->tot_len);
                copy_len = sizeof(response_buffer) - response_len - 1;
            }
            pbuf_copy_partial(p, response_buffer + response_len, copy_len, 0);
            response_len += copy_len;
            response_buffer[response_len] = '\0';
        } else {
            printf("WARNING: Response buffer full, dropping %u bytes\n", p->tot_len);
        }
        pbuf_free(p);
    } else {
        printf("Received NULL pbuf (connection closed), packet count: %d\n", packet_count);
        packet_count = 0; // Reset for next request
    }
    return ERR_OK;
}

void balvi_api_get_config(const char* hostname) {
    static const uint8_t gts_cert[] = GTS_ROOT_CERT;
    static EXAMPLE_HTTP_REQUEST_T req = {0};

    // Reset response buffer
    response_len = 0;
    memset(response_buffer, 0, sizeof(response_buffer));

    req.hostname = hostname;
    req.url = "/config";
    req.headers_fn = NULL;
    req.recv_fn = store_response_callback;  // Store the response
    req.tls_config = altcp_tls_create_config_client(gts_cert, sizeof(gts_cert));

    printf("Getting balvi-api config from %s/config\n", hostname);
    int result = http_client_request_sync(cyw43_arch_async_context(), &req);
    
    altcp_tls_free_config(req.tls_config);

    if (result != 0) {
        printf("Balvi API config request failed with error: %d\n", result);
        return;
    }
    
    printf("Balvi API config request successful\n");
    if (response_len > 0) {
        // Parse the JSON response
        if (parse_balvi_config(response_buffer, response_len, &current_config) == 0) {
            printf("Config parsed successfully!\n");
            printf("TFHE key length: %zu\n", strlen(current_config.tfhe_public_key_b64));
            printf("Merkle root: %.64s...\n", current_config.merkle_root_b64);
        } else {
            printf("Failed to parse config JSON\n");
        }
    } else {
        printf("ERROR: No response data received\n");
    }
}

balvi_config_t* get_current_config(void) {
    return current_config.valid ? &current_config : NULL;
}

// JSON parsing helper
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

// Auth endpoint implementations

int balvi_api_get_witness(const char* hostname, const char* parent_b64, witness_response_t* response) {
    printf("[balvi_api] POST /auth/witness\n");

    // Build JSON payload
    char json_payload[512];
    snprintf(json_payload, sizeof(json_payload),
             "{\"commitment_b64\":\"%s\"}", parent_b64);

    printf("FULL REQUEST JSON:\n%s\n", json_payload);

    // Send POST request
    http_response_t http_resp;
    int rc = https_post_json(hostname, "/auth/witness", json_payload, &http_resp);

    if (rc != 0 || !http_resp.success) {
        printf("[balvi_api] POST failed: rc=%d, status=%d\n", rc, http_resp.status_code);
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    printf("FULL SERVER RESPONSE JSON (%zu bytes):\n%s\n", http_resp.body_len, http_resp.body);

    // Parse JSON response
    jsmn_parser p;
    jsmntok_t tokens[32];
    jsmn_init(&p);

    int token_count = jsmn_parse(&p, http_resp.body, http_resp.body_len, tokens, 32);
    if (token_count < 0 || tokens[0].type != JSMN_OBJECT) {
        printf("[balvi_api] JSON parse failed\n");
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    // Extract fields
    bool found_root = false, found_witness = false;
    for (int i = 1; i < token_count; i++) {
        if (jsoneq(http_resp.body, &tokens[i], "root_b64") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->root_b64)) {
                strncpy(response->root_b64, http_resp.body + tokens[i+1].start, len);
                response->root_b64[len] = '\0';
                found_root = true;
            }
            i++;
        } else if (jsoneq(http_resp.body, &tokens[i], "witness_b64") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->witness_b64)) {
                strncpy(response->witness_b64, http_resp.body + tokens[i+1].start, len);
                response->witness_b64[len] = '\0';
                found_witness = true;
            }
            i++;
        }
    }

    response->valid = found_root && found_witness;
    http_response_free(&http_resp);

    if (response->valid) {
        printf("[balvi_api] Witness retrieved successfully\n");
        return 0;
    } else {
        printf("[balvi_api] Missing fields in response\n");
        return -1;
    }
}

int balvi_api_get_nonce(const char* hostname, nonce_response_t* response) {
    printf("[balvi_api] GET /auth/nonce\n");

    // Send GET request
    http_response_t http_resp;
    int rc = https_get(hostname, "/auth/nonce", &http_resp);

    if (rc != 0 || !http_resp.success) {
        printf("[balvi_api] GET failed: rc=%d, status=%d\n", rc, http_resp.status_code);
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    printf("FULL SERVER RESPONSE JSON (%zu bytes):\n%s\n", http_resp.body_len, http_resp.body);

    // Parse JSON response
    jsmn_parser p;
    jsmntok_t tokens[16];
    jsmn_init(&p);

    int token_count = jsmn_parse(&p, http_resp.body, http_resp.body_len, tokens, 16);
    if (token_count < 0 || tokens[0].type != JSMN_OBJECT) {
        printf("[balvi_api] JSON parse failed\n");
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    // Extract fields
    bool found_nonce = false, found_expires = false;
    for (int i = 1; i < token_count; i++) {
        if (jsoneq(http_resp.body, &tokens[i], "nonce") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->nonce)) {
                strncpy(response->nonce, http_resp.body + tokens[i+1].start, len);
                response->nonce[len] = '\0';
                found_nonce = true;
            }
            i++;
        } else if (jsoneq(http_resp.body, &tokens[i], "expires_at") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->expires_at)) {
                strncpy(response->expires_at, http_resp.body + tokens[i+1].start, len);
                response->expires_at[len] = '\0';
                found_expires = true;
            }
            i++;
        }
    }

    response->valid = found_nonce && found_expires;
    http_response_free(&http_resp);

    if (response->valid) {
        printf("[balvi_api] Nonce retrieved successfully (expires: %s)\n", response->expires_at);
        return 0;
    } else {
        printf("[balvi_api] Missing fields in response\n");
        return -1;
    }
}

int balvi_api_verify_proof(const char* hostname, const char* nonce_b64, const char* proof_b64, auth_verify_response_t* response) {
    printf("[balvi_api] POST /auth/verify\n");
    printf("[balvi_api]   nonce_b64: %s\n", nonce_b64);
    printf("[balvi_api]   proof_b64 length: %zu\n", strlen(proof_b64));

    size_t nonce_len = strlen(nonce_b64);
    size_t proof_len = strlen(proof_b64);

    // Calculate total JSON size
    size_t prefix_len = strlen("{\"nonce\":\"") + nonce_len + strlen("\",\"proof_bundle\":\"");
    size_t suffix_len = strlen("\"}");
    size_t total_json = prefix_len + proof_len + suffix_len;

    printf("[balvi_api] Building JSON payload in PSRAM (%zu bytes)\n", total_json);

    // Build JSON in-place by shifting proof_b64 right to make room for prefix
    // proof_b64 is already in crypto_shared->proof_b64
    // We'll build the JSON at the START of proof[] buffer (which has 435KB)
    char *json_buffer = (char*)crypto_shared->proof;  // Reuse proof buffer (no longer needed)

    // Check if it fits in the proof buffer
    if (total_json >= sizeof(crypto_shared->proof)) {
        printf("[balvi_api] JSON payload too large: %zu >= %zu\n", total_json, sizeof(crypto_shared->proof));
        if (response) response->valid = false;
        return -1;
    }

    // Build JSON by copying proof_b64 first, then prepending the prefix
    char *json_ptr = json_buffer;
    const char *prefix1 = "{\"nonce\":\"";
    const char *prefix2 = "\",\"proof_bundle\":\"";
    const char *suffix  = "\"}";

    // Copy part 1: {"nonce":"
    memcpy(json_ptr, prefix1, strlen(prefix1));
    json_ptr += strlen(prefix1);

    // Copy part 2: <the actual nonce>
    memcpy(json_ptr, nonce_b64, nonce_len);
    json_ptr += nonce_len;

    // Copy part 3: ","proof_bundle":"
    memcpy(json_ptr, prefix2, strlen(prefix2));
    json_ptr += strlen(prefix2);

    // Copy part 4: <the actual proof> - use memmove since source and dest might overlap
    // Verify proof_b64 first/last chars before copying
    printf("[balvi_api] proof_b64 first 20 chars: %.20s\n", proof_b64);
    printf("[balvi_api] proof_b64 last 20 chars: %s\n", proof_b64 + proof_len - 20);

    memmove(json_ptr, proof_b64, proof_len);
    json_ptr += proof_len;

    // Verify after copying
    printf("[balvi_api] After memmove, json first 100 chars at proof pos: %.100s\n", json_buffer + prefix_len);
    printf("[balvi_api] After memmove, json last 20 chars: %.20s\n", json_ptr - 20);

    // Copy part 5: "}
    memcpy(json_ptr, suffix, strlen(suffix));
    json_ptr += strlen(suffix);

    // Add the final null terminator
    *json_ptr = '\0';

    // Send POST request
    // Must use _2 version with chunked sending - single write of 187KB causes mbedTLS panic
    http_response_t http_resp;
    int rc = https_post_json_2(hostname, "/auth/verify", json_buffer, &http_resp);

    if (rc != 0 || !http_resp.success) {
        printf("[balvi_api] POST failed: rc=%d, status=%d\n", rc, http_resp.status_code);
        if (http_resp.body && http_resp.body_len > 0) {
            printf("FULL SERVER ERROR RESPONSE (%zu bytes):\n%s\n", http_resp.body_len, http_resp.body);
        }
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    printf("FULL SERVER SUCCESS RESPONSE (%zu bytes):\n%s\n", http_resp.body_len, http_resp.body);

    // Parse JSON response
    jsmn_parser p;
    jsmntok_t tokens[16];
    jsmn_init(&p);

    int token_count = jsmn_parse(&p, http_resp.body, http_resp.body_len, tokens, 16);
    if (token_count < 0 || tokens[0].type != JSMN_OBJECT) {
        printf("[balvi_api] JSON parse failed\n");
        if (response) response->valid = false;
        http_response_free(&http_resp);
        return -1;
    }

    // Extract fields
    bool found_token = false, found_expires = false;
    for (int i = 1; i < token_count; i++) {
        if (jsoneq(http_resp.body, &tokens[i], "access_token") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->access_token)) {
                strncpy(response->access_token, http_resp.body + tokens[i+1].start, len);
                response->access_token[len] = '\0';
                found_token = true;
            }
            i++;
        } else if (jsoneq(http_resp.body, &tokens[i], "expires_at") == 0) {
            int len = tokens[i+1].end - tokens[i+1].start;
            if (len < sizeof(response->expires_at)) {
                strncpy(response->expires_at, http_resp.body + tokens[i+1].start, len);
                response->expires_at[len] = '\0';
                found_expires = true;
            }
            i++;
        }
    }

    response->valid = found_token && found_expires;
    http_response_free(&http_resp);

    if (response->valid) {
        printf("[balvi_api] Proof verified! Token expires: %s\n", response->expires_at);
        return 0;
    } else {
        printf("[balvi_api] Missing fields in response\n");
        return -1;
    }
}

// POST /ingest - Submit encrypted sensor readings
// Note: This is a simplified version without Bearer auth header support
// The server needs to be configured to accept requests without authentication for now
int balvi_api_ingest(const char* hostname, const char** ct_b64_array, size_t num_cts,
                     const char* timestamp, const char* auth_token) {
    http_response_t http_resp = {0};

    // Build JSON payload: {"ts":"...", "sensors":["ct1","ct2",...]}
    // Use PSRAM for large buffer (40 ciphertexts * ~1.5KB each = ~60KB JSON)
    static char json_body[65536] __attribute__((section(".psram_data")));
    int offset = 0;

    offset += snprintf(json_body + offset, sizeof(json_body) - offset,
                      "{\"ts\":\"%s\",\"sensors\":[", timestamp);

    for (size_t i = 0; i < num_cts; i++) {
        offset += snprintf(json_body + offset, sizeof(json_body) - offset,
                          "\"%s\"%s", ct_b64_array[i], (i < num_cts - 1) ? "," : "");
        if (offset >= sizeof(json_body) - 10) {
            printf("[balvi_api_ingest] JSON body too large\n");
            return -1;
        }
    }

    offset += snprintf(json_body + offset, sizeof(json_body) - offset, "]}");

    printf("[balvi_api_ingest] Sending %zu ciphertexts to %s/ingest\n", num_cts, hostname);
    printf("[balvi_api_ingest] JSON body length: %d bytes\n", offset);
    printf("[balvi_api_ingest] Auth token: %.32s...\n", auth_token);

    // Set global auth token for this request (need to cast away const)
    *(const char**)&g_current_auth_token = auth_token;

    // Use https_post_json_2 for large payload support with auth
    int result = https_post_json_2(hostname, "/ingest", json_body, &http_resp);
    
    // Clear auth token after request
    *(const char**)&g_current_auth_token = NULL;

    if (result != 0 || !http_resp.success) {
        printf("[balvi_api_ingest] POST failed: rc=%d, status=%d\n", result, http_resp.status_code);
        if (http_resp.body && http_resp.body_len > 0) {
            printf("[balvi_api_ingest] Response body: %.*s\n",
                   (int)http_resp.body_len, http_resp.body);
        }
        http_response_free(&http_resp);
        return -1;
    }

    printf("[balvi_api_ingest] Response status: %d\n", http_resp.status_code);

    if (http_resp.status_code == 202 || http_resp.status_code == 200) {
        printf("[balvi_api_ingest] Data accepted successfully\n");
        http_response_free(&http_resp);
        return 0;
    } else {
        printf("[balvi_api_ingest] Server returned non-202 status\n");
        if (http_resp.body_len > 0) {
            printf("[balvi_api_ingest] Response body: %.*s\n",
                   (int)http_resp.body_len, http_resp.body);
        }
        http_response_free(&http_resp);
        return -1;
    }
}
