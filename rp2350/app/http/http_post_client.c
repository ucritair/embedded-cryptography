#include "http_post_client.h"
#include "pico/cyw43_arch.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include <string.h>
#include <stdio.h>

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

#define HTTP_REQUEST_BUFFER_SIZE (4 * 1024)   // 4KB for request (headers + small payload)
#define HTTP_RESPONSE_BUFFER_SIZE (16 * 1024)  // 16KB for responses (static, no realloc)
#define HTTP_TIMEOUT_MS 30000  // 30 second timeout

// Static buffers (no malloc/free)
static char static_request_buffer[HTTP_REQUEST_BUFFER_SIZE];
static char static_response_buffer[HTTP_RESPONSE_BUFFER_SIZE];
static bool http_client_busy = false;

// State for HTTP request
typedef struct {
    struct altcp_pcb *pcb;
    char *request_data;          // Points to static_request_buffer
    size_t request_len;
    size_t request_sent;
    char *response_buffer;       // Points to static_response_buffer
    size_t response_len;
    size_t response_capacity;
    bool complete;
    bool error;
    int status_code;
    char *body_start;
    size_t body_len;
    bool is_post;
} http_state_t;

static err_t http_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t http_client_sent(void *arg, struct altcp_pcb *pcb, u16_t len);
static err_t http_client_connected(void *arg, struct altcp_pcb *pcb, err_t err);
static void http_client_err(void *arg, err_t err);

static err_t http_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
    http_state_t *state = (http_state_t *)arg;

    if (!p) {
        // Connection closed
        printf("[http_post] Connection closed\n");
        state->complete = true;
        return ERR_OK;
    }

    if (err != ERR_OK) {
        printf("[http_post] Receive error: %d\n", err);
        pbuf_free(p);
        state->error = true;
        state->complete = true;
        return err;
    }

    // Check if buffer has space (static buffer, no realloc)
    size_t needed = state->response_len + p->tot_len;
    if (needed > state->response_capacity) {
        printf("[http_post] Response too large: %zu > %zu\n", needed, state->response_capacity);
        pbuf_free(p);
        state->error = true;
        state->complete = true;
        return ERR_MEM;
    }

    // Copy data
    pbuf_copy_partial(p, state->response_buffer + state->response_len, p->tot_len, 0);
    state->response_len += p->tot_len;

    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

static err_t http_client_sent(void *arg, struct altcp_pcb *pcb, u16_t len) {
    http_state_t *state = (http_state_t *)arg;

    state->request_sent += len;

    // Send remaining data if any
    if (state->request_sent < state->request_len) {
        size_t remaining = state->request_len - state->request_sent;
        size_t to_send = remaining < 2048 ? remaining : 2048;

        err_t err = altcp_write(pcb, state->request_data + state->request_sent,
                                to_send, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            altcp_output(pcb);
        } else {
            printf("[http_post] Failed to write more data: %d\n", err);
            state->error = true;
            state->complete = true;
        }
    }

    return ERR_OK;
}

static err_t http_client_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
    http_state_t *state = (http_state_t *)arg;

    if (err != ERR_OK) {
        printf("[http_post] Connection failed: %d\n", err);
        state->error = true;
        state->complete = true;
        return err;
    }

    printf("[http_post] Connected, sending %s request (%zu bytes)\n",
           state->is_post ? "POST" : "GET", state->request_len);

    // Send request (or first chunk)
    size_t to_send = state->request_len < 2048 ? state->request_len : 2048;
    err = altcp_write(pcb, state->request_data, to_send, TCP_WRITE_FLAG_COPY);

    if (err != ERR_OK) {
        printf("[http_post] Failed to write request: %d\n", err);
        state->error = true;
        state->complete = true;
        return err;
    }

    altcp_output(pcb);
    return ERR_OK;
}

static void http_client_err(void *arg, err_t err) {
    http_state_t *state = (http_state_t *)arg;
    printf("[http_post] Connection error: %d\n", err);
    state->error = true;
    state->complete = true;
}

static int parse_http_response(http_state_t *state) {
    if (state->response_len == 0) {
        return -1;
    }

    // Null-terminate for easier parsing
    if (state->response_len < state->response_capacity) {
        state->response_buffer[state->response_len] = '\0';
    }

    // Parse status line: "HTTP/1.1 200 OK\r\n"
    char *status_line = state->response_buffer;
    char *line_end = strstr(status_line, "\r\n");
    if (!line_end) {
        printf("[http_post] No status line found\n");
        return -1;
    }

    // Extract status code
    char *status_start = strchr(status_line, ' ');
    if (status_start) {
        state->status_code = atoi(status_start + 1);
        printf("[http_post] Status code: %d\n", state->status_code);
    }

    // Find body (after "\r\n\r\n")
    char *body_start = strstr(state->response_buffer, "\r\n\r\n");
    if (body_start) {
        state->body_start = body_start + 4;
        state->body_len = state->response_len - (state->body_start - state->response_buffer);
        printf("[http_post] Body length: %zu bytes\n", state->body_len);
    } else {
        state->body_start = NULL;
        state->body_len = 0;
    }

    return 0;
}

static int https_request(const char* hostname, const char* path, const char* method,
                         const char* json_payload, http_response_t* response) {
    printf("[http_post] Starting %s request to %s%s\n", method, hostname, path);

    // Check if client is already busy (single request at a time with static buffers)
    if (http_client_busy) {
        printf("[http_post] Client busy, only one request at a time\n");
        return -1;
    }
    http_client_busy = true;

    // Initialize TLS config
    static const uint8_t cert[] = GTS_ROOT_CERT;
    printf("[http_post] Creating TLS config...\n");
    struct altcp_tls_config *tls_config = altcp_tls_create_config_client(cert, sizeof(cert));
    if (!tls_config) {
        printf("[http_post] Failed to create TLS config\n");
        http_client_busy = false;
        return -1;
    }
    printf("[http_post] TLS config created\n");

    // Use static state (no malloc)
    static http_state_t state;
    memset(&state, 0, sizeof(state));

    state.is_post = (strcmp(method, "POST") == 0);
    state.response_buffer = static_response_buffer;
    state.response_capacity = HTTP_RESPONSE_BUFFER_SIZE;
    state.response_len = 0;

    // Build HTTP request in static buffer
    int req_len;
    if (state.is_post && json_payload) {
        req_len = snprintf(static_request_buffer, HTTP_REQUEST_BUFFER_SIZE,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, hostname, strlen(json_payload), json_payload);
    } else {
        req_len = snprintf(static_request_buffer, HTTP_REQUEST_BUFFER_SIZE,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, path, hostname);
    }

    if (req_len >= HTTP_REQUEST_BUFFER_SIZE) {
        printf("[http_post] Request too large: %d >= %d\n", req_len, HTTP_REQUEST_BUFFER_SIZE);
        altcp_tls_free_config(tls_config);
        http_client_busy = false;
        return -1;
    }

    state.request_data = static_request_buffer;
    state.request_len = req_len;

    // Create PCB
    state.pcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
    if (!state.pcb) {
        printf("[http_post] Failed to create PCB\n");
        altcp_tls_free_config(tls_config);
        http_client_busy = false;
        return -1;
    }

    // Set SNI hostname
    mbedtls_ssl_set_hostname(altcp_tls_context(state.pcb), hostname);

    // Set callbacks
    altcp_arg(state.pcb, &state);
    altcp_recv(state.pcb, http_client_recv);
    altcp_sent(state.pcb, http_client_sent);
    altcp_err(state.pcb, http_client_err);

    // Resolve hostname
    ip_addr_t server_ip;
    printf("[http_post] Resolving %s...\n", hostname);

    err_t err = dns_gethostbyname(hostname, &server_ip, NULL, NULL);
    if (err == ERR_INPROGRESS) {
        printf("[http_post] DNS resolution in progress...\n");
        // Wait for DNS
        int timeout = 100;  // 10 seconds
        while (err == ERR_INPROGRESS && timeout-- > 0) {
            cyw43_arch_poll();
            sleep_ms(100);
            err = dns_gethostbyname(hostname, &server_ip, NULL, NULL);
        }
    }

    if (err != ERR_OK) {
        printf("[http_post] DNS resolution failed: %d\n", err);
        altcp_close(state.pcb);
        altcp_tls_free_config(tls_config);
        http_client_busy = false;
        return -1;
    }

    printf("[http_post] Connecting to %s:443...\n", ipaddr_ntoa(&server_ip));
    err = altcp_connect(state.pcb, &server_ip, 443, http_client_connected);
    if (err != ERR_OK) {
        printf("[http_post] Connect failed: %d\n", err);
        altcp_close(state.pcb);
        altcp_tls_free_config(tls_config);
        http_client_busy = false;
        return -1;
    }

    // Wait for completion
    printf("[http_post] Waiting for response...\n");
    int timeout = HTTP_TIMEOUT_MS / 100;
    while (!state.complete && timeout-- > 0) {
        cyw43_arch_poll();
        sleep_ms(100);
    }

    if (!state.complete) {
        printf("[http_post] Request timeout\n");
        altcp_close(state.pcb);
        altcp_tls_free_config(tls_config);
        http_client_busy = false;
        return -1;
    }

    // Parse response
    int result = -1;
    if (!state.error && parse_http_response(&state) == 0) {
        response->status_code = state.status_code;
        response->success = (state.status_code >= 200 && state.status_code < 300);

        // Copy body to caller's buffer (caller must provide buffer or we use static)
        // For now, just point to our static buffer (caller should copy if needed)
        if (state.body_len > 0) {
            response->body = state.body_start;  // Points into static_response_buffer
            response->body_len = state.body_len;
            result = 0;
        } else {
            response->body = NULL;
            response->body_len = 0;
            result = 0;
        }
    }

    // Cleanup
    altcp_close(state.pcb);
    altcp_tls_free_config(tls_config);
    http_client_busy = false;

    return result;
}

int https_post_json(const char* hostname, const char* path, const char* json_payload, http_response_t* response) {
    memset(response, 0, sizeof(http_response_t));
    return https_request(hostname, path, "POST", json_payload, response);
}

int https_get(const char* hostname, const char* path, http_response_t* response) {
    memset(response, 0, sizeof(http_response_t));
    return https_request(hostname, path, "GET", NULL, response);
}

void http_response_free(http_response_t* response) {
    // No-op now since we use static buffers
    // Body points into static_response_buffer, so nothing to free
    if (response) {
        response->body = NULL;
        response->body_len = 0;
    }
}
