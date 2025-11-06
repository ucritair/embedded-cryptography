#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/altcp_tls.h"
#include "lwip/netif.h"
#include "http_client_util.h"
#include "balvi_config.h"

// Response buffer for storing API responses
static char response_buffer[8192];
static size_t response_len = 0;
static balvi_config_t current_config;

// Using this url as we know the root cert won't change for a long time
#define HOST "fw-download-alias1.raspberrypi.com"
#define URL_REQUEST "/net_install/boot.sig"

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

// Raspberry Pi certificate (kept for existing function)
#define TLS_ROOT_CERT_OK "-----BEGIN CERTIFICATE-----\n\
MIIC+jCCAn+gAwIBAgICEAAwCgYIKoZIzj0EAwIwgbcxCzAJBgNVBAYTAkdCMRAw\n\
DgYDVQQIDAdFbmdsYW5kMRIwEAYDVQQHDAlDYW1icmlkZ2UxHTAbBgNVBAoMFFJh\n\
c3BiZXJyeSBQSSBMaW1pdGVkMRwwGgYDVQQLDBNSYXNwYmVycnkgUEkgRUNDIENB\n\
MR0wGwYDVQQDDBRSYXNwYmVycnkgUEkgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYX\n\
c3VwcG9ydEByYXNwYmVycnlwaS5jb20wIBcNMjExMjA5MTEzMjU1WhgPMjA3MTEx\n\
MjcxMTMyNTVaMIGrMQswCQYDVQQGEwJHQjEQMA4GA1UECAwHRW5nbGFuZDEdMBsG\n\
A1UECgwUUmFzcGJlcnJ5IFBJIExpbWl0ZWQxHDAaBgNVBAsME1Jhc3BiZXJyeSBQ\n\
SSBFQ0MgQ0ExJTAjBgNVBAMMHFJhc3BiZXJyeSBQSSBJbnRlcm1lZGlhdGUgQ0Ex\n\
JjAkBgkqhkiG9w0BCQEWF3N1cHBvcnRAcmFzcGJlcnJ5cGkuY29tMHYwEAYHKoZI\n\
zj0CAQYFK4EEACIDYgAEcN9K6Cpv+od3w6yKOnec4EbyHCBzF+X2ldjorc0b2Pq0\n\
N+ZvyFHkhFZSgk2qvemsVEWIoPz+K4JSCpgPstz1fEV6WzgjYKfYI71ghELl5TeC\n\
byoPY+ee3VZwF1PTy0cco2YwZDAdBgNVHQ4EFgQUJ6YzIqFh4rhQEbmCnEbWmHEo\n\
XAUwHwYDVR0jBBgwFoAUIIAVCSiDPXut23NK39LGIyAA7NAwEgYDVR0TAQH/BAgw\n\
BgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDaQAwZgIxAJYM+wIM\n\
PC3wSPqJ1byJKA6D+ZyjKR1aORbiDQVEpDNWRKiQ5QapLg8wbcED0MrRKQIxAKUT\n\
v8TJkb/8jC/oBVTmczKlPMkciN+uiaZSXahgYKyYhvKTatCTZb+geSIhc0w/2w==\n\
-----END CERTIFICATE-----\n"

void https_download_signature(void) {
    static const uint8_t cert_ok[] = TLS_ROOT_CERT_OK;
    static EXAMPLE_HTTP_REQUEST_T req = {0};
    req.hostname = HOST;
    req.url = URL_REQUEST;
    req.headers_fn = http_client_header_print_fn;
    req.recv_fn = http_client_receive_print_fn;
    req.tls_config = altcp_tls_create_config_client(cert_ok, sizeof(cert_ok));

    int pass = http_client_request_sync(cyw43_arch_async_context(), &req);
    altcp_tls_free_config(req.tls_config);
    if (pass != 0) {
        printf("HTTPS download failed\n");
    } else {
        printf("HTTPS download successful\n");
    }
}

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
    if (p != NULL && response_len < sizeof(response_buffer) - 1) {
        size_t copy_len = p->tot_len;
        if (copy_len > sizeof(response_buffer) - response_len - 1) {
            copy_len = sizeof(response_buffer) - response_len - 1;
        }
        pbuf_copy_partial(p, response_buffer + response_len, copy_len, 0);
        response_len += copy_len;
        response_buffer[response_len] = '\0';
        pbuf_free(p);
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
        printf("Balvi API config request failed\n");
    } else {
        printf("Balvi API config request successful\n");
        printf("Response: %s\n", response_buffer);

        // Parse the JSON response
        if (parse_balvi_config(response_buffer, response_len, &current_config) == 0) {
            printf("Config parsed successfully!\n");
            printf("TFHE key length: %zu\n", strlen(current_config.tfhe_public_key_b64));
            printf("Merkle root: %.64s...\n", current_config.merkle_root_b64);
        } else {
            printf("Failed to parse config JSON\n");
        }
    }
}

balvi_config_t* get_current_config(void) {
    return current_config.valid ? &current_config : NULL;
}
