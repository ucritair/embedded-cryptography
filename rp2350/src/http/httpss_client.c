#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/altcp_tls.h"

#include "lwip/netif.h"

#include "FreeRTOS.h"
#include "task.h"
#include "http_client_util.h"

// Using this url as we know the root cert won't change for a long time
#define HOST "fw-download-alias1.raspberrypi.com"
#define URL_REQUEST "/net_install/boot.sig"

// This is the PUBLIC root certificate exported from a browser
// Note that the newlines are needed
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

static void https_download_task(__unused void *params) {
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

    vTaskDelete(NULL);
}

void https_download_signature(void) {
    xTaskCreate(https_download_task, "HTTPSDownloadThread", 2048, NULL, tskIDLE_PRIORITY + 3, NULL);
}
