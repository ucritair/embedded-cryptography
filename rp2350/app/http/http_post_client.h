#ifndef HTTP_POST_CLIENT_H
#define HTTP_POST_CLIENT_H

#include <stddef.h>
#include <stdbool.h>

// HTTP response structure
typedef struct {
    int status_code;
    char *body;
    size_t body_len;
    bool success;
} http_response_t;

/**
 * Perform a synchronous HTTPS POST request with JSON payload.
 *
 * @param hostname Server hostname (e.g., "air.gp.xyz")
 * @param path URL path (e.g., "/auth/witness")
 * @param json_payload JSON string to send as request body
 * @param response Output structure to receive response (caller must free response->body)
 * @return 0 on success, negative on error
 */
int https_post_json(const char* hostname, const char* path, const char* json_payload, http_response_t* response);

/**
 * Perform a synchronous HTTPS POST request with JSON payload using a more robust
 * chunking mechanism suitable for very large payloads.
 *
 * @param hostname Server hostname (e.g., "air.gp.xyz")
 * @param path URL path (e.g., "/auth/witness")
 * @param json_payload JSON string to send as request body
 * @param response Output structure to receive response
 * @return 0 on success, negative on error
 */
int https_post_json_2(const char* hostname, const char* path, const char* json_payload, http_response_t* response);

/**
 * Perform a synchronous HTTPS GET request.
 *
 * @param hostname Server hostname
 * @param path URL path
 * @param response Output structure to receive response (caller must free response->body)
 * @return 0 on success, negative on error
 */
int https_get(const char* hostname, const char* path, http_response_t* response);

/**
 * Free resources allocated by http_response_t.
 */
void http_response_free(http_response_t* response);

#endif // HTTP_POST_CLIENT_H
