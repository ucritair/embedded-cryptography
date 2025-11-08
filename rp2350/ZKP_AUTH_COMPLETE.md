# ZKP Authentication - COMPLETE IMPLEMENTATION

## Status: ✅ FULLY IMPLEMENTED

All components of the ZKP authentication system are now complete and ready for testing.

## What Was Implemented

### 1. HTTP POST/GET Client (`app/http/http_post_client.{c,h}`)
Complete HTTPS client using lwIP low-level API:
- **HTTPS POST with JSON** - Send JSON payloads over TLS
- **HTTPS GET** - Retrieve data over TLS
- **TLS Support** - Uses Google Trust Services root certificate for air.gp.xyz
- **Dynamic response buffers** - Handles large responses (up to 32KB, expandable)
- **Synchronous operation** - Waits for complete response
- **Error handling** - Comprehensive error reporting
- **Memory management** - Automatic buffer allocation/cleanup

**Key Features**:
- Uses `altcp_tls` for TLS connections
- DNS resolution built-in
- HTTP status code parsing
- Body extraction from HTTP response
- 30-second timeout

### 2. Auth API Endpoints (`app/http/httpss_client.c`)
Complete implementation of all three auth endpoints:

#### `balvi_api_get_witness()`
- **POST** to `/auth/witness`
- **Request**: `{"commitment_b64": "<parent_commitment>"}`
- **Response**: `{"root_b64": "...", "witness_b64": "..."}`
- **JSON parsing**: Extracts both fields using jsmn
- **Returns**: 0 on success, -1 on failure

#### `balvi_api_get_nonce()`
- **GET** from `/auth/nonce`
- **Response**: `{"nonce": "...", "expires_at": "..."}`
- **JSON parsing**: Extracts nonce and expiry timestamp
- **Returns**: 0 on success, -1 on failure

#### `balvi_api_verify_proof()`
- **POST** to `/auth/verify`
- **Request**: `{"nonce": "<nonce_b64>", "proof_bundle": "<proof_b64>"}`
- **Response**: `{"access_token": "...", "expires_at": "..."}`
- **JSON parsing**: Extracts access token and expiry
- **Dynamic payload allocation**: Handles large proof bundles
- **Returns**: 0 on success, -1 on failure

### 3. ZKP Auth Module (`app/auth/zkp_auth.{c,h}`)
Complete authentication flow implementation:
- Secret initialization and storage
- Parent commitment computation using `zkp_parent_from_secret()`
- Witness retrieval from server
- Nonce retrieval from server
- ZKP proof generation using `zkp_generate_proof()`
- Proof verification and token retrieval
- Token management and validation

### 4. Demo Code (`app/crypto/battery_e2e.c`)
`zkp_auth_demo()` demonstrates complete flow:
1. Initialize with test secret
2. Compute parent commitment
3. Get Merkle witness from server
4. Get current epoch nonce
5. Generate ZKP proof
6. Verify proof and obtain access token
7. Display token for use in authenticated requests

## Complete Authentication Flow

```
┌─────────────────┐
│  Device Secret  │  (Base64: 64 bytes)
└────────┬────────┘
         │
         ▼
┌────────────────────────┐
│ zkp_parent_from_secret │  Poseidon2 hash
└────────┬───────────────┘
         │
         ▼
┌─────────────────┐
│ Parent (32 B)   │
└────────┬────────┘
         │
         ▼
┌──────────────────────────┐
│ POST /auth/witness       │
│ {"commitment_b64": "..."} │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Witness + Root (JSON)    │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│ GET /auth/nonce          │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Nonce + Expiry (JSON)    │
└────────┬─────────────────┘
         │
         ▼
┌───────────────────────────┐
│ zkp_generate_proof()      │  SP1 proving
└────────┬──────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Proof Bundle (postcard)  │
└────────┬─────────────────┘
         │
         ▼
┌────────────────────────────┐
│ POST /auth/verify          │
│ {"nonce": "...",           │
│  "proof_bundle": "..."}    │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│ Access Token + Expiry      │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│ Authenticated Requests     │
│ Header: Authorization:     │
│   Bearer <token>           │
└────────────────────────────┘
```

## Files Modified/Created

### Created:
1. `/app/http/http_post_client.h` - HTTP POST/GET client interface
2. `/app/http/http_post_client.c` - HTTP POST/GET client implementation
3. `/app/auth/zkp_auth.h` - ZKP auth module interface
4. `/app/auth/zkp_auth.c` - ZKP auth module implementation
5. `ZKP_AUTH_README.md` - Authentication flow documentation
6. `ZKP_AUTH_IMPLEMENTATION.md` - Initial implementation status
7. `ZKP_AUTH_COMPLETE.md` - This file

### Modified:
1. `/app/http/httpss_client.h` - Added auth response structures and function declarations
2. `/app/http/httpss_client.c` - Implemented all three auth endpoint functions
3. `/app/crypto/battery_e2e.h` - Added `zkp_auth_demo()` declaration
4. `/app/crypto/battery_e2e.c` - Added `zkp_auth_demo()` implementation
5. `/app/CMakeLists.txt` - Added `http/http_post_client.c` and `auth/zkp_auth.c` to build

## Testing Instructions

### 1. Build the Project
```bash
cd /home/a/Desktop/entropic-engg/embedded-cryptography/rp2350
cd build
cmake ..
make
```

### 2. Flash to Device
```bash
# Copy pico_project.uf2 to the RP2350 in bootloader mode
```

### 3. Run Demo
The `zkp_auth_demo()` function should be called from `main()` to test the complete flow.

Expected output:
```
=== ZKP Authentication Demo ===
[zkp_auth_demo] Initializing with test secret
[zkp_auth] Secret initialized (64 bytes)
[zkp_auth] Secret u32[0-3]: 1 2 3 4

[zkp_auth_demo] Computing parent commitment
[zkp_auth] Parent commitment (u32[0-3]): ...
[zkp_auth] Parent base64: ...

[zkp_auth_demo] Step 1: Get Merkle witness from server
[balvi_api] POST /auth/witness
[http_post] Resolving air.gp.xyz...
[http_post] Connecting to <IP>:443...
[http_post] Connected, sending POST request...
[http_post] Status code: 200
[balvi_api] Witness retrieved successfully

[zkp_auth_demo] Step 2: Get current nonce from server
[balvi_api] GET /auth/nonce
[http_post] GET /auth/nonce
[http_post] Status code: 200
[balvi_api] Nonce retrieved successfully (expires: ...)

[zkp_auth_demo] Step 3: Generate ZKP proof
[zkp_auth] Generating ZKP proof...
[zkp_auth] Proof generated (XXXXX bytes)

[zkp_auth_demo] Step 4: Submit proof for verification
[balvi_api] POST /auth/verify
[http_post] POST /auth/verify
[http_post] Status code: 200
[balvi_api] Proof verified! Token expires: ...

[zkp_auth_demo] Step 5: Use access token
[zkp_auth_demo] Access token: abcd1234...
[zkp_auth_demo] Token is valid: yes

=== ZKP Authentication Demo Complete ===
```

## Using the Auth Module

### Initialize Once
```c
#include "zkp_auth.h"

// At startup
const char* secret_b64 = "AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==";
zkp_auth_init(secret_b64);
```

### Get Witness (One-time or when root changes)
```c
zkp_auth_get_witness("air.gp.xyz");
```

### Authenticate (Get Token)
```c
// This does steps 2-4: get nonce, generate proof, verify
zkp_auth_authenticate("air.gp.xyz");
```

### Use Token
```c
const char* token = zkp_auth_get_token();
if (token && zkp_auth_is_token_valid()) {
    // Include in HTTP headers:
    // Authorization: Bearer <token>

    // Example: POST to /ingest
    char auth_header[768];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: Bearer %s", token);

    // ... make authenticated request
}
```

### Re-authenticate When Token Expires
```c
if (!zkp_auth_is_token_valid()) {
    zkp_auth_authenticate("air.gp.xyz");
}
```

## Integration with /ingest Endpoint

To send encrypted sensor data with authentication:

```c
// 1. Ensure we have a valid token
if (!zkp_auth_is_token_valid()) {
    zkp_auth_authenticate("air.gp.xyz");
}

// 2. Encrypt sensor data (already implemented)
const uint8_t sensor_values[5] = {42, 128, 200, 99, 155};
// ... encrypt using cloud_tfhe_encrypt_sensor_bits()

// 3. Build JSON payload with ciphertexts
// (Need to implement this part - array of base64 ciphertexts)

// 4. POST to /ingest with Authorization header
const char* token = zkp_auth_get_token();
// ... implement POST with auth header
```

## Security Notes

1. **Secret Storage**: Currently in RAM. For production:
   - Store encrypted in flash
   - Use RP2350 OTP (One-Time Programmable) memory
   - Never log or transmit the secret

2. **Token Storage**: In-memory only, cleared on reset. Acceptable for session-based auth.

3. **TLS Certificate**: Hardcoded GTS root cert. Update if server certificate changes.

4. **Replay Protection**: Nonce-based, enforced by server. Tokens expire at epoch boundary.

## Memory Usage

### HTTP Client
- Response buffer: 32KB (expandable)
- Request buffer: ~4KB for headers + payload size
- TLS overhead: ~16KB (mbedTLS)

### ZKP Auth State
- Total: ~529KB (mostly proof buffer)
- Consider PSRAM allocation for large buffers if RAM constrained

### Recommendations
- Allocate proof encoding buffer in PSRAM if needed
- Use existing PSRAM allocation patterns from sensor encryption code

## Known Limitations

1. **Token Expiry Parsing**: Currently stores expiry timestamp as string, doesn't parse to epoch time for validation. `zkp_auth_is_token_valid()` always returns true if token exists.

2. **DNS Caching**: No DNS cache, resolves hostname on every request. Consider caching IP address.

3. **Connection Reuse**: Creates new TCP connection for each request. HTTP keep-alive not implemented.

4. **Error Recovery**: Limited retry logic. Should add exponential backoff for transient failures.

5. **Concurrent Requests**: Not thread-safe, assumes single-threaded operation.

## Next Steps

1. **Test with Real Server**:
   - Deploy test server at air.gp.xyz
   - Test complete auth flow with real witness
   - Verify proof generation works end-to-end

2. **Implement /ingest Integration**:
   - Create `balvi_api_ingest_sensors()` function
   - Combine sensor encryption + auth + POST
   - Include Authorization header in request

3. **Add Error Handling**:
   - Retry logic with backoff
   - Handle 401 (re-authenticate)
   - Handle 404 on witness (device not authorized)

4. **Optimize Performance**:
   - Cache DNS lookups
   - Reuse TCP connections if possible
   - Reduce buffer sizes where safe

5. **Production Hardening**:
   - Implement proper token expiry checking
   - Secure secret storage
   - Add logging/metrics
   - Add health checks

## Summary

The ZKP authentication system is **fully implemented** and ready for testing. All major components are complete:

✅ HTTP POST/GET client with TLS
✅ JSON request/response handling
✅ All three auth endpoints (/witness, /nonce, /verify)
✅ ZKP proof generation and verification flow
✅ Token management
✅ Demo code
✅ Build integration

The implementation follows the authentication flow documented in the OpenAPI spec and provides a clean API for integrating with the rest of the application.
