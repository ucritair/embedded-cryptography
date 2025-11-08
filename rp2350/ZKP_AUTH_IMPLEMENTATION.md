# ZKP Authentication Implementation Summary

## Overview
Implemented a complete ZKP authentication module for the RP2350 to authenticate with the balvi-api server using zero-knowledge proofs. This allows the device to prove it possesses a secret leaf in the server's Merkle tree without revealing the secret itself.

## Files Created

### 1. `app/auth/zkp_auth.h`
Header file defining the ZKP auth API:
- **Status codes**: `ZKP_AUTH_OK`, `ZKP_AUTH_ERR_*`
- **Key functions**:
  - `zkp_auth_init()` - Initialize with device secret
  - `zkp_auth_compute_parent()` - Compute parent commitment from secret
  - `zkp_auth_get_witness()` - Request Merkle witness from server
  - `zkp_auth_get_nonce()` - Get current epoch nonce
  - `zkp_auth_generate_proof()` - Generate ZKP proof
  - `zkp_auth_verify()` - Submit proof and obtain access token
  - `zkp_auth_authenticate()` - Complete auth flow (steps 2-4)
  - `zkp_auth_get_token()` - Retrieve current valid token
  - `zkp_auth_is_token_valid()` - Check token validity

### 2. `app/auth/zkp_auth.c`
Implementation of the auth module:
- **State management**: Stores secret, parent, witness, nonce, proof, and token
- **Base64 encoding/decoding**: Uses mbedTLS for all conversions
- **ZKP operations**: Calls Rust library functions:
  - `zkp_parent_from_secret()` - Compute Poseidon2 hash
  - `zkp_generate_proof()` - Generate SP1 proof
- **HTTP integration**: Calls HTTP client for API requests
- **Error handling**: Comprehensive error checking and debug output

### 3. `app/http/httpss_client.h` (Updated)
Added auth endpoint declarations:
- `witness_response_t` - Response structure for `/auth/witness`
- `nonce_response_t` - Response structure for `/auth/nonce`
- `auth_verify_response_t` - Response structure for `/auth/verify`
- Function declarations for auth API calls

### 4. `app/http/httpss_client.c` (Updated)
Added placeholder implementations for auth endpoints:
- `balvi_api_get_witness()` - POST to `/auth/witness`
- `balvi_api_get_nonce()` - GET from `/auth/nonce`
- `balvi_api_verify_proof()` - POST to `/auth/verify`

**NOTE**: These are currently TODO placeholders with debug output. Full HTTP POST with JSON payloads needs to be implemented using low-level lwIP TCP API.

### 5. `app/crypto/battery_e2e.c` (Updated)
Added `zkp_auth_demo()` function demonstrating the complete auth flow:
1. Initialize with test secret
2. Compute parent commitment
3. Get Merkle witness
4. Get nonce
5. Generate proof
6. Verify proof and obtain token
7. Use token for authenticated requests

### 6. `app/crypto/battery_e2e.h` (Updated)
Added `zkp_auth_demo()` declaration

### 7. `app/CMakeLists.txt` (Updated)
- Added `auth/zkp_auth.c` to sources
- Added `${CMAKE_CURRENT_SOURCE_DIR}/auth` to include directories

## Implementation Status

### ✅ Completed
1. **Data structures** - State storage for secret, witness, nonce, proof, token
2. **Secret initialization** - Base64 decode and store device secret
3. **Parent computation** - Call `zkp_parent_from_secret()` to hash leaves
4. **Proof generation** - Call `zkp_parent_generate_proof()` with witness and nonce
5. **Base64 conversions** - All encode/decode operations for API communication
6. **Token management** - Store and validate access tokens
7. **Demo code** - Complete example showing auth flow
8. **Build integration** - CMakeLists.txt updated

### ⚠️ Partially Implemented
1. **HTTP GET** - Can use existing client, needs JSON parsing
2. **HTTP POST** - Requires low-level TCP implementation with JSON payloads
3. **Token expiry** - Needs timestamp parsing from ISO 8601 format

### 🔴 TODO (Next Steps)
1. **Implement HTTP POST with JSON**
   - Use lwIP `altcp` API directly
   - Build JSON payloads manually (or use lightweight JSON library)
   - Parse JSON responses using `jsmn` (already used for config parsing)

2. **Implement balvi_api_get_nonce()**
   - Use existing HTTP GET client
   - Parse JSON: `{"nonce": "...", "expires_at": "..."}`
   - Extract and decode base64 nonce

3. **Implement balvi_api_get_witness()**
   - POST JSON: `{"commitment_b64": "..."}`
   - Parse JSON: `{"root_b64": "...", "witness_b64": "..."}`
   - Extract and decode base64 witness

4. **Implement balvi_api_verify_proof()**
   - POST JSON: `{"nonce": "...", "proof_bundle": "..."}`
   - Parse JSON: `{"access_token": "...", "expires_at": "..."}`
   - Extract token and expiry

5. **Add timestamp parsing**
   - Parse ISO 8601 timestamps from `expires_at` fields
   - Convert to epoch time for expiry checking

## Test Secret
From Bilal (base64-encoded, 64 bytes decoded):
```
AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==
```

This decodes to:
- Leaf (8 u32): `[1, 2, 3, 4, 5, 6, 7, 8]`
- Sibling (8 u32): `[9, 10, 11, 12, 13, 14, 15, 16]`

## Authentication Flow

```
1. Device Init
   └─> zkp_auth_init(secret_b64)
       └─> Decode base64 → secret16_u32[16]

2. Compute Parent
   └─> zkp_parent_from_secret(secret16_u32)
       └─> Poseidon2(leaf || sibling) → parent8_u32[8]

3. Get Witness
   └─> POST /auth/witness {"commitment_b64": parent_b64}
       └─> Response: {"root_b64": "...", "witness_b64": "..."}

4. Get Nonce
   └─> GET /auth/nonce
       └─> Response: {"nonce": "...", "expires_at": "..."}

5. Generate Proof
   └─> zkp_generate_proof(secret16_u32, witness, nonce)
       └─> SP1 proof → proof_bundle (postcard)

6. Verify Proof
   └─> POST /auth/verify {"nonce": nonce_b64, "proof_bundle": proof_b64}
       └─> Response: {"access_token": "...", "expires_at": "..."}

7. Use Token
   └─> Include in headers: "Authorization: Bearer <token>"
```

## API Endpoints

### GET /auth/nonce
Returns current epoch nonce for proof generation.

**Response**:
```json
{
  "nonce": "base64-encoded-32-bytes",
  "expires_at": "2025-11-08T12:34:56Z"
}
```

### POST /auth/witness
Request Merkle authentication path for parent commitment.

**Request**:
```json
{
  "commitment_b64": "base64-encoded-parent-commitment"
}
```

**Response**:
```json
{
  "root_b64": "base64-merkle-root",
  "witness_b64": "base64-opaque-witness-data"
}
```

**Error**: 404 if parent not found (device not authorized)

### POST /auth/verify
Submit proof for verification and obtain access token.

**Request**:
```json
{
  "nonce": "base64-nonce",
  "proof_bundle": "base64-postcard-proof"
}
```

**Response**:
```json
{
  "access_token": "opaque-bearer-token",
  "expires_at": "2025-11-08T12:34:56Z"
}
```

**Error**: 400 if proof invalid or nonce expired

## Memory Usage

### Static State (`zkp_auth_state_t`)
- Secret: 64 bytes (16 × u32)
- Parent: 32 bytes (8 × u32)
- Witness: 16 KB max
- Nonce: 32 bytes
- Proof: 512 KB max
- Token: 512 bytes
- **Total**: ~529 KB

### Stack Usage (per function call)
- `zkp_auth_compute_parent()`: ~128 bytes (parent_b64 buffer)
- `zkp_auth_verify()`: ~1 MB (proof_b64 base64 expansion)

### Recommendations
- Consider allocating large buffers (proof encoding) in PSRAM
- Proof generation itself uses Rust heap (configured separately)

## Security Considerations

1. **Secret Storage**: Currently in RAM (cleared on reset). Consider:
   - Store in flash (encrypted)
   - Use RP2350 OTP for production secrets

2. **Token Storage**: In-memory only. Acceptable for session-based auth.

3. **Replay Protection**: Nonce-based, enforced by server epoch expiry.

4. **Side-Channel**: ZKP proof generation may leak timing info. Not critical for this use case.

## Next Actions

1. **HTTP POST Implementation** (Priority: HIGH)
   - Critical for witness and verify endpoints
   - Options:
     - Use lwIP `altcp_write()` directly
     - Extend existing `http_client_util` for POST
     - Use third-party HTTP client library

2. **JSON Parsing** (Priority: MEDIUM)
   - Already have `jsmn` for simple parsing
   - Add helper functions for auth responses

3. **Testing** (Priority: HIGH)
   - Test with actual server at `air.gp.xyz`
   - Verify proof generation works with real witness
   - Test token expiry and re-authentication

4. **Integration** (Priority: MEDIUM)
   - Call `zkp_auth_demo()` from `main()`
   - Add to IPC commands for nRF53 control
   - Integrate with `/ingest` endpoint (sensor data upload)
