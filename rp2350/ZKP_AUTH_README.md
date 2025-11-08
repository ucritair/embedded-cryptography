# ZKP Authentication Flow

## Overview
The device proves it possesses a secret leaf in the server's Merkle tree without revealing the secret itself. This proves device identity/authorization.

---

## Authentication Steps

### 1. Initial Setup (One-time)
- **Device has**: 64-byte secret (two 32-byte leaves)
  - Format: `secret16_u32[16]` = `[leaf(8 u32) | sibling(8 u32)]`
  - Given base64: `AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==`
- **Server has**: Merkle tree containing all authorized device leaves
  - Current Merkle root published in `/config` endpoint

### 2. Compute Parent Commitment (Device-side)
```c
// Call: zkp_parent_from_secret(secret16_u32, parent8_u32_out)
```
- **Purpose**: Hash the two secret leaves to get the parent node commitment
- **Function**: Uses Poseidon2 hash with selector=0
- **Input**: `secret16_u32[16]` (your 64-byte secret)
- **Output**: `parent8_u32[8]` (32-byte parent commitment)

### 3. Request Merkle Witness (Device → Server)
**Endpoint**: `POST /auth/witness`
```json
{
  "commitment_b64": "<base64 of parent8_u32>"
}
```
- **Server action**: Looks up parent commitment in Merkle tree
- **Server returns**:
  - `root_b64`: Merkle root (should match `/config`)
  - `witness_b64`: Opaque postcard-serialized path from parent→root
    - Contains: `(neighbors8_by_level_u32, sides_bitflags)`
    - This is the authentication path through the tree

### 4. Get Current Nonce (Device → Server)
**Endpoint**: `GET /auth/nonce`
```json
{
  "nonce": "<base64, 32 bytes>",
  "expires_at": "2025-11-08T12:34:56Z"
}
```
- **Purpose**: Prevent replay attacks
- **Note**: Nonce is shared across all devices for an epoch
- **Important**: Proof must be generated and submitted before expiry

### 5. Unpack Witness (Device-side)
- **Input**: `witness_b64` from step 3
- **Action**: Deserialize postcard bytes to extract:
  - `neighbors8_by_level_u32[]`: Sibling hashes at each level
  - `sides_bitflags[]`: Left/right orientation flags
- **Use these as inputs to `zkp_pack_args()`** (or pass witness bytes directly if already in correct format)

### 6. Generate ZKP Proof (Device-side)
```c
// Call: zkp_generate_proof(secret16_u32, args, args_len, nonce32,
//                          proof_out, proof_out_len, &proof_written)
```
**Inputs**:
- `secret16_u32[16]`: Your original secret (both leaves)
- `args`: Postcard-serialized witness from step 3 (or repacked via `zkp_pack_args`)
- `nonce32`: 32-byte nonce from step 4

**Output**:
- `proof_out`: Postcard-serialized bundle containing:
  - ZK proof itself
  - Public values: `[root(8) | nonce_field(8) | hash(leaf||nonce)(8)]`

**What the proof proves**:
- "I know a secret leaf in the Merkle tree with this root"
- "I'm using the current nonce" (freshness)
- Without revealing which leaf or the secret itself

### 7. Submit Proof for Verification (Device → Server)
**Endpoint**: `POST /auth/verify`
```json
{
  "nonce": "<base64, same as step 4>",
  "proof_bundle": "<base64 of proof_out from step 6>"
}
```

**Server verifies**:
- Proof is cryptographically valid
- Nonce matches current epoch nonce
- Merkle root in public values matches server's current root

**Server returns** (on success):
```json
{
  "access_token": "<bearer token>",
  "expires_at": "2025-11-08T12:34:56Z"  // Expires at epoch boundary
}
```

### 8. Use Access Token
- **Store**: `access_token` in memory
- **Use**: Include in all authenticated requests (e.g., `POST /ingest`)
  - Header: `Authorization: Bearer <access_token>`
- **Expiry**: Token valid until epoch boundary (same as nonce expiry)
- **Re-auth**: When token expires, repeat steps 4-7 (witness can be reused if root hasn't changed)

---

## Implementation Plan

### Phase 1: Parent Computation & Witness Retrieval
1. Decode the base64 secret to `uint32_t secret16_u32[16]`
2. Call `zkp_parent_from_secret()` to compute parent commitment
3. Encode parent as base64
4. HTTP POST to `/auth/witness` with parent commitment
5. Store returned witness bytes

### Phase 2: Nonce & Proof Generation
6. HTTP GET to `/auth/nonce` to get current nonce
7. Decode nonce from base64
8. Call `zkp_generate_proof()` with:
   - Secret leaves
   - Witness bytes (args)
   - Current nonce
9. Encode proof bundle as base64

### Phase 3: Verification & Token Management
10. HTTP POST to `/auth/verify` with nonce + proof bundle
11. Parse response to extract `access_token` and `expires_at`
12. Store token in global config structure
13. Add helper function to include `Authorization: Bearer` header in requests

### Phase 4: Token Lifecycle
14. Check token expiry before making authenticated requests
15. Auto-refresh token when expired (re-run steps 4-7)
16. Handle 401 responses by triggering re-authentication

---

## Key Implementation Details

### Data Conversions Needed
- Base64 decode secret string → `uint32_t[16]`
- `uint32_t[8]` parent → base64 string
- Base64 nonce → `uint8_t[32]`
- `uint8_t[]` proof → base64 string

### Error Handling
- 404 on `/auth/witness` = secret not in tree (unauthorized device)
- 400 on `/auth/verify` = invalid proof or expired nonce
- Token expiry tracking to avoid 401 errors

### Code Organization
- Create `app/auth/zkp_auth.c` and `app/auth/zkp_auth.h`
- Functions:
  - `zkp_auth_init(const char* secret_b64)` - Store secret
  - `zkp_auth_get_witness()` - Steps 2-3
  - `zkp_auth_generate_and_verify()` - Steps 4-7
  - `zkp_auth_get_token()` - Return current valid token
  - `zkp_auth_is_token_valid()` - Check expiry

---

## Device Secret (Test)
```
AQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAAA==
```
