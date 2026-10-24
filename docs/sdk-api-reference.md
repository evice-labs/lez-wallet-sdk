## Evice Wallet SDK — API Reference Manual

> **Version:** Draft v1.0 (Alpha)  
> **Target Audience:** dApp Developers, Core Module (`wallet-provider`) Integrators, and Native Client Engineers.

## 1. Architectural Overview & API Surfaces

The Evice Wallet SDK exposes two distinct high-level interfaces on top of the headless `SdkEngine`:

1. **`DAppApi` (Untrusted External Surface):**  
   Session-scoped interface accessed by dApps or external consumers. All methods require a valid `SessionId` and enforce granular, per-account privilege checks (`GrantKind`).
2. **`OwnerApi` (Privileged Wallet Controller Surface):**  
   Privileged management interface intended for the wallet host environment (CLI, Desktop QML UI, or Core Module). Governs key generation, storage locking, account derivation, and access grant issuance.
3. **`C-ABI FFI Layer` (`crates/sdk-ffi`, `include/lez_wallet_sdk.h`):**  
   C-compatible linkage layer with opaque engine handles, ABI-stable JSON serialization, panic boundaries (`catch_unwind`), and non-blocking approval callback dispatch.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CONSUMER APPLICATIONS                           │
│   ┌───────────────────────────┐      ┌─────────────────────────────┐   │
│   │   External LEZ dApp       │      │   Logos Basecamp / Desktop  │   │
│   └─────────────┬─────────────┘      └──────────────┬──────────────┘   │
└─────────────────┼───────────────────────────────────┼──────────────────┘
                  │ Session-Scoped IPC                │ Privileged Host
                  ▼                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      C-ABI INTEROPERABILITY LAYER                      │
│   `crates/sdk-ffi` (Header: `include/lez_wallet_sdk.h`)                 │
│   • Opaque Pointer: `*mut FfiSdkEngine`                                │
│   • Memory Lifecycle: `lez_wallet_free_string(char*)`                  │
│   • Non-Blocking Bridge: `FfiApprovalCallback` + Deferred Submission   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          CORE SDK ENGINE                               │
│   `crates/sdk-engine`                                                  │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      DAppApi (Session Guard)                   │   │
│   ├────────────────────────────────────────────────────────────────┤   │
│   │                      OwnerApi (Privileged)                     │   │
│   ├────────────────────────────────────────────────────────────────┤   │
│   │ Subsystems: Decoders | Verifiers | LNS Resolver | SSS Identity │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

## 2. Wire Format & Response Envelope

All structured data across the C-ABI FFI boundary is formatted as UTF-8 encoded JSON. Responses follow a standardized envelope:

### Success Response
```json
{
  "ok": true,
  "...": "<method-specific payload>"
}
```

### Error Response
```json
{
  "ok": false,
  "error": "Descriptive error message string"
}
```

### Memory Management Rule
Any `*mut c_char` returned by `lez_wallet_*` functions is allocated by Rust using standard heap allocators. The caller **must** deallocate it by passing the pointer to `lez_wallet_free_string(ptr)`. Passing a null pointer is safe (no-op).

## 3. `DAppApi` Reference Specification

### 3.1 `sdk_info`
Retrieves engine metadata, API compatibility version, and runtime status.
- **FFI Signature:** `lez_wallet_sdk_info(engine: *mut FfiSdkEngine) -> *mut c_char`
- **Session Required:** No.
- **Response Format:**
```json
{
  "ok": true,
  "sdk_version": "0.1.0",
  "api_version": 1,
  "network": "standalone-local",
  "wallet_initialized": true,
  "wallet_locked": false
}
```

### 3.2 `connect`
Initializes an isolated, timestamped dApp session with protocol version handshake.
- **FFI Signature:** `lez_wallet_connect(engine: *mut FfiSdkEngine, caller_identity: *const c_char, api_version: u32) -> *mut c_char`
- **Parameters:**
  - `caller_identity`: Human-readable identifier of the calling dApp (e.g. `"uniswap.lez"` or `"portal-app"`).
  - `api_version`: Expected protocol version (currently `1`).
- **Response Format:**
```json
{
  "ok": true,
  "session_id": "sess_01J98X..."
}
```

### 3.3 `disconnect`
Explicitly closes an active session, invalidating all associated ephemeral grants.
- **FFI Signature:** `lez_wallet_disconnect(engine: *mut FfiSdkEngine, session_id: *const c_char) -> *mut c_char`
- **Response Format:** `{"ok": true}`

### 3.4 `request_accounts` & `list_accounts`
Returns accounts authorized for the given session.
- **FFI Signatures:**
  - `lez_wallet_request_accounts(engine: *mut FfiSdkEngine, session_id: *const c_char) -> *mut c_char`
  - `lez_wallet_list_accounts(engine: *mut FfiSdkEngine, session_id: *const c_char) -> *mut c_char`
- **Privilege Required:** Requires at least one active grant for the account.
- **Response Format:**
```json
{
  "ok": true,
  "accounts": [
    {
      "account_id": "44KVvzvh2ephQU9aR5snboGUXKgS1FnPYh1W4KZKwmhm",
      "privacy": "public",
      "label": "Primary Treasury",
      "balance": 10000000000
    }
  ]
}
```

### 3.5 `get_balance`
Fetches the balance of an authorized account in native atomic units.
- **FFI Signature:** `lez_wallet_get_balance(engine: *mut FfiSdkEngine, session_id: *const c_char, account_id: *const c_char) -> *mut c_char`
- **Privilege Required:** `GrantKind::Read`.
- **Response Format:**
```json
{
  "ok": true,
  "balance": 500000000
}
```

### 3.6 `propose_native_transfer`
Proposes a native token transfer. Computes an immutable intent hash and dispatches for user approval.
- **FFI Signature:**
  ```c
  char* lez_wallet_propose_native_transfer(
      FfiSdkEngine* engine,
      const char* session_id,
      const char* from_account,
      const char* to_account_or_name,
      const char* amount_str
  );
  ```
- **Privilege Required:** `GrantKind::Propose` on `from_account`.
- **Destination Support:** Accepts standard Base58 `AccountId` or human-readable `.lez` names (e.g. `"alice.lez"`).
- **Response Format:**
```json
{
  "ok": true,
  "request_id": "req_01J98Y...",
  "status": "pending_approval"
}
```

### 3.7 `propose_token_transfer`
Proposes a transfer of custom fungible tokens defined under the LEZ token program.
- **FFI Signature:**
  ```c
  char* lez_wallet_propose_token_transfer(
      FfiSdkEngine* engine,
      const char* session_id,
      const char* from_account,
      const char* to_account_or_name,
      const char* token_id,
      const char* amount_str
  );
  ```
- **Privilege Required:** `GrantKind::Propose` on `from_account`.
- **Response Format:**
```json
{
  "ok": true,
  "request_id": "req_01J98Z...",
  "status": "pending_approval"
}
```

### 3.8 `get_request_status` & `cancel_request`
Monitors or cancels the lifecycle of an immutable request proposal.
- **FFI Signatures:**
  - `lez_wallet_get_request_status(engine: *mut FfiSdkEngine, request_id: *const c_char) -> *mut c_char`
  - `lez_wallet_cancel_request(engine: *mut FfiSdkEngine, request_id: *const c_char) -> *mut c_char`
- **Possible Statuses:**
  - `pending_approval`: Waiting for user confirmation.
  - `approved`: Confirmed by user, preparing on-chain submission.
  - `submitted`: Dispatched to sequencer with `tx_hash`.
  - `rejected`: Explicitly rejected by user or expired via timeout.
  - `failed`: On-chain execution failure with error reason.
- **Response Format:**
```json
{
  "ok": true,
  "status": "submitted",
  "tx_hash": "a1b2c3d4..."
}
```

### 3.9 `resolve_name`
Resolves a human-readable `.lez` domain name using the clean-room Logos Name Service (LNS) client against live on-chain registry state.
- **FFI Signature:** `lez_wallet_resolve_name(engine: *mut FfiSdkEngine, session_id: *const c_char, name: *const c_char) -> *mut c_char`
- **Parameters:**
  - `session_id`: Active authorized session identifier.
  - `name`: Target `.lez` domain name (e.g. `"alice.lez"` or `"jef.lez"`).
- **Resolution Protocol (SPEC.md):**
  1. **Normalisation:** Trims whitespace, lowers ASCII case, verifies `[a-z0-9-]{1,32}` without leading/trailing hyphens.
  2. **Key Derivation:** Computes `Argon2id(name, "logos-names/v5", 64MiB, 3, 1)` -> `id` (`SHA-256("logos-names/v5/id" || master)`) and `key` (`SHA-256("logos-names/v5/key" || master)`).
  3. **PDA Calculation:** Derives `seed = SHA-256("logos-names/v5/name/" || id)` and public PDA `SHA-256(pad32("/LEE/v0.2/AccountId/PDA/") || registry || seed)`.
  4. **State Query:** Fetches on-chain account state from LEZ Sequencer JSON-RPC (`getAccount`), extracting the registry shard.
  5. **Borsh Decoding & Expiry:** Decodes `NameRecord` and checks expiration (epoch ms; deposit v5 never lapses, active terms checked against 30-day grace period of 2,592,000,000 ms).
  6. **AES-256-GCM Decryption:** Opens sealed profile payload with 12-byte nonce, 16-byte authentication tag, and Associated Data `b"logos-names/v5/record"`.
  7. **Profile Deserialization:** Decodes Borsh `Profile` (ignoring zero-padding bytes) and verifies `profile.name == input_name`.
- **Response Format:**
```json
{
  "ok": true,
  "name": "alice",
  "account": "44KVvzvh2ephQU9aR5snboGUXKgS1FnPYh1W4KZKwmhm",
  "npk": null,
  "vpk": null,
  "expires": 1893456000000,
  "texts": [
    ["chat", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
  ]
}
```

### 3.10 Identity Accountability API
Client-side primitives for accountable pseudonymity:
- **`request_identity_access`:** Requests `IdentityRead` or `IdentityPropose` grants for a session.
- **`get_identity_commitment`:** Generates deterministic master identity commitment `SHA-256("lez/identity/v1/commitment" || secret)`.
- **`derive_scoped_nullifier`:** Computes cross-dApp unlinkable nullifier `SHA-256("lez/identity/v1/scoped_nullifier" || secret || scope_id)`.
- **`sign_identity_attestation`:** Produces a 64-byte BIP-340 Schnorr signature over custom payloads.
- **`prepare_identity_registration`:** Prepares Two-Tier Shamir Secret Sharing (SSS) threshold encrypted recovery shares over GF(2^8).

## 4. `OwnerApi` Reference Specification

Privileged interface restricted to the wallet owner / host environment:

| Method Signature (C-ABI) | Description | Parameters |
|---|---|---|
| `lez_wallet_create_wallet(engine, password)` | Generates a new master BIP-39 mnemonic phrase and initializes encrypted storage. | `password`: Non-empty master passphrase. |
| `lez_wallet_restore_wallet(engine, mnemonic, password)` | Restores an existing wallet from a 12- or 24-word recovery phrase. | `mnemonic`: Normalized space-delimited phrase; `password`: New passphrase. |
| `lez_wallet_lock(engine)` | Immediately zeroes key material in memory and clears cached session states. | None. |
| `lez_wallet_unlock(engine, password)` | Re-derives encryption keys and unlocks local storage. | `password`: Master passphrase. |
| `lez_wallet_create_account_public(engine, label)` | Derives a new transparent public account (`Public/...`). | `label`: Optional UTF-8 display alias. |
| `lez_wallet_create_account_private(engine, label)` | Derives a new shielded zero-knowledge private account. | `label`: Optional UTF-8 display alias. |
| `lez_wallet_list_all_accounts(engine)` | Lists all registered accounts with labels, types, and balances. | None. |
| `lez_wallet_grant_account(engine, session_id, account_id, grant_kind)` | Issues an explicit privilege grant to an active dApp session. | `grant_kind`: `"read"` or `"propose"`. |
| `lez_wallet_revoke_session(engine, session_id)` | Immediately revokes an authorized session and all its grants. | `session_id`: Target session identifier. |
| `lez_wallet_set_account_label(engine, account_id, label)` | Renames or sets a human-readable alias on an account. | `account_id`: Target account; `label`: New alias string. |

## 5. Non-Blocking Approval Modal Bridge

To eliminate UI freezes and support asynchronous desktop dialogs (e.g. Qt/QML modals in Basecamp), the SDK implements a callback bridge:

### Step 1: Register Callback
```c
int on_approval_prompt(const char* prompt_json, void* user_data);

lez_wallet_set_approval_callback(engine, on_approval_prompt, host_context);
```

### Step 2: Callback Return Semantics
When an action requiring user consent occurs (e.g. `propose_native_transfer`):
- Return `1`: **Synchronous Approve** (immediate confirmation).
- Return `0`: **Synchronous Reject** (immediate denial).
- Return `-1`: **Asynchronous / Deferred** (host opens a modal dialog; resolution occurs later via `lez_wallet_submit_approval_decision`).

### Step 3: Deferred Resolution
Once the user confirms or dismisses the UI dialog:
```c
// decision: 1 for Approve, 0 for Reject
lez_wallet_submit_approval_decision(engine, request_id, 1);
```

## 6. Error Codes & Diagnostics

Errors returned inside `{"ok": false, "error": "..."}` adhere to the following categories:

| Error Category | Identifier / Prefix | Description | Remediation |
|---|---|---|---|
| **Authentication** | `WalletLocked` | Operation attempted while wallet core is locked. | Call `unlock(password)` before invoking the method. |
| **Session** | `SessionNotFound` / `SessionExpired` | The supplied `session_id` does not exist or has exceeded its TTL. | Re-authenticate via `connect()`. |
| **Authorization** | `PermissionDenied` | The session lacks required `GrantKind` for the account. | User must authorize access via `grant_account()`. |
| **Validation** | `InvalidArgument` | Invalid account address, malformed Base58 string, or zero amount. | Correct input parameter format. |
| **Name Resolution** | `NameResolutionError` | `.lez` domain is unregistered or expired. | Verify domain registration status on LNS. |
| **TOCTOU Guard** | `IntentHashMismatch` | Transaction parameters were mutated between proposal and signing. | Reject request; regenerate fresh proposal. |
| **Sequencer** | `SequencerRpcError` | Upstream LEZ sequencer node is unreachable or returned RPC error. | Verify local container via `just dev-health`. |
