## Evice Wallet SDK

> **Evice Wallet & Provider SDK for Logos Execution Zone** — A modular, high-performance wallet engine and dApp integration SDK for the Logos Execution Zone (LEZ).

## Overview

Provides the foundational wallet infrastructure, developer SDK, and integration tooling for the Logos Execution Zone (LEZ). For comprehensive technical details on the underlying engine, security models, and subsystems, refer to [ARCHITECTURE.md](docs/ARCHITECTURE.md).

It solves the core challenges of asset custody, dApp communication, and transaction security on LEZ:
- **Full LEZ Asset & Account Management:** Unified handling of native and token-program assets across both public and private (shielded) accounts.
- **Wallet Provider SDK:** Robust, asynchronous dApp-facing API enabling external applications to connect, request account access, read balances, and propose transactions.
- **Informed Consent & Approval UX:** Every transaction proposal produces human-readable instruction summaries, simulated balance/state diffs, and bytecode source verification status before signing.
- **Privacy-Preserving Name Resolution:** Built-in clean-room resolver for human-readable `.lez` names (Logos Name Service, SPEC.md) using off-chain Argon2id key derivation, live on-chain sequencer PDA lookups, and AES-256-GCM sealed profile decryption.
- **Client-Side Identity Accountability:** Native accountable pseudonymity featuring master identity commitments, cross-dApp unlinkable scoped nullifiers, BIP-340 Schnorr attestations, and Two-Tier Shamir Secret Sharing (SSS).
- **Decoupled Three-Layer Architecture:** Pure Rust core logic (`sdk-engine`) with zero GUI dependencies, accessible via C-ABI (`sdk-ffi`) for Logos Basecamp modules and via CLI.

## Workspace Structure

The workspace is structured into specialized, decoupled crates under `crates/`:

```
lez-wallet-sdk/
├── Cargo.toml                  # Workspace manifest and pinned dependencies
├── SUBMISSION_ID               # Unique submission identifier for on-chain testimonials
├── Dockerfile                  # Multi-stage container build for standalone LEZ sequencer
├── docker-compose.yml          # Container orchestration runner for local dev-env
├── Justfile                    # Declarative task runner (just dev-start, dev-health, dev-fund)
├── LICENSE-MIT / LICENSE-APACHE
├── crates/
│   ├── sdk-engine/             # Core wallet engine (pure Rust, no Qt)
│   ├── sdk-ffi/                # C-ABI FFI layer for Basecamp module binding
│   ├── cli/                    # Command-line interface (`evice-wallet`)
│   └── evidence-tool/          # Adoption verification tool for on-chain testimonials
├── programs/
│   └── testimonial-program/    # On-chain testimonial smart contract (RISC-V zkVM guest)
├── tools/
│   └── dispatcher/             # Program deployment and on-chain dispatch CLI (`lez-dispatcher`)
├── deployments.json            # On-chain program deployment registry (testnet 0.3 - 0.4 & dev-env)
├── dev-env/                    # Standalone development environment & genesis fixtures
│   ├── genesis_accounts.json   # Pre-funded Alice, Bob, and shielded circuit accounts
│   ├── sequencer_config.json   # Standalone genesis parameters and mock channel config
│   ├── wallet_config.json      # SDK & CLI RPC connection settings (http://127.0.0.1:3040)
│   └── README.md               # Standalone development environment guide
├── integration-tests/          # End-to-end integration test suites
├── docs/                       # Specifications and technical documentation
│   ├── ARCHITECTURE.md         # Comprehensive system architecture & technical specification
│   ├── sdk-api-reference.md    # Complete SDK API reference & JSON wire format
│   ├── program-deployment.md   # Smart contract compilation, deployment & dispatcher guide
│   └── testnet-deployment-evidence.md # On-chain testnet deployment logs, block heights & transaction hashes
└── .github/workflows/          # Multi-platform CI workflows (Linux & macOS)
```

## Implemented Architecture & Features

#### 1. Granular Session & Permission Management (`session.rs`)
- Connections from external dApps open an isolated, ephemeral in-memory `Session`.
- Grants are assigned per-account and per-capability with specific privileges:
  - `GrantKind::Read`: Permission to inspect balances and program states.
  - `GrantKind::Propose`: Permission to submit transaction proposals for user approval.
  - `GrantKind::IdentityRead`: Permission to read public identity commitments and derive scoped nullifiers.
  - `GrantKind::IdentityPropose`: Permission to sign cryptographic attestations and construct threshold registration payloads.
- Sessions include automatic timestamped expiration (`DEFAULT_SESSION_DURATION`).

#### 2. Immutable Requests & Intent Hashing (`request.rs`)
- Propose calls (`proposeNativeTransfer`, `proposeTokenTransfer`, `proposeTransaction`) immediately return a `RequestId`.
- The engine computes a deterministic 32-byte SHA-256 intent hash (`evice-wallet-sdk/intent/v1/`) binding the request ID, session ID, and serialised parameters.
- The hash is verified before execution, eliminating Time-of-Check to Time-of-Use (TOCTOU) tampering.

#### 3. Asynchronous Non-Blocking Approvals (`approval.rs`)
- The pluggable `ApprovalHandler` trait allows user authorization without blocking UI or async runtimes:
  - `CliApprovalHandler`: Formatted terminal modal prompt reading interactive user input.
  - `UiApprovalHandler`: Bridge routing prompts to Basecamp desktop QML modals.
  - `PolicyApprovalHandler`: Auto-approval policy feature-gated behind `dev-auto-approve` (audited by CI to ensure absence from release builds).

#### 4. Instruction Decoders & Effect Simulation (`decode/`, `effects.rs`)
- The `DecoderRegistry` automatically inspects program calldata and converts raw bytes into human-readable operations:
  - Native token transfers.
  - Token program operations (holding creation, mint, burn, transfer).
  - Associated Token Accounts (ATA).
  - Testimonial program submissions.
- `EffectSimulator` pre-calculates balance changes and state mutations (`EffectSource::Simulation`), preventing blind signing.

#### 5. Program Source Verification (`verifier.rs`)
- Integrates source-code reproducibility verification based on reproducible smart contract registry standards.
- Displays `VerificationStatus::Verified`, `NotVerified`, or `NotChecked` alongside compiler and source repository metadata.

#### 6. Clean-Room LNS Resolver (`resolve/lns.rs`)
- Full, independent implementation of [SPEC.md](https://github.com/jefdiesel/logos-names/blob/main/SPEC.md) for `.lez` domain resolution.
- Normalises names (`[a-z0-9-]{1,32}`), derives master keys via Argon2id (64 MiB, 3 passes, salt `"logos-names/v5"`), and computes on-chain PDA account addresses (`SHA-256(pad32("/LEE/v0.2/AccountId/PDA/") || program || seed)`).
- Live on-chain resolution via LEZ Sequencer JSON-RPC (`getAccount`), decoding Borsh `NameRecord` state and validating millisecond timestamps against 30-day grace periods.
- AES-256-GCM sealed profile decryption bound to associated data `logos-names/v5/record`, deserializing Borsh `Profile` records (with zero-padding tolerance) and verifying `profile.name == input_name`.
- In-memory cache with 5-minute TTL, cleared automatically upon wallet lock.
- User-controllable toggle (`lns_enabled`) with graceful fallback to raw 32-byte account IDs.

#### 7. Resilient Storage (`store.rs`)
- Atomic persistence using write-then-rename (`.tmp` → target file) preventing state corruption during unexpected crashes or power loss.
- Automatic `.bak` backup retention and fallback recovery.

#### 8. Identity Accountability & Accountable Pseudonymity (`identity/`)
- Pure client-side zero-knowledge accountable pseudonymity derived from the master BIP-39 root seed (`lez/identity/v1/secret`).
- Public identity commitments (`SHA-256("lez/identity/v1/commitment" || secret)`) for on-chain governance and community registry membership.
- Cross-dApp unlinkable scoped nullifiers (`SHA-256("lez/identity/v1/scoped_nullifier" || secret || scope_id)`).
- BIP-340 Schnorr attestations (`k256::schnorr`) producing 64-byte signatures over arbitrary message payloads.
- Two-Tier Shamir Secret Sharing (SSS) over GF(2^8) via `sharks` crate, encrypting threshold shares to designated accountability trustees using secp256k1 ECDH with XOR keystream encryption.
- Memory protection via `ZeroizeOnDrop` and automatic clearing upon wallet lock.

#### 9. Comprehensive C-ABI FFI & Basecamp Interop Layer (`crates/sdk-ffi`, `include/lez_wallet_sdk.h`)
- Native C-ABI surface (`extern "C"`) exporting opaque engine handles (`FfiSdkEngine`), built as `cdylib`, `staticlib`, and `rlib`.
- Panic-safe execution boundary wrapping operations in `catch_unwind` and returning ABI-safe JSON payloads (`{"ok": true, ...}` / `{"ok": false, "error": "..."}`).
- Non-blocking approval bridge (`FfiApprovalCallback`) supporting synchronous decisions and asynchronous deferred decision submission (`lez_wallet_submit_approval_decision`) for Qt/QML modals.
- Complete coverage of `OwnerApi`, `DAppApi`, and Identity Accountability APIs.
- Header generation via `cbindgen` producing [`include/lez_wallet_sdk.h`](include/lez_wallet_sdk.h) with strict C/C++ linkage guards.

#### 10. Comprehensive Command-Line Interface (`crates/cli`, `evice-wallet`)
- Standalone, zero-dependency terminal binary dispatching directly to the headless `SdkEngine` core.
- **Robust Terminal Security:** Zero-echo password prompting via `rpassword::prompt_password` preventing shoulder surfing and terminal scrollback leaks (CWE-522), mandatory password confirmation on wallet creation/restoration to eliminate typo lockouts, and explicit storage overwrite protection requiring `--force`.
- **4-Direction Asset Transfers & LNS:** Supports `public`, `shield`, `unshield`, and `private` transfers with non-zero amount validation, account privacy verification, and transparent `.lez` domain resolution.
- **Interactive Informed Consent:** Terminal approval modal (`CliApprovalHandler`) displaying human-readable operation summaries, simulated balance diffs, and verification status with `--yes` auto-approval support for scripts.
- **Token Management:** Full support for fungible token definitions, holding initialization, minting, burning, and transfers.
- **Human-Centric Presentation:** Mnemonic recovery phrases displayed in a clean, numbered 3-column grid (`1. word   2. word   3. word`), preventing line-wrapping across 12- and 24-word phrases.

#### 11. Standalone Development Environment (`dev-env`, Docker, Justfile)
- **Containerized LEZ Sequencer:** Multi-stage `Dockerfile` packaging an authentic `sequencer_service` running in `--features standalone` mode with an in-memory mocked Bedrock L1 layer.
- **Fast Proving Execution:** Operates under `RISC0_DEV_MODE=1` producing transaction validation and state commitments in milliseconds without zkVM STARK proving latency.
- **Zero Faucet Dependency:** Pre-funded genesis accounts ([`genesis_accounts.json`](dev-env/genesis_accounts.json)) with Alice (dispenser, 10T units) and Bob (counterparty, 20T units), plus shielded pools, insulating local development from external network conditions.
- **Task Runner Orchestration:** Unified commands in root [`Justfile`](Justfile) (`just dev-start`, `just dev-stop`, `just dev-health`, `just dev-logs`, `just dev-fund`, `just dev-clean`) and root [`docker-compose.yml`](docker-compose.yml).
- **Comprehensive Documentation:** Full setup, account tables, and operational workflows documented in [`dev-env/README.md`](dev-env/README.md).

#### 12. On-Chain Smart Contract, Program Deployment & Dispatcher (`programs/`, `tools/`, `deployments.json`)
- **zkVM Testimonial Smart Contract (`programs/testimonial-program`):** Embeds `SUBMISSION_ID` into submitter PDA records with strict invariant checks ($\le 280$ byte text, $\le 64$ byte moniker, submitter deduplication per submission ID).
- **On-Chain Dispatcher Tool (`tools/dispatcher`, `lez-dispatcher`):** CLI tool for chunked program bytecode deployment via `ProgramLoader`, sending on-chain testimonial transactions, checking registry status, and dispatching raw instructions.
- **Unified Deployment Registry (`deployments.json`):** Tracks deployed program header accounts across `standalone` (local) and `testnet` (public) environments, dynamically linked with `BuiltinVerifier` and `TestimonialDecoder`.
- **Adoption Evidence Auditing (`crates/evidence-tool`):** Audits on-chain testimonial records against LP-0021 criteria (150 distinct submitters across required intervals).
- **Comprehensive Guide:** Complete build, deploy, and dispatch instructions documented in [`docs/program-deployment.md`](docs/program-deployment.md).

## Quick Start

### Prerequisites
- **Rust Toolchain:** Pinned to Rust 1.98.1+ via `rust-toolchain.toml`.
- **LEZ Monorepo:** Pinned directly via Cargo Git dependencies tracking `https://github.com/logos-blockchain/logos-execution-zone` (`dev` branch), making the SDK completely standalone without requiring local sibling checkouts.

### Building & Checking
Commands can be run via the [`Justfile`](Justfile) task runner or directly with `cargo`:

```bash
# Clone the repository
git clone https://github.com/evice-labs/lez-wallet-sdk.git
cd lez-wallet-sdk

# Using Just task runner
just build            # Compile all workspace crates
just test             # Run full test suite (all 50 tests across engine, ffi, and integration-tests)
just lint             # Check clippy lints with warnings as errors
just header           # Generate C/C++ FFI header via cbindgen

# Or using standard Cargo directly
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### Standalone Development Environment (Local Sequencer)

Run an authentic LEZ sequencer locally with zero external network dependency and pre-funded genesis accounts:

```bash
# Start standalone sequencer in background via Docker Compose
just dev-start        # or: docker compose up -d

# Verify JSON-RPC health probe (http://127.0.0.1:3040)
just dev-health

# Stream live sequencer container logs
just dev-logs

# Disburse initial funds from Genesis Alice to an account address or .lez name
just dev-fund Public/891ae258f92ca8447af6cf09c41d96b3a06187d098b91ab2cc17b42e3c4a2fa1 10000000

# Stop the local sequencer
just dev-stop         # or: docker compose down

# Wipe sequencer data to reset genesis state
just dev-clean
```

For developer workstations without a Docker daemon, launch directly via native Cargo:
```bash
just dev-native-start
```

See [`dev-env/README.md`](dev-env/README.md) for full architectural details, pre-funded key tables, and configuration options.

### Running the CLI

```bash
# Display full CLI help and list of all available commands
cargo run --bin evice-wallet -- --help

# Display SDK version, API version, and network diagnostics
cargo run --bin evice-wallet -- info

# Initialize a new wallet with zero-echo password and 24-word recovery phrase
cargo run --bin evice-wallet -- wallet create

# Derive transparent public and shielded private accounts
cargo run --bin evice-wallet -- account create-public --label "Alice Public"
cargo run --bin evice-wallet -- account create-private --label "Bob Shielded"

# List all accounts with privacy types, labels, and balances
cargo run --bin evice-wallet -- account list

# Propose a transfer (accepts raw account addresses or human-readable .lez names)
cargo run --bin evice-wallet -- transfer public --from <FROM_ADDR> --to alice.lez --amount 100

# Perform offline clean-room .lez name resolution (Argon2id 64 MiB, 3 passes + PDA calculation)
cargo run --bin evice-wallet -- resolve alice.lez

# Identity Accountability: Inspect master public commitment
cargo run --bin evice-wallet -- identity commitment

# Identity Accountability: Derive cross-dApp unlinkable scoped nullifier
cargo run --bin evice-wallet -- identity nullifier --scope "dao_voting_room"

# Identity Accountability: Sign verifiable BIP-340 Schnorr attestation
cargo run --bin evice-wallet -- identity attest --scope "dao_voting_room" --message "Vote YES on Proposal 42"
```

### On-Chain Program Deployment & Testimonials (`lez-dispatcher`)

Deploy smart contracts and submit testimonials attributed to `SUBMISSION_ID` using `Justfile` tasks or `lez-dispatcher`:

```bash
# Check current deployment registry status
just status
# or: cargo run -p lez-dispatcher -- status

# Deploy program binary to standalone local sequencer via ProgramLoader
just deploy-program <path-to-bin> standalone
# or: cargo run -p lez-dispatcher -- deploy --bin <path-to-bin> --network standalone

# Submit an on-chain testimonial attributed to SUBMISSION_ID
just submit-testimonial "Built with Evice Wallet SDK! Fast, private, and developer-friendly." "alice"
# or: cargo run -p lez-dispatcher -- submit-testimonial --text "..." --username "alice"

# Run adoption criteria audit across sequencer records
just audit-evidence
# or: cargo run -p evidence-tool
```

### Self-Contained Demo

Execute the demo script to verify build integrity, C-ABI generation, CLI diagnostics, offline name resolution, and submission identifier output:

```bash
./demo.sh
```

## Continuous Integration & Quality Assurance

Automated GitHub Actions workflows are configured in `.github/workflows/`:
- **`ci-linux.yml`:** Runs on `ubuntu-latest` validating `cargo check`, `cargo test`, `cargo clippy`, and verifies the complete absence of test auto-approval symbols (`PolicyApprovalHandler`) in release binaries.
- **`cli-e2e.yml`:** Builds workspace binaries, executes the complete end-to-end CLI validation suite in an isolated runner environment, and validates `./demo.sh`.
- **`ci-macos.yml`:** Runs on `macos-latest` ensuring full macOS compilation and test suite compatibility.
- **`testnet-smoke.yml`:** Periodic weekly and on-demand workflow running live integration smoke tests verifying Wallet CLI info, LNS offline derivation, multi-network deployment registry, and testnet adoption evidence auditing.

## Security & Privacy Guarantees

- **No Telemetry:** Zero analytics, metrics, or telemetry are collected or transmitted.
- **No Mandatory External Services:** All core wallet functions, key management, and transactions communicate solely with the user's configured LEZ sequencer node.
- **Client-Side Cryptography:** All private key derivations, Argon2id computations, and transaction signings occur exclusively on the local machine.
- **Explicit User Consent:** A dApp cannot sign transactions, read private balances, or mutate state without explicit, per-account user authorization.

## Acknowledgments & Attribution

- **Logos Name Service (LNS):** We gratefully acknowledge **Jef** ([@jefdiesel](https://github.com/jefdiesel)) for designing and publishing the open protocol specification for the Logos Name Service ([SPEC.md](https://github.com/jefdiesel/logos-names/blob/main/SPEC.md)) on the Logos Execution Zone. This SDK includes an independent, clean-room Rust implementation of the client-side name resolution protocol.
- **Identity Accountability Architecture:** The accountable pseudonymity model, deterministic identity commitments, and threshold accountability primitives are designed by **Evice Labs**, adapted from the [`e-identity-stack`](https://github.com/evice-labs/e-identity-stack) repository for native integration into the Logos Execution Zone.

## License

Dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
