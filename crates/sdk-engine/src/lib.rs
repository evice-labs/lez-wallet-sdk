//! # Evice Wallet SDK Engine.
//!
//! The core logic layer of the Evice Wallet SDK for the Logos Execution Zone (LEZ). This crate is **pure Rust, no Qt**
//! and exposes everything needed by the C-ABI FFI (`sdk-ffi`), the CLI, and Basecamp modules.

pub mod api;
pub mod approval;
pub mod decode;
pub mod effects;
pub mod error;
pub mod identity;
pub mod queue;
pub mod request;
pub mod resolve;
pub mod session;
pub mod store;
pub mod verifier;

// Re-export core types that consumers use constantly.
pub use api::{DAppApi, OwnerApi, SdkEngine};
pub use approval::{ApprovalDecision, ApprovalHandler};
pub use error::SdkError;
pub use identity::{
    AttestationPayload, IdentityCommitment, IdentitySecret, RegistrationPayload, ScopedNullifier,
};
pub use request::{PendingRequest, RequestId, RequestStatus};
pub use session::{GrantKind, SessionGrant, SessionId};

/// SDK version string, returned by `sdk_info()`.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// API version for capability negotiation.
/// Frozen at initial release; additive-only afterwards.
pub const API_VERSION: u32 = 1;
