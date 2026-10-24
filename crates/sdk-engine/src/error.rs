//! SDK error types.
//!
//! Every public SDK method returns `Result<T, SdkError>`. Internal subsystems
//! have their own error enums that convert into `SdkError` via `From` impls.

use thiserror::Error;

use crate::request::RequestId;
use crate::session::SessionId;

/// Result type alias used throughout the SDK engine.
pub type SdkResult<T> = Result<T, SdkError>;

/// Top-level error type for the SDK engine.
#[derive(Debug, Error)]
pub enum SdkError {
    // Session errors
    #[error("session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("session expired: {0}")]
    SessionExpired(SessionId),
    #[error("session does not have the required grant")]
    InsufficientGrant,

    // Request errors
    #[error("request not found: {0}")]
    RequestNotFound(RequestId),
    #[error("request was rejected by the user")]
    RequestRejected,
    #[error("request timed out waiting for approval")]
    RequestTimeout,
    #[error("request has already been finalized")]
    RequestAlreadyFinalized,

    // Wallet / chain errors
    #[error("wallet is locked")]
    WalletLocked,
    #[error("wallet is not initialized — call create or restore first")]
    WalletNotInitialized,
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("recipient account not initialized for this token")]
    RecipientNotInitialized,
    #[error("incorrect password — cannot unlock wallet")]
    InvalidPassword,

    // Name resolution errors
    #[error("name not found: {0}")]
    NameNotFound(String),
    #[error("name expired: {0}")]
    NameExpired(String),
    #[error("name resolution is disabled")]
    NameResolutionDisabled,
    #[error("name resolution failed: {0}")]
    NameResolutionError(String),

    // Decode / verification errors
    #[error("failed to decode program instruction: {0}")]
    DecodeError(String),
    #[error("program verification failed: {0}")]
    VerificationError(String),

    // Generic
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
