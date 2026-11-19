//! Engine error type and its CLI exit-code mapping.

use thiserror::Error;

/// Failures the engine can report to its callers.
///
/// CLI exit codes:
///
/// | Variant | Exit |
/// | --- | --- |
/// | [`ScanError::OptionsInvalid`] | 1 |
/// | [`ScanError::InvalidPlan`], [`ScanError::AllowlistViolation`], [`ScanError::IdentityMissing`] | 3 |
/// | [`ScanError::Network`], [`ScanError::Busy`], [`ScanError::RegistrationRejected`] | 4 |
/// | [`ScanError::Cancelled`], [`ScanError::BudgetExhausted`] | 5 |
/// | [`ScanError::ResultLaneOverflow`], [`ScanError::Internal`] | 6 |
///
/// [`ScanError::BudgetExhausted`] has exactly one constructor: the budget
/// expires before any summary is emitted.
#[derive(Clone, Debug, Error)]
pub enum ScanError {
    /// The plan breaks the planner's structural rules.
    #[error("invalid plan: {0}")]
    InvalidPlan(String),

    /// The plan targets an address outside the resolved allowlist.
    #[error("allowlist violation: {0}")]
    AllowlistViolation(String),

    /// A CLI or config option failed validation.
    #[error("invalid option `{key}`: {reason}")]
    OptionsInvalid { key: String, reason: String },

    /// A network operation failed against the named target.
    #[error("network failure for `{target}`: {cause}")]
    Network { target: String, cause: String },

    /// The scan was cancelled by the user or the supervising process.
    #[error("scan cancelled")]
    Cancelled,

    /// Another scan already holds the single-instance run lock.
    #[error("another scan is already running and holds the run lock")]
    Busy,

    /// The result lane could not accept another entry.
    #[error("result lane overflow: capacity {capacity} exceeded")]
    ResultLaneOverflow { capacity: usize },

    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),

    /// No client identity is available for the registration handshake.
    #[error("client identity missing: no stored identity or registration token was found")]
    IdentityMissing,

    /// The control plane rejected the client registration.
    #[error("registration rejected with HTTP status {status} (API version `{api_version}`)")]
    RegistrationRejected { status: u16, api_version: String },

    /// The scan budget expired before any summary was emitted.
    #[error("scan budget exhausted before any summary was emitted")]
    BudgetExhausted,
}
