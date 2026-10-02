use crate::crypto::errors::CryptoError;
use std::borrow::Cow;
use thiserror::Error;

/// Errors of the FROST signing protocol.
///
/// Mirrors the reference's two failure classes: `Value` for inputs that don't
/// meet a precondition (the reference `ValueError`) and `InvalidContribution`
/// for a signer that misbehaved (the reference `InvalidContributionError`).
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SignError {
    #[error("invalid value: {0}")]
    Value(Cow<'static, str>),

    #[error("participant {participant} sent an invalid contribution: {message}")]
    InvalidContribution {
        participant: usize,
        message: Cow<'static, str>,
    },

    #[error("runtime error: {0}")]
    Runtime(Cow<'static, str>),
}

pub type Result<T> = std::result::Result<T, SignError>;

/// Crypto failures keep their class. Signing never decodes keys or checks
/// certificates, so those failures cannot occur here and are internal errors.
impl From<CryptoError> for SignError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Value(message) => SignError::Value(message),
            CryptoError::Runtime(message) => SignError::Runtime(message),
            other => SignError::Runtime(other.to_string().into()),
        }
    }
}
