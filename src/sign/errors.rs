use crate::dkg::errors::ChillDkgError;
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

/// The crypto primitives report through the DKG error type; only its
/// `Value` and `Runtime` variants can reach signing.
impl From<ChillDkgError> for SignError {
    fn from(e: ChillDkgError) -> Self {
        match e {
            ChillDkgError::Value(message) => SignError::Value(message),
            ChillDkgError::Runtime(message) => SignError::Runtime(message),
            other => SignError::Runtime(other.to_string().into()),
        }
    }
}
