//! Errors of the cryptographic building blocks.
//!
//! `crypto` knows nothing about the protocols built on it, so its errors only
//! classify *what* went wrong. The protocol modules convert them into their
//! own error types (`From<CryptoError>` in `dkg::errors` and `sign::errors`)
//! and add the *who*, i.e. the fault attribution the reference
//! implementations use.

use std::array::TryFromSliceError;
use std::borrow::Cow;
use thiserror::Error;

/// Returns early with `$err.into()` unless `$cond` holds. Works with any
/// error type the enclosing function's error converts from.
#[macro_export]
macro_rules! chill_dkg_ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err.into());
        }
    };
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    /// An input does not meet a precondition (the reference's `ValueError`).
    #[error("invalid value: {0}")]
    Value(Cow<'static, str>),

    /// The public key at `index` of a key list does not decode to a valid point.
    #[error("invalid public key at index {index}")]
    InvalidPubkey { index: usize },

    /// A certificate is malformed, e.g. has the wrong number of signatures.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(Cow<'static, str>),

    /// The signature at `index` of a certificate does not verify.
    #[error("invalid certificate signature at index {index}: {message}")]
    InvalidCertificateSignature {
        index: usize,
        message: Cow<'static, str>,
    },

    /// A failure that cannot be triggered by a well-formed input except with
    /// negligible probability, or a failed verification.
    #[error("runtime error: {0}")]
    Runtime(Cow<'static, str>),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<TryFromSliceError> for CryptoError {
    fn from(e: TryFromSliceError) -> Self {
        CryptoError::Runtime(format!("{:?}", e).into())
    }
}
