use crate::crypto::errors::CryptoError;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChillDkgError {
    #[error("protocol error: {0}")]
    Protocol(Cow<'static, str>),

    #[error("participant {participant} is faulty: {message}")]
    FaultyParticipant {
        participant: usize,
        message: Cow<'static, str>,
    },

    #[error("participant {participant} or the coordinator is faulty: {message}")]
    FaultyParticipantOrCoordinator {
        participant: usize,
        message: Cow<'static, str>,
    },

    #[error("coordinator is faulty: {0}")]
    FaultyCoordinator(Cow<'static, str>),

    #[error("unable to identify whether a participant or the coordinator is faulty: {0}")]
    UnknownFaultyParticipantOrCoordinator(Cow<'static, str>),

    #[error("failed to parse message: {0}")]
    MsgParse(Cow<'static, str>),

    #[error("host secret key error: {0}")]
    HostSeckey(Cow<'static, str>),

    #[error("invalid session parameters: {0}")]
    SessionParams(Cow<'static, str>),

    #[error("participants {participant1} and {participant2} have duplicate host public keys")]
    DuplicateHostPubkey {
        participant1: usize,
        participant2: usize,
    },

    #[error("participant {participant} has an invalid host public key")]
    InvalidHostPubkey { participant: usize },

    #[error(
        "threshold must be between 1 and the participant count, and participant count must not exceed u32::MAX"
    )]
    ThresholdOrCount,

    #[error("invalid randomness")]
    Randomness,

    #[error("participant {participant} has an invalid signature in the certificate")]
    InvalidSignatureInCertificate { participant: usize },

    #[error("invalid recovery data: {0}")]
    RecoveryData(Cow<'static, str>),

    #[error("invalid secret-share sum: {0}")]
    SecshareSum(Cow<'static, str>),

    #[error("invalid value: {0}")]
    Value(Cow<'static, str>),

    #[error("invalid index: {0}")]
    Index(Cow<'static, str>),

    #[error("runtime error: {0}")]
    Runtime(Cow<'static, str>),
}

pub type Result<T> = std::result::Result<T, ChillDkgError>;

/// Attributes crypto failures the way the reference does: a key that fails
/// to decode belongs to a participant, and a malformed certificate or a bad
/// certificate signature received by a participant comes from the
/// coordinator. `Value` and `Runtime` keep their class.
impl From<CryptoError> for ChillDkgError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Value(message) => ChillDkgError::Value(message),
            CryptoError::InvalidPubkey { index } => {
                ChillDkgError::InvalidHostPubkey { participant: index }
            }
            CryptoError::InvalidCertificate(message) => ChillDkgError::FaultyCoordinator(message),
            // The coordinator verifies every signature before broadcasting
            // the certificate, so a participant receiving a bad one blames
            // the coordinator. The coordinator itself maps this variant to
            // `FaultyParticipant` at its call site.
            CryptoError::InvalidCertificateSignature { message, .. } => {
                ChillDkgError::FaultyCoordinator(
                    format!(
                        "Coordinator has provided a certificate with an invalid signature, error = {message}"
                    )
                    .into(),
                )
            }
            CryptoError::Runtime(message) => ChillDkgError::Runtime(message),
        }
    }
}
