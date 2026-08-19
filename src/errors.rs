use std::array::TryFromSliceError;
use thiserror::Error;

#[macro_export]
macro_rules! chill_dkg_ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err.into());
        }
    };
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChillDkgError {
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("participant {participant} is faulty: {message}")]
    FaultyParticipant { participant: usize, message: String },

    #[error("participant {participant} or the coordinator is faulty: {message}")]
    FaultyParticipantOrCoordinator { participant: usize, message: String },

    #[error("coordinator is faulty: {0}")]
    FaultyCoordinator(String),

    #[error("unable to identify whether a participant or the coordinator is faulty: {0}")]
    UnknownFaultyParticipantOrCoordinator(String),

    #[error("failed to parse message: {0}")]
    MsgParse(String),

    #[error("host secret key error: {0}")]
    HostSeckey(String),

    #[error("invalid session parameters: {0}")]
    SessionParams(String),

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
    RecoveryData(String),

    #[error("invalid secret-share sum: {0}")]
    SecshareSum(String),

    #[error("invalid value: {0}")]
    Value(String),

    #[error("invalid index: {0}")]
    Index(String),

    #[error("runtime error: {0}")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, ChillDkgError>;

impl From<TryFromSliceError> for ChillDkgError {
    fn from(e: TryFromSliceError) -> Self {
        ChillDkgError::Runtime(format!("{:?}", e))
    }
}
