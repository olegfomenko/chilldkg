use std::array::TryFromSliceError;
use std::borrow::Cow;
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

impl From<TryFromSliceError> for ChillDkgError {
    fn from(e: TryFromSliceError) -> Self {
        ChillDkgError::Runtime(format!("{:?}", e).into())
    }
}
