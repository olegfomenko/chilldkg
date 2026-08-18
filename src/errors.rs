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
    #[error("ProtocolError")]
    Protocol(String),

    #[error("FaultyParticipantError")]
    FaultyParticipant { participant: usize, message: String },

    #[error("FaultyParticipantOrCoordinatorError")]
    FaultyParticipantOrCoordinator { participant: usize, message: String },

    #[error("FaultyCoordinatorError")]
    FaultyCoordinator(String),

    #[error("UnknownFaultyParticipantOrCoordinatorError")]
    UnknownFaultyParticipantOrCoordinator(String),

    #[error("MsgParseError")]
    MsgParse(String),

    #[error("HostSeckeyError")]
    HostSeckey(String),

    #[error("SessionParamsError")]
    SessionParams(String),

    #[error("DuplicateHostPubkeyError")]
    DuplicateHostPubkey {
        participant1: usize,
        participant2: usize,
    },

    #[error("InvalidHostPubkeyError")]
    InvalidHostPubkey { participant: usize },

    #[error("ThresholdOrCountError")]
    ThresholdOrCount,

    #[error("RandomnessError")]
    Randomness,

    #[error("InvalidSignatureInCertificateError")]
    InvalidSignatureInCertificate { participant: usize },

    #[error("RecoveryDataError")]
    RecoveryData(String),

    #[error("SecshareSumError")]
    SecshareSum(String),

    #[error("ValueError")]
    Value(String),

    #[error("IndexError")]
    Index(String),

    #[error("RuntimeError")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, ChillDkgError>;

impl From<TryFromSliceError> for ChillDkgError {
    fn from(e: TryFromSliceError) -> Self {
        ChillDkgError::Runtime(format!("{:?}", e))
    }
}
