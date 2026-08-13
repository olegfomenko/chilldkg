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
    ProtocolError(String),

    #[error("FaultyParticipantError")]
    FaultyParticipantError { participant: usize, message: String },

    #[error("FaultyParticipantOrCoordinatorError")]
    FaultyParticipantOrCoordinatorError { participant: usize, message: String },

    #[error("FaultyCoordinatorError")]
    FaultyCoordinatorError(String),

    #[error("UnknownFaultyParticipantOrCoordinatorError")]
    UnknownFaultyParticipantOrCoordinatorError(String),

    #[error("MsgParseError")]
    MsgParseError(String),

    #[error("HostSeckeyError")]
    HostSeckeyError(String),

    #[error("SessionParamsError")]
    SessionParamsError(String),

    #[error("DuplicateHostPubkeyError")]
    DuplicateHostPubkeyError {
        participant1: usize,
        participant2: usize,
    },

    #[error("InvalidHostPubkeyError")]
    InvalidHostPubkeyError { participant: usize },

    #[error("ThresholdOrCountError")]
    ThresholdOrCountError,

    #[error("RandomnessError")]
    RandomnessError,

    #[error("InvalidSignatureInCertificateError")]
    InvalidSignatureInCertificateError { participant: usize },

    #[error("RecoveryDataError")]
    RecoveryDataError(String),

    #[error("SecshareSumError")]
    SecshareSumError(String),

    #[error("ValueError")]
    ValueError(String),

    #[error("IndexError")]
    IndexError(String),

    #[error("RuntimeError")]
    RuntimeError(String),
}

pub type Result<T> = std::result::Result<T, ChillDkgError>;

impl From<TryFromSliceError> for ChillDkgError {
    fn from(e: TryFromSliceError) -> Self {
        ChillDkgError::RuntimeError(format!("{:?}", e))
    }
}
