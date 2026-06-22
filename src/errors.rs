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

impl<'a> TryFrom<&'a anyhow::Error> for &'a ChillDkgError {
    type Error = anyhow::Error;

    fn try_from(error: &'a anyhow::Error) -> Result<Self, Self::Error> {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ChillDkgError>())
            .ok_or_else(|| anyhow::anyhow!("error chain does not contain ChillDkgError"))
    }
}
