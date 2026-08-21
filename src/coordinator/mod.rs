#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::coordinator::recovery::recover;
use crate::crypto::certeq::CertEQTranscript;
use crate::crypto::curve::{Curve, CurvePoint};
use crate::errors::{ChillDkgError, Result};
use crate::msg::{ParticipantMsg1, RecoveryData};

pub mod recovery;
pub mod transitions;
pub trait CoordinatorState: Sized {
    type Message;
    type Next: CoordinatorState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorInitialState<C: Curve> {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<C::Point>,
}

impl<C: Curve> CoordinatorInitialState<C> {
    pub fn new(host_pubkeys: Vec<C::Point>, t: usize) -> Result<Self> {
        let state = Self { t, host_pubkeys };
        state.validate_session_params()?;
        Ok(state)
    }

    fn validate_session_params(&self) -> Result<()> {
        chill_dkg_ensure!(
            self.t >= 1
                && self.t <= self.host_pubkeys.len()
                && self.host_pubkeys.len() <= u32::MAX as usize,
            ChillDkgError::ThresholdOrCountError,
        );

        for (i, P_i) in self.host_pubkeys.iter().enumerate() {
            chill_dkg_ensure!(
                !P_i.is_identity(),
                ChillDkgError::InvalidHostPubkeyError { participant: i },
            );

            for (j, P_j) in self.host_pubkeys.iter().enumerate().skip(i + 1) {
                chill_dkg_ensure!(
                    P_i != P_j,
                    ChillDkgError::DuplicateHostPubkeyError {
                        participant1: i,
                        participant2: j,
                    },
                );
            }
        }

        Ok(())
    }

    fn validate_participant_msg1(&self, msgs: &[ParticipantMsg1<C>]) -> Result<()> {
        chill_dkg_ensure!(
            msgs.len() == self.host_pubkeys.len(),
            ChillDkgError::ValueError(
                "Coordinator step 1 received invalid number of participant messages".to_owned()
            ),
        );

        for (i, p_msg) in msgs.iter().enumerate() {
            chill_dkg_ensure!(
                p_msg.commitment.len() == self.t,
                ChillDkgError::FaultyParticipantError {
                    participant: i,
                    message: "Participant sent invalid number of VSS commitments".to_owned(),
                },
            );
            chill_dkg_ensure!(
                p_msg.enc_shares.len() == self.host_pubkeys.len(),
                ChillDkgError::FaultyParticipantError {
                    participant: i,
                    message: "missing encrypted secret shares".to_owned(),
                },
            );
            chill_dkg_ensure!(
                !p_msg.pubnonce.is_identity(),
                ChillDkgError::FaultyParticipantError {
                    participant: i,
                    message: "Participant sent invalid public nonce".to_owned(),
                },
            );

            for (k, C_k) in p_msg.commitment.iter().enumerate() {
                chill_dkg_ensure!(
                    !C_k.is_identity(),
                    ChillDkgError::FaultyParticipantError {
                        participant: i,
                        message: format!(
                            "Participant sent invalid VSS commitment at coefficient {k}"
                        ),
                    },
                );
            }
        }

        Ok(())
    }

    /// Recover coordinator's DKG output from successful-session recovery data.
    pub fn recover(&self, recovery_data: &RecoveryData<C>) -> Result<CoordinatorDKGOutput<C>> {
        recover(recovery_data)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorDKGOutput<C: Curve> {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Final threshold public key.
    ///
    /// Math: tweaked commitment to the aggregate secret, `C_0`.
    pub threshold_pubkey: C::Point,

    /// Final participant public shares.
    ///
    /// Math: `Y_i`.
    pub pubshares: Vec<C::Point>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorStep1State<C: Curve> {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<C::Point>,

    /// Equality-check transcript.
    ///
    /// Math: `eq_input`.
    pub transcript: CertEQTranscript<C>,

    /// Coordinator's DKG output.
    pub dkg_output: CoordinatorDKGOutput<C>,
}
