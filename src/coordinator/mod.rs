#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::errors::ChillDkgError;
use crate::msg::{ParticipantMsg1, RecoveryData};
use anyhow::Result;
use k256::ProjectivePoint;
use k256::elliptic_curve::Group;

pub mod transitions;
pub trait CoordinatorState: Sized {
    type Message;
    type Next: CoordinatorState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorInitialState {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<ProjectivePoint>,
}

impl CoordinatorInitialState {
    pub fn new(host_pubkeys: Vec<ProjectivePoint>, t: usize) -> Result<Self> {
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
                !bool::from(P_i.is_identity()),
                ChillDkgError::InvalidHostPubkeyError { participant: i },
            );

            for j in (i + 1)..self.host_pubkeys.len() {
                chill_dkg_ensure!(
                    *P_i != self.host_pubkeys[j],
                    ChillDkgError::DuplicateHostPubkeyError {
                        participant1: i,
                        participant2: j,
                    },
                );
            }
        }

        Ok(())
    }

    fn validate_participant_msg1(&self, msgs: &Vec<ParticipantMsg1>) -> Result<()> {
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
                !bool::from(p_msg.pubnonce.is_identity()),
                ChillDkgError::FaultyParticipantError {
                    participant: i,
                    message: "Participant sent invalid public nonce".to_owned(),
                },
            );

            for (k, C_k) in p_msg.commitment.iter().enumerate() {
                chill_dkg_ensure!(
                    !bool::from(C_k.is_identity()),
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorDkgOutput {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Final threshold public key.
    ///
    /// Math: tweaked commitment to the aggregate secret, `C_0`.
    pub threshold_pubkey: ProjectivePoint,

    /// Final participant public shares.
    ///
    /// Math: `Y_i`.
    pub pubshares: Vec<ProjectivePoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorStep1State {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<ProjectivePoint>,

    /// Equality-check transcript.
    ///
    /// Math: `eq_input`.
    pub transcript: Vec<u8>,

    /// Coordinator's DKG output.
    pub dkg_output: CoordinatorDkgOutput,
}

#[derive(Clone, Debug)]
pub struct CoordinatorFinalizeOutput {
    /// Final coordinator message broadcast to participants.
    pub coordinator_msg: crate::msg::CoordinatorMsg2,

    /// Coordinator's DKG output.
    pub dkg_output: CoordinatorDkgOutput,

    /// Recovery data for the completed session.
    pub recovery_data: RecoveryData,
}
