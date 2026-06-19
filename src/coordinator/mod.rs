#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::msg::{ParticipantMsg1, RecoveryData};
use anyhow::{Result, ensure};
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
        ensure!(
            self.t >= 1
                && self.t <= self.host_pubkeys.len()
                && self.host_pubkeys.len() <= u32::MAX as usize,
            "CoordinatorInitialState: invalid DKG threshold or participant count"
        );

        for (i, P_i) in self.host_pubkeys.iter().enumerate() {
            ensure!(
                !bool::from(P_i.is_identity()),
                "CoordinatorInitialState: invalid host public key at index {i}"
            );

            for j in (i + 1)..self.host_pubkeys.len() {
                ensure!(
                    *P_i != self.host_pubkeys[j],
                    "CoordinatorInitialState: duplicate host public keys at indices {i} and {j}"
                );
            }
        }

        Ok(())
    }

    fn validate_participant_msg1(&self, msgs: &Vec<ParticipantMsg1>) -> Result<()> {
        ensure!(
            msgs.len() == self.host_pubkeys.len(),
            "Coordinator step 1 received invalid number of participant messages"
        );

        for (i, p_msg) in msgs.iter().enumerate() {
            ensure!(
                p_msg.commitment.len() == self.t,
                "Participant {i} sent invalid number of VSS commitments"
            );
            ensure!(
                p_msg.enc_shares.len() == self.host_pubkeys.len(),
                "Participant {i} sent invalid number of encrypted shares"
            );
            ensure!(
                !bool::from(p_msg.pubnonce.is_identity()),
                "Participant {i} sent invalid public nonce"
            );

            for (k, C_k) in p_msg.commitment.iter().enumerate() {
                ensure!(
                    !bool::from(C_k.is_identity()),
                    "Participant {i} sent invalid VSS commitment at coefficient {k}"
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
