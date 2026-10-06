#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::CertEQTranscript;
use crate::dkg::ParticipantInitialState;
use crate::dkg::coordinator::recovery::recover;
use crate::dkg::errors::{ChillDkgError, Result};
use crate::dkg::msg::{CoordinatorDKGOutput, ParticipantMsg1, RecoveryData};
use k256::ProjectivePoint;
use k256::elliptic_curve::Group;

pub mod recovery;
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
        ParticipantInitialState::validate_public_session_params(&host_pubkeys, t)?;
        Ok(Self { t, host_pubkeys })
    }

    fn validate_participant_msg1(&self, msgs: &[ParticipantMsg1]) -> Result<()> {
        chill_dkg_ensure!(
            msgs.len() == self.host_pubkeys.len(),
            ChillDkgError::Value(
                "Coordinator step 1 received invalid number of participant messages".into()
            ),
        );

        for (i, p_msg) in msgs.iter().enumerate() {
            chill_dkg_ensure!(
                p_msg.commitment.len() == self.t,
                ChillDkgError::FaultyParticipant {
                    participant: i,
                    message: "Participant sent invalid number of VSS commitments".into(),
                },
            );
            chill_dkg_ensure!(
                p_msg.enc_shares.len() == self.host_pubkeys.len(),
                ChillDkgError::FaultyParticipant {
                    participant: i,
                    message: "missing encrypted secret shares".into(),
                },
            );
            chill_dkg_ensure!(
                !bool::from(p_msg.pubnonce.is_identity()),
                ChillDkgError::FaultyParticipant {
                    participant: i,
                    message: "Participant sent invalid public nonce".into(),
                },
            );

            for (k, C_k) in p_msg.commitment.iter().enumerate() {
                chill_dkg_ensure!(
                    !bool::from(C_k.is_identity()),
                    ChillDkgError::FaultyParticipant {
                        participant: i,
                        message: format!(
                            "Participant sent invalid VSS commitment at coefficient {k}"
                        )
                        .into(),
                    },
                );
            }
        }

        Ok(())
    }

    /// Recover coordinator's DKG output from successful-session recovery data.
    pub fn recover(&self, recovery_data: &RecoveryData) -> Result<CoordinatorDKGOutput> {
        recover(recovery_data)
    }
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
    pub transcript: CertEQTranscript,

    /// Coordinator's DKG output.
    pub dkg_output: CoordinatorDKGOutput,
}
