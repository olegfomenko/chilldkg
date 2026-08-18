#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::CertEQTranscript;
use crate::errors::{ChillDkgError, Result};
use crate::msg::{CoordinatorMsg1, RecoveryData};
use crate::party::recovery::recover;
use k256::elliptic_curve::Group;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod recovery;
pub mod transitions;

pub trait ParticipantState: Sized {
    type Message;
    type Next: ParticipantState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ParticipantInitialState {
    /// Participant host secret key.
    ///
    /// Math: `s_i`.
    pub s: Scalar,
}

impl ParticipantInitialState {
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            s: *NonZeroScalar::random(rng).as_ref(),
        }
    }

    pub fn new_with_secret(scalar: &Scalar) -> Self {
        Self { s: *scalar }
    }

    pub fn get_host_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.s
    }

    /// Recover this participant's DKG output from successful-session recovery data.
    pub fn recover(&self, recovery_data: &RecoveryData) -> Result<DKGOutput> {
        recover(&self.s, recovery_data)
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ParticipantStep1State {
    /// Participant index.
    ///
    /// Math: `i`.
    pub idx: usize,

    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Participant host secret key.
    ///
    /// Math: `s_i`.
    pub s: Scalar,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<ProjectivePoint>,

    /// Participant's public encryption nonce.
    ///
    /// Math: `R_i`.
    pub pubnonce: ProjectivePoint,

    /// Participant's commitment to the shared secret.
    ///
    /// Math: `C_{i,0}`.
    pub com_to_secret: ProjectivePoint,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DKGOutput {
    /// Participant index.
    ///
    /// Math: `i`.
    pub idx: usize,

    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Participant's final secret share.
    ///
    /// Math: tweaked secret share `u_i`.
    pub secshare: Scalar,

    /// Final threshold public key.
    ///
    /// Math: tweaked commitment to the aggregate secret, `C_0`.
    pub threshold_pubkey: ProjectivePoint,

    /// Final participant public shares.
    ///
    /// Math: `Y_i`.
    pub pubshares: Vec<ProjectivePoint>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParticipantStep2State {
    /// Equality-check transcript produced by THIS participant.
    ///
    /// Math: `eq_input`.
    pub transcript: CertEQTranscript,

    /// Participant's DKG output.
    pub dkg_output: DKGOutput,
}

impl ParticipantInitialState {
    fn validate_session_params(&self, host_pubkeys: &[ProjectivePoint], t: usize) -> Result<usize> {
        chill_dkg_ensure!(
            t >= 1 && t <= host_pubkeys.len() && host_pubkeys.len() <= u32::MAX as usize,
            ChillDkgError::ThresholdOrCount,
        );

        for (i, pubkey) in host_pubkeys.iter().enumerate() {
            chill_dkg_ensure!(
                !bool::from(pubkey.is_identity()),
                ChillDkgError::InvalidHostPubkey { participant: i },
            );

            for (j, other_pubkey) in host_pubkeys.iter().enumerate().skip(i + 1) {
                chill_dkg_ensure!(
                    pubkey != other_pubkey,
                    ChillDkgError::DuplicateHostPubkey {
                        participant1: i,
                        participant2: j,
                    },
                );
            }
        }

        host_pubkeys
            .iter()
            .position(|P_i| *P_i == ProjectivePoint::GENERATOR * self.s)
            .ok_or(ChillDkgError::HostSeckey(
                "Host secret key does not match any host public key".to_owned(),
            ))
    }
}

impl ParticipantStep1State {
    fn validate_coordinator_msg1(&self, coordinator_msg: &CoordinatorMsg1) -> Result<()> {
        chill_dkg_ensure!(
            self.t >= 1,
            ChillDkgError::FaultyCoordinator("DKG threshold must be at least 1".to_owned()),
        );
        chill_dkg_ensure!(
            coordinator_msg.coms_to_secrets.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of secret commitments".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.sum_coms_to_nonconst_terms.len() == self.t - 1,
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of non-constant commitments".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pops.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of proofs of possession".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pubnonces.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of public nonces".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.enc_secshares.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of encrypted secret shares".to_owned()
            ),
        );
        for (i, pubnonce) in coordinator_msg.pubnonces.iter().enumerate() {
            chill_dkg_ensure!(
                !bool::from(pubnonce.is_identity()),
                ChillDkgError::FaultyCoordinator(format!(
                    "Coordinator message 1 has invalid public nonce at index {i}"
                )),
            );
        }

        Ok(())
    }
}
