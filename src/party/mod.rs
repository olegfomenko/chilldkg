use crate::chill_dkg_ensure;
use crate::errors::ChillDkgError;
use crate::msg::CoordinatorMsg1;
use anyhow::Result;
use k256::elliptic_curve::Group;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};

pub mod transitions;

pub trait ParticipantState: Sized {
    type Message;
    type Next: ParticipantState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantInitialState {
    /// Participant index.
    ///
    /// Math: `i`.
    pub idx: usize,

    /// Participant host secret key.
    ///
    /// Math: `s_i`.
    pub s: Scalar,
}

impl ParticipantInitialState {
    pub fn new(idx: usize, rng: &mut impl CryptoRngCore) -> Self {
        let s = *NonZeroScalar::random(rng).as_ref();

        Self { idx, s }
    }

    pub fn get_host_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantParamsState {
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantStep2State {
    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<ProjectivePoint>,

    /// Equality-check transcript.
    ///
    /// Math: `eq_input`.
    pub transcript: Vec<u8>,

    /// Participant's DKG output.
    pub dkg_output: DKGOutput,
}

impl ParticipantParamsState {
    fn validate_session_params(&self) -> Result<()> {
        chill_dkg_ensure!(
            self.t >= 1
                && self.t <= self.host_pubkeys.len()
                && self.host_pubkeys.len() <= u32::MAX as usize,
            ChillDkgError::ThresholdOrCountError,
        );
        chill_dkg_ensure!(
            self.idx < self.host_pubkeys.len(),
            ChillDkgError::ValueError(
                "participant index is out of range for host public keys".to_owned()
            ),
        );

        for (i, pubkey) in self.host_pubkeys.iter().enumerate() {
            chill_dkg_ensure!(
                !bool::from(pubkey.is_identity()),
                ChillDkgError::InvalidHostPubkeyError { participant: i },
            );

            for j in (i + 1)..self.host_pubkeys.len() {
                chill_dkg_ensure!(
                    *pubkey != self.host_pubkeys[j],
                    ChillDkgError::DuplicateHostPubkeyError {
                        participant1: i,
                        participant2: j,
                    },
                );
            }
        }

        chill_dkg_ensure!(
            self.host_pubkeys[self.idx] == (ProjectivePoint::GENERATOR * self.s),
            ChillDkgError::HostSeckeyError(
                "Host secret key does not match any host public key".to_owned()
            ),
        );

        Ok(())
    }
}

impl ParticipantStep1State {
    fn validate_coordinator_msg1(&self, coordinator_msg: &CoordinatorMsg1) -> Result<()> {
        chill_dkg_ensure!(
            self.t >= 1,
            ChillDkgError::FaultyCoordinatorError("DKG threshold must be at least 1".to_owned()),
        );
        chill_dkg_ensure!(
            coordinator_msg.coms_to_secrets.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator message 1 has invalid number of secret commitments".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.sum_coms_to_nonconst_terms.len() == self.t - 1,
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator message 1 has invalid number of non-constant commitments".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pops.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator message 1 has invalid number of proofs of possession".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pubnonces.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator message 1 has invalid number of public nonces".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.enc_secshares.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator message 1 has invalid number of encrypted secret shares".to_owned()
            ),
        );
        for (i, pubnonce) in coordinator_msg.pubnonces.iter().enumerate() {
            chill_dkg_ensure!(
                !bool::from(pubnonce.is_identity()),
                ChillDkgError::FaultyCoordinatorError(format!(
                    "Coordinator message 1 has invalid public nonce at index {i}"
                )),
            );
        }

        Ok(())
    }
}
