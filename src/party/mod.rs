use anyhow::{Result, ensure};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};

pub mod transitions;

pub trait ParticipantState: Sized {
    type Message;
    type Next: ParticipantState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;

    fn encryption_key(&self) -> ProjectivePoint;
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
    fn validate_session_params(&self) -> anyhow::Result<()> {
        ensure!(
            self.t >= 1
                && self.t <= self.host_pubkeys.len()
                && self.host_pubkeys.len() <= u32::MAX as usize,
            "ParticipantParamsState: invalid DKG threshold or participant count"
        );
        ensure!(
            self.idx < self.host_pubkeys.len(),
            "ParticipantParamsState: participant index is out of range for host public keys"
        );

        for (i, pubkey) in self.host_pubkeys.iter().enumerate() {
            ensure!(
                !bool::from(pubkey.is_identity()),
                "ParticipantParamsState: invalid host public key at index {i}"
            );

            for j in (i + 1)..self.host_pubkeys.len() {
                ensure!(
                    *pubkey != self.host_pubkeys[j],
                    "ParticipantParamsState: duplicate host public keys at indices {i} and {j}"
                );
            }
        }

        ensure!(
            self.host_pubkeys[self.idx] == self.encryption_key(),
            "ParticipantParamsState: host secret key does not match public key at participant index"
        );

        Ok(())
    }
}
