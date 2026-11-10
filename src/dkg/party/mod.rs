#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::CertEQTranscript;
use crate::dkg::errors::{ChillDkgError, Result};
use crate::dkg::msg::{CoordinatorMsg1, DKGOutput, ParticipantMsg2, RecoveryData};
use crate::dkg::party::recovery::recover;
use k256::elliptic_curve::Group;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod recovery;
pub mod transitions;

/// One step of the participant's side of a ChillDKG session.
///
/// `next` consumes the state, but that only prevents reuse of the value in
/// memory. A state that was persisted and restored, or rebuilt from its public
/// fields, can be passed to `next` again, and **must not be**: as in
/// BIP-FROST-DKG, every session state must be passed to `next` at most once.
/// See [`ParticipantStep1State`] for why this matters.
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

/// Participant state after step 1, waiting for the coordinator's
/// [`CoordinatorMsg1`].
///
/// **Single use.** Pass this state to [`ParticipantState::next`] at most once.
/// Never run `next` on a persisted, restored or rebuilt copy of it once a
/// [`ParticipantMsg2`] produced from it may have been sent. If the coordinator
/// asks for that message again, resend [`ParticipantStep2State::pmsg2`]
/// instead.
///
/// Step 2 signs the session transcript for the CertEq equality check. If an
/// honest participant signs two different transcripts, a malicious
/// coordinator can build a valid certificate for each and split honest
/// participants onto different DKG outputs (BIP-FROST-DKG: the state "must
/// not be reused").
///
/// For this reason the type is not `Clone`:
///
/// ```compile_fail,E0277
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<chilldkg_rs::dkg::ParticipantStep1State>();
/// ```
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

/// Participant state after step 2, waiting for the coordinator's certificate.
///
/// Persist this state in place of the [`ParticipantStep1State`] it came from
/// before sending [`pmsg2`](Self::pmsg2), so that a coordinator retry is
/// answered by resending the same message rather than by running step 2
/// again. Pass it to [`ParticipantState::next`] at most once.
#[derive(Clone, PartialEq, Eq)]
pub struct ParticipantStep2State {
    /// Equality-check transcript produced by THIS participant.
    ///
    /// Math: `eq_input`.
    pub transcript: CertEQTranscript,

    /// Participant's DKG output.
    pub dkg_output: DKGOutput,

    /// The step 2 message produced for `transcript`, i.e. this participant's
    /// CertEq signature. Resend this message if the coordinator asks for it
    /// again.
    pub pmsg2: ParticipantMsg2,
}

impl ParticipantInitialState {
    pub fn validate_public_session_params(
        host_pubkeys: &[ProjectivePoint],
        t: usize,
    ) -> Result<()> {
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

        Ok(())
    }

    fn validate_session_params(&self, host_pubkeys: &[ProjectivePoint], t: usize) -> Result<usize> {
        Self::validate_public_session_params(host_pubkeys, t)?;

        host_pubkeys
            .iter()
            .position(|P_i| *P_i == ProjectivePoint::GENERATOR * self.s)
            .ok_or(ChillDkgError::HostSeckey(
                "Host secret key does not match any host public key".into(),
            ))
    }
}

impl ParticipantStep1State {
    fn validate_coordinator_msg1(&self, coordinator_msg: &CoordinatorMsg1) -> Result<()> {
        chill_dkg_ensure!(
            self.t >= 1,
            ChillDkgError::FaultyCoordinator("DKG threshold must be at least 1".into()),
        );
        chill_dkg_ensure!(
            coordinator_msg.coms_to_secrets.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of secret commitments".into()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.sum_coms_to_nonconst_terms.len() == self.t - 1,
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of non-constant commitments".into()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pops.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of proofs of possession".into()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pubnonces.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of public nonces".into()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.enc_secshares.len() == self.host_pubkeys.len(),
            ChillDkgError::FaultyCoordinator(
                "Coordinator message 1 has invalid number of encrypted secret shares".into()
            ),
        );

        chill_dkg_ensure!(
            coordinator_msg.pubnonces[self.idx] == self.pubnonce,
            ChillDkgError::FaultyCoordinator("Coordinator replied with wrong pubnonce".into()),
        );

        for (i, pubnonce) in coordinator_msg.pubnonces.iter().enumerate() {
            chill_dkg_ensure!(
                !bool::from(pubnonce.is_identity()),
                ChillDkgError::FaultyParticipantOrCoordinator {
                    participant: i,
                    message: "invalid public nonce".into(),
                },
            );
        }

        chill_dkg_ensure!(
            coordinator_msg.coms_to_secrets[self.idx] == self.com_to_secret,
            ChillDkgError::FaultyCoordinator(
                "Coordinator sent unexpected first group element for local index".into()
            ),
        );

        Ok(())
    }
}
