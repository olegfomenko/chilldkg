#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::tweak::Tweak;
use crate::dkg::msg::DKGOutput;
use crate::sign::errors::Result;
use crate::sign::party::nonce::SecNonce;
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod nonce;
pub mod sign;
pub mod transitions;

pub trait SignerState: Sized {
    type Message;
    type Next: SignerState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

/// A participant about to take part in one signing session, holding its DKG
/// key material.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SignerInitialState {
    /// Participant index.
    ///
    /// Math: `i`.
    pub idx: usize,

    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Participant's secret share.
    ///
    /// Math: `u_i`.
    pub secshare: Scalar,

    /// Public shares of all participants, indexed by participant id.
    ///
    /// Math: `Y_0, ..., Y_{n-1}`.
    pub pubshares: Vec<ProjectivePoint>,

    /// Untweaked threshold public key of the DKG.
    pub threshold_pubkey: ProjectivePoint,
}

impl SignerInitialState {
    pub fn new(output: &DKGOutput) -> Self {
        Self {
            idx: output.idx,
            t: output.t,
            secshare: output.secshare,
            pubshares: output.pubshares.clone(),
            threshold_pubkey: output.threshold_pubkey,
        }
    }

    /// Math: `Y_i = u_i * G`.
    pub fn pubshare(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.secshare
    }
}

impl From<&DKGOutput> for SignerInitialState {
    fn from(output: &DKGOutput) -> Self {
        Self::new(output)
    }
}

/// A participant that has published its nonce and waits for the nonces of
/// the other signers. Holds the secret nonce; consumed by the next step so a
/// nonce is never used twice.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignerStep1State {
    /// Participant index.
    ///
    /// Math: `i`.
    pub idx: usize,

    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Participant's secret share.
    ///
    /// Math: `u_i`.
    pub secshare: Scalar,

    /// Public shares of all participants, indexed by participant id.
    ///
    /// Math: `Y_0, ..., Y_{n-1}`.
    pub pubshares: Vec<ProjectivePoint>,

    /// Untweaked threshold public key of the DKG.
    pub threshold_pubkey: ProjectivePoint,

    /// The message the nonce was bound to, if it was known when the nonce
    /// was generated.
    pub msg: Option<Vec<u8>>,

    /// The tweaks the nonce was bound to, if they were known when the nonce
    /// was generated.
    #[zeroize(skip)]
    pub tweaks: Option<Vec<Tweak>>,

    /// This session's secret nonce.
    ///
    /// Math: `(k_1, k_2)`.
    pub secnonce: SecNonce,
}
