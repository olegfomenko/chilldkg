#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::tweak::{Tweak, TweakContext};
use crate::dkg::msg::CoordinatorDKGOutput;
use crate::sign::errors::Result;
use crate::sign::msg::PubNonce;
use k256::ProjectivePoint;
use std::collections::BTreeMap;

pub mod transitions;
pub mod verify;

pub trait CoordinatorState: Sized {
    type Message;
    type Next: CoordinatorState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;
}

/// A coordinator about to run one signing session for `msg` under the
/// threshold key tweaked by `tweaks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorInitialState {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Public shares of all participants, indexed by participant id.
    ///
    /// Math: `Y_0, ..., Y_{n-1}`.
    pub pubshares: Vec<ProjectivePoint>,

    /// Untweaked threshold public key of the DKG.
    pub threshold_pubkey: ProjectivePoint,

    /// The message being signed.
    pub msg: Vec<u8>,

    /// Tweaks applied to the threshold key, in order.
    pub tweaks: Vec<Tweak>,
}

impl CoordinatorInitialState {
    pub fn new(output: &CoordinatorDKGOutput, msg: Vec<u8>, tweaks: Vec<Tweak>) -> Result<Self> {
        // The signing subset (and `t` with it) is validated at round 1; a
        // malformed tweak list is the only thing worth rejecting this early.
        TweakContext::new(output.threshold_pubkey).apply_all(&tweaks)?;

        Ok(Self {
            t: output.t,
            pubshares: output.pubshares.clone(),
            threshold_pubkey: output.threshold_pubkey,
            msg,
            tweaks,
        })
    }
}

/// A coordinator that has fixed the signing subset and relayed its public
/// nonces, waiting for the partial signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorStep1State {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Public shares of all participants, indexed by participant id.
    ///
    /// Math: `Y_0, ..., Y_{n-1}`.
    pub pubshares: Vec<ProjectivePoint>,

    /// Untweaked threshold public key of the DKG.
    pub threshold_pubkey: ProjectivePoint,

    /// The message being signed.
    pub msg: Vec<u8>,

    /// Tweaks applied to the threshold key, in order.
    pub tweaks: Vec<Tweak>,

    /// The signing subset's public nonces, paired with their participant ids.
    pub pubnonces: BTreeMap<usize, PubNonce>,
}
