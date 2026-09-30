#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

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

/// A coordinator about to run one signing session, holding the public DKG
/// key material.
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
}

impl CoordinatorInitialState {
    pub fn new(output: &CoordinatorDKGOutput) -> Self {
        Self {
            t: output.t,
            pubshares: output.pubshares.clone(),
            threshold_pubkey: output.threshold_pubkey,
        }
    }
}

impl From<&CoordinatorDKGOutput> for CoordinatorInitialState {
    fn from(output: &CoordinatorDKGOutput) -> Self {
        Self::new(output)
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

    /// The signing subset's public nonces, paired with their participant ids.
    pub pubnonces: BTreeMap<usize, PubNonce>,
}
