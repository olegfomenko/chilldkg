use anyhow::{Result, bail, ensure};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use std::collections::HashMap;

pub mod crypto;
pub mod math;
pub mod msg;
mod transitions;

pub trait ParticipantState: Sized {
    type Message;
    type Next: ParticipantState;
    type Output;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)>;

    fn encryption_key(&self) -> ProjectivePoint;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantInitialState {
    pub idx: usize,
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
    pub idx: usize,
    pub s: Scalar,

    pub host_pubkeys: Vec<ProjectivePoint>,

    pub t: u32,
}

impl ParticipantParamsState {
    fn validate_session_params(&self) -> Result<()> {
        ensure!(
            self.t >= 1
                && (self.t as usize) <= self.host_pubkeys.len()
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
