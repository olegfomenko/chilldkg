#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::ec::compress_default;
use crate::crypto::enc::encrypt;
use crate::crypto::pop::chilldkg_pop_sign;
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_ENCPEDPOP_SECNONCE, TAG_ENCPEDPOP_SEED};
use crate::math::Polynomial;
use crate::msg::{
    CoordinatorMsg1, ParticipantMsg1, ParticipantStep1TransitionMsg, SessionParamsMsg,
};
use crate::{
    ParticipantInitialState, ParticipantParamsState, ParticipantState, ParticipantStep1State,
};
use anyhow::{Context, Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};

fn serialize_enc_context(t: usize, host_pubkeys: &[ProjectivePoint]) -> Vec<u8> {
    let mut enc_context = Vec::with_capacity(4 + 33 * host_pubkeys.len());
    enc_context.extend_from_slice(&(t as u32).to_be_bytes());

    for P_i in host_pubkeys {
        enc_context.extend_from_slice(&compress_default(P_i));
    }

    enc_context
}

fn derive_simpl_seed(s: &Scalar, random: &[u8; 32], enc_context: &[u8]) -> [u8; 32] {
    let seed: [u8; 32] = s.to_bytes().into();

    let mut preimage = Vec::with_capacity(32 + 32 + enc_context.len());
    preimage.extend_from_slice(&seed);
    preimage.extend_from_slice(random);
    preimage.extend_from_slice(enc_context);

    tagged_hash(TAG_ENCPEDPOP_SEED, preimage)
}

impl ParticipantState for ParticipantInitialState {
    type Message = SessionParamsMsg;
    type Next = ParticipantParamsState;
    type Output = ();

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let next_stage = ParticipantParamsState {
            idx: self.idx,
            s: self.s,
            host_pubkeys: msg.host_pubkeys,
            t: msg.t,
        };

        next_stage.validate_session_params()?;

        Ok((Some(next_stage), ()))
    }

    fn encryption_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.s
    }
}

impl ParticipantState for ParticipantParamsState {
    type Message = ParticipantStep1TransitionMsg;
    type Next = ParticipantStep1State;
    type Output = ParticipantMsg1;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let enc_context = serialize_enc_context(self.t, &self.host_pubkeys);
        let simpl_seed = derive_simpl_seed(&self.s, &msg.random, &enc_context);

        let r = Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_ENCPEDPOP_SECNONCE,
            simpl_seed,
        )));

        ensure!(r != Scalar::ZERO, "EncPedPop secret nonce must not be zero");

        let polynomial = Polynomial::new(&simpl_seed, self.t);

        let shares: Vec<Scalar> = (0..self.host_pubkeys.len())
            .map(|i| polynomial.eval(Scalar::from((i + 1) as u64)))
            .collect();

        let commitment: Vec<ProjectivePoint> = polynomial
            .into_iter()
            .map(|coef| ProjectivePoint::GENERATOR * coef)
            .collect();

        let pop = chilldkg_pop_sign(
            &simpl_seed,
            polynomial
                .coeff(0)
                .context("Free term must exist")?
                .to_owned(),
            self.idx as u32,
        )?;

        let pubnonce = ProjectivePoint::GENERATOR * r;

        let enc_shares = encrypt(
            &r,
            &self.s,
            &self.host_pubkeys,
            &enc_context,
            self.idx,
            &shares,
        )?;

        let com_to_secret = commitment[0];

        let pmsg1 = ParticipantMsg1 {
            commitment,
            pop,
            pubnonce,
            enc_shares,
        };

        let next_stage = ParticipantStep1State {
            idx: self.idx,
            s: self.s,
            host_pubkeys: self.host_pubkeys,
            t: self.t,
            pubnonce,
            com_to_secret,
        };

        Ok((Some(next_stage), pmsg1))
    }

    fn encryption_key(&self) -> ProjectivePoint {
        self.host_pubkeys[self.idx]
    }
}

impl ParticipantState for ParticipantStep1State {
    type Message = CoordinatorMsg1;
    type Next = Self;
    type Output = ();

    fn next(self, _msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        todo!("participant step 1 state transition is not implemented yet")
    }

    fn encryption_key(&self) -> ProjectivePoint {
        self.host_pubkeys[self.idx]
    }
}
