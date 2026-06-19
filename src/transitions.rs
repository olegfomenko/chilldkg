#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::certeq::{get_certeq, get_certeq_transcript};
use crate::crypto::ec::{compress_default, tap_tweak_no_script};
use crate::crypto::enc::{decrypt, encrypt};
use crate::crypto::pop::{chilldkg_pop_sign, chilldkg_pop_verify};
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_ENCPEDPOP_SECNONCE, TAG_ENCPEDPOP_SEED};
use crate::math::Polynomial;
use crate::msg::{
    CoordinatorMsg2, ParticipantMsg1, ParticipantMsg2, ParticipantStep1TransitionMsg,
    ParticipantStep2TransitionMsg, SessionParamsMsg,
};
use crate::{
    DkgOutput, ParticipantInitialState, ParticipantParamsState, ParticipantState,
    ParticipantStep1State, ParticipantStep2State,
};
use anyhow::{Context, Result, bail, ensure};
use k256::elliptic_curve::Group;
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

fn validate_coordinator_msg1(
    msg: &ParticipantStep2TransitionMsg,
    t: usize,
    n: usize,
) -> Result<()> {
    let coordinator_msg = &msg.coordinator_msg;

    ensure!(t >= 1, "DKG threshold must be at least 1");
    ensure!(
        coordinator_msg.coms_to_secrets.len() == n,
        "Coordinator message 1 has invalid number of secret commitments"
    );
    ensure!(
        coordinator_msg.sum_coms_to_nonconst_terms.len() == t - 1,
        "Coordinator message 1 has invalid number of non-constant commitments"
    );
    ensure!(
        coordinator_msg.pops.len() == n,
        "Coordinator message 1 has invalid number of proofs of possession"
    );
    ensure!(
        coordinator_msg.pubnonces.len() == n,
        "Coordinator message 1 has invalid number of public nonces"
    );
    ensure!(
        coordinator_msg.enc_secshares.len() == n,
        "Coordinator message 1 has invalid number of encrypted secret shares"
    );
    for (i, pubnonce) in coordinator_msg.pubnonces.iter().enumerate() {
        ensure!(
            !bool::from(pubnonce.is_identity()),
            "Coordinator message 1 has invalid public nonce at index {i}"
        );
    }

    Ok(())
}

fn pubshare(commitment: &[ProjectivePoint], idx: usize) -> ProjectivePoint {
    let x = Scalar::from((idx + 1) as u64);
    let mut x_power = Scalar::ONE;
    let mut pubshare = ProjectivePoint::IDENTITY;

    for C_k in commitment {
        pubshare += *C_k * x_power;
        x_power *= x;
    }

    pubshare
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
    type Message = ParticipantStep2TransitionMsg;
    type Next = ParticipantStep2State;
    type Output = ParticipantMsg2;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let n = self.host_pubkeys.len();
        validate_coordinator_msg1(&msg, self.t, n)?;

        ensure!(
            msg.coordinator_msg.coms_to_secrets[self.idx] == self.com_to_secret,
            "Coordinator sent unexpected commitment to secret for local participant"
        );
        ensure!(
            msg.coordinator_msg.pubnonces[self.idx] == self.pubnonce,
            "Coordinator sent unexpected public nonce for local participant"
        );

        for i in 0..n {
            if i == self.idx {
                continue;
            }

            ensure!(
                !bool::from(msg.coordinator_msg.coms_to_secrets[i].is_identity()),
                "Participant {i} sent invalid commitment"
            );

            chilldkg_pop_verify(
                &msg.coordinator_msg.pops[i],
                &msg.coordinator_msg.coms_to_secrets[i],
                i as u32,
            )
            .with_context(|| format!("Participant {i} sent invalid proof of possession"))?;
        }

        let enc_context = serialize_enc_context(self.t, &self.host_pubkeys);
        let mut secshare = decrypt(
            &self.s,
            &msg.coordinator_msg.pubnonces,
            &enc_context,
            self.idx,
            &msg.coordinator_msg.enc_secshares[self.idx],
        )?;

        let mut sum_commitment = Vec::with_capacity(self.t);
        sum_commitment.push(msg.coordinator_msg.coms_to_secrets.iter().sum());
        sum_commitment.extend_from_slice(&msg.coordinator_msg.sum_coms_to_nonconst_terms);

        let (pubtweak, tweak) = tap_tweak_no_script(&sum_commitment[0]);
        secshare += tweak;

        let mut sum_commitment_tweaked = sum_commitment.clone();
        sum_commitment_tweaked[0] += pubtweak;

        let pubshare_tweaked = pubshare(&sum_commitment_tweaked, self.idx);

        if ProjectivePoint::GENERATOR * secshare != pubshare_tweaked {
            bail!("Received invalid secret share");
        }

        let threshold_pubkey = sum_commitment_tweaked[0];
        let pubshares = (0..n)
            .map(|i| pubshare(&sum_commitment_tweaked, i))
            .collect();

        let transcript = get_certeq_transcript(
            self.t,
            &sum_commitment,
            &self.host_pubkeys,
            &msg.coordinator_msg.pubnonces,
            &msg.coordinator_msg.enc_secshares,
        );

        let sig = get_certeq(self.s, self.idx, &transcript, &msg.aux_rand)?;

        let dkg_output = DkgOutput {
            secshare,
            threshold_pubkey,
            pubshares,
        };
        let next_stage = ParticipantStep2State {
            idx: self.idx,
            t: self.t,
            host_pubkeys: self.host_pubkeys,
            transcript,
            dkg_output,
        };

        Ok((Some(next_stage), ParticipantMsg2 { sig }))
    }

    fn encryption_key(&self) -> ProjectivePoint {
        self.host_pubkeys[self.idx]
    }
}

impl ParticipantState for ParticipantStep2State {
    type Message = CoordinatorMsg2;
    type Next = Self;
    type Output = ();

    fn next(self, _msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        todo!("participant step 2 state transition is not implemented yet")
    }

    fn encryption_key(&self) -> ProjectivePoint {
        self.host_pubkeys[self.idx]
    }
}
