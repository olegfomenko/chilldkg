#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::certeq::{get_certeq, get_certeq_transcript, verify_certeq};
use crate::crypto::ec::{compress_default, eval_pub_share, tap_tweak_no_script};
use crate::crypto::enc::{decrypt, encrypt};
use crate::crypto::pop::{chilldkg_pop_sign, chilldkg_pop_verify};
use crate::crypto::tags::{TAG_ENCPEDPOP_SECNONCE, TAG_ENCPEDPOP_SEED};
use crate::crypto::{scalar_from_bytes, tagged_hash};
use crate::math::Polynomial;
use crate::msg::{CoordinatorMsg1, RecoveryData};
use crate::msg::{CoordinatorMsg2, ParticipantMsg1, ParticipantMsg2};
use crate::party::{
    DKGOutput, ParticipantInitialState, ParticipantParamsState, ParticipantState,
    ParticipantStep1State, ParticipantStep2State,
};
use anyhow::{Context, Result, bail, ensure};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

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
    type Message = (Vec<ProjectivePoint>, usize);
    type Next = ParticipantParamsState;
    type Output = ();

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (host_pubkeys, t) = msg;
        let next_stage = ParticipantParamsState {
            idx: self.idx,
            s: self.s,
            host_pubkeys,
            t,
        };

        next_stage.validate_session_params()?;

        Ok((Some(next_stage), ()))
    }
}

impl ParticipantState for ParticipantParamsState {
    type Message = [u8; 32];
    type Next = ParticipantStep1State;
    type Output = ParticipantMsg1;

    fn next(self, random: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let enc_context = serialize_enc_context(self.t, &self.host_pubkeys);
        let simpl_seed = derive_simpl_seed(&self.s, &random, &enc_context);

        let r = scalar_from_bytes(tagged_hash(TAG_ENCPEDPOP_SECNONCE, simpl_seed))?;

        ensure!(r != Scalar::ZERO, "EncPedPop secret nonce must not be zero");

        let polynomial = Polynomial::new(&simpl_seed, self.t)?;

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
}

impl ParticipantState for ParticipantStep1State {
    type Message = (CoordinatorMsg1, [u8; 32]);
    type Next = ParticipantStep2State;
    type Output = ParticipantMsg2;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (coordinator_msg, aux) = msg;
        self.validate_coordinator_msg1(&coordinator_msg)?;

        ensure!(
            coordinator_msg.coms_to_secrets[self.idx] == self.com_to_secret,
            "Coordinator sent unexpected commitment to secret for local participant"
        );
        ensure!(
            coordinator_msg.pubnonces[self.idx] == self.pubnonce,
            "Coordinator sent unexpected public nonce for local participant"
        );

        for i in 0..self.host_pubkeys.len() {
            if i == self.idx {
                continue;
            }

            ensure!(
                !bool::from(coordinator_msg.coms_to_secrets[i].is_identity()),
                "Participant {i} sent invalid commitment"
            );

            chilldkg_pop_verify(
                &coordinator_msg.pops[i],
                &coordinator_msg.coms_to_secrets[i],
                i as u32,
            )
            .with_context(|| format!("Participant {i} sent invalid proof of possession"))?;
        }

        let enc_context = serialize_enc_context(self.t, &self.host_pubkeys);
        let mut secshare = decrypt(
            &self.s,
            &coordinator_msg.pubnonces,
            &enc_context,
            self.idx,
            &coordinator_msg.enc_secshares[self.idx],
        )?;

        let mut sum_commitment = Vec::with_capacity(self.t);
        sum_commitment.push(coordinator_msg.coms_to_secrets.iter().sum());
        sum_commitment.extend_from_slice(&coordinator_msg.sum_coms_to_nonconst_terms);

        let (pubtweak, tweak) = tap_tweak_no_script(&sum_commitment[0])?;
        secshare += tweak;

        let mut sum_commitment_tweaked = sum_commitment.clone();
        sum_commitment_tweaked[0] += pubtweak;

        let pubshare_tweaked = eval_pub_share(&sum_commitment_tweaked, self.idx);

        if ProjectivePoint::GENERATOR * secshare != pubshare_tweaked {
            bail!("Received invalid secret share");
        }

        let threshold_pubkey = sum_commitment_tweaked[0];
        let pubshares = (0..self.host_pubkeys.len())
            .map(|i| eval_pub_share(&sum_commitment_tweaked, i))
            .collect();

        let transcript = get_certeq_transcript(
            self.t,
            &sum_commitment,
            &self.host_pubkeys,
            &coordinator_msg.pubnonces,
            &coordinator_msg.enc_secshares,
        );

        let sig = get_certeq(self.s, self.idx, &transcript, &aux)?;

        let dkg_output = DKGOutput {
            idx: self.idx,
            t: self.t,
            secshare,
            threshold_pubkey,
            pubshares,
        };
        let next_stage = ParticipantStep2State {
            host_pubkeys: self.host_pubkeys,
            transcript,
            dkg_output,
        };

        Ok((Some(next_stage), ParticipantMsg2 { sig }))
    }
}

impl ParticipantState for ParticipantStep2State {
    type Message = CoordinatorMsg2;
    type Next = Self;
    type Output = (DKGOutput, RecoveryData);

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        ensure!(
            msg.cert.len() == self.host_pubkeys.len(),
            "CertEq certificate has invalid number of signatures"
        );

        for (i, (host_pubkey, sig)) in self.host_pubkeys.iter().zip(msg.cert.iter()).enumerate() {
            verify_certeq(host_pubkey, i, &self.transcript, sig).with_context(|| {
                format!("CertEq certificate has invalid signature at index {i}")
            })?;
        }

        let recovery_data = RecoveryData {
            transcript: self.transcript,
            cert: msg.cert,
        };

        Ok((None, (self.dkg_output, recovery_data)))
    }
}
