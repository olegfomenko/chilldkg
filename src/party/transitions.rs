#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::{CertEQSigner, CertEQTranscript, verify_certeq_certificate};
use crate::crypto::ec::{
    COMPRESSED_POINT_BYTES_SIZE, EC_SCALAR_BYTES_SIZE, ScalarBytes, compress_default,
    eval_pub_share, parse_secret_scalar_from_bytes, tap_tweak_no_script,
};
use crate::crypto::enc::{decrypt, encrypt};
use crate::crypto::poly::Polynomial;
use crate::crypto::pop::{PopSigner, PopVerifier};
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_ENCPEDPOP_SECNONCE, TAG_ENCPEDPOP_SEED};
use crate::errors::{ChillDkgError, Result};
use crate::msg::{CoordinatorMsg1, RecoveryData};
use crate::msg::{CoordinatorMsg2, ParticipantMsg1, ParticipantMsg2};
use crate::party::{
    DKGOutput, ParticipantInitialState, ParticipantState, ParticipantStep1State,
    ParticipantStep2State,
};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use zeroize::Zeroizing;

pub(crate) fn serialize_enc_context(t: usize, host_pubkeys: &[ProjectivePoint]) -> Vec<u8> {
    let mut enc_context = Vec::with_capacity(4 + COMPRESSED_POINT_BYTES_SIZE * host_pubkeys.len());
    enc_context.extend_from_slice(&(t as u32).to_be_bytes());

    for P_i in host_pubkeys {
        enc_context.extend_from_slice(&compress_default(P_i));
    }

    enc_context
}

pub(crate) fn derive_simpl_seed(
    s: &Scalar,
    random: &[u8; 32],
    enc_context: &[u8],
) -> Zeroizing<[u8; 32]> {
    let seed: Zeroizing<[u8; EC_SCALAR_BYTES_SIZE]> =
        Zeroizing::from(ScalarBytes::from(s.to_bytes()));

    let mut preimage = Zeroizing::new(Vec::with_capacity(
        EC_SCALAR_BYTES_SIZE + random.len() + enc_context.len(),
    ));
    preimage.extend_from_slice(seed.as_slice());
    preimage.extend_from_slice(random);
    preimage.extend_from_slice(enc_context);

    tagged_hash(TAG_ENCPEDPOP_SEED, &preimage).into()
}

impl ParticipantState for ParticipantInitialState {
    type Message = (Vec<ProjectivePoint>, usize, [u8; 32]);
    type Next = ParticipantStep1State;
    type Output = ParticipantMsg1;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (host_pubkeys, t, random) = msg;

        let idx = self.validate_session_params(&host_pubkeys, t)?;

        let enc_context = serialize_enc_context(t, &host_pubkeys);
        let simpl_seed = derive_simpl_seed(&self.s, &random, &enc_context);

        let r_nonce_hash = Zeroizing::new(tagged_hash(TAG_ENCPEDPOP_SECNONCE, &simpl_seed));
        let r = Zeroizing::new(parse_secret_scalar_from_bytes(r_nonce_hash)?);

        chill_dkg_ensure!(
            *r != Scalar::ZERO,
            ChillDkgError::RuntimeError("EncPedPop secret nonce must not be zero".to_owned()),
        );

        let polynomial = Polynomial::new(&simpl_seed, t)?;

        let shares = polynomial.eval_shares(host_pubkeys.len() as u64);

        let commitment: Vec<ProjectivePoint> = polynomial.commit();

        let pop = PopSigner::new(
            polynomial
                .coeff(0)
                .ok_or_else(|| ChillDkgError::RuntimeError("Free term must exist".to_owned()))?
                .as_ref(),
            &simpl_seed,
            idx as u32,
        )
        .sign()?;

        let pubnonce = ProjectivePoint::GENERATOR * r.as_ref();

        let enc_shares = encrypt(&r, &self.s, &host_pubkeys, &enc_context, idx, &shares)?;

        let com_to_secret = commitment[0];

        let pmsg1 = ParticipantMsg1 {
            commitment,
            pop,
            pubnonce,
            enc_shares,
        };

        let next_stage = ParticipantStep1State {
            idx,
            s: self.s,
            host_pubkeys,
            t,
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

        chill_dkg_ensure!(
            coordinator_msg.coms_to_secrets[self.idx] == self.com_to_secret,
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator sent unexpected first group element for local index".to_owned()
            ),
        );
        chill_dkg_ensure!(
            coordinator_msg.pubnonces[self.idx] == self.pubnonce,
            ChillDkgError::FaultyCoordinatorError(
                "Coordinator replied with wrong pubnonce".to_owned()
            ),
        );

        for i in 0..self.host_pubkeys.len() {
            if i == self.idx {
                continue;
            }

            chill_dkg_ensure!(
                !bool::from(coordinator_msg.coms_to_secrets[i].is_identity()),
                ChillDkgError::FaultyParticipantOrCoordinatorError {
                    participant: i,
                    message: "Participant sent invalid commitment".to_owned(),
                },
            );

            chill_dkg_ensure!(
                PopVerifier::new(coordinator_msg.coms_to_secrets[i], i as u32)
                    .verify(coordinator_msg.pops[i])
                    .is_ok(),
                ChillDkgError::FaultyParticipantOrCoordinatorError {
                    participant: i,
                    message: "Participant sent invalid proof-of-knowledge".to_owned(),
                },
            );
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
        *secshare += tweak.as_ref();

        let mut sum_commitment_tweaked = sum_commitment.clone();
        sum_commitment_tweaked[0] += pubtweak;

        let pubshare_tweaked = eval_pub_share(&sum_commitment_tweaked, self.idx);

        chill_dkg_ensure!(
            ProjectivePoint::GENERATOR * secshare.as_ref() == pubshare_tweaked,
            ChillDkgError::UnknownFaultyParticipantOrCoordinatorError(
                "Received invalid secshare, consider investigation procedure to determine faulty party"
                    .to_owned(),
            ),
        );

        let threshold_pubkey = sum_commitment_tweaked[0];
        let pubshares = (0..self.host_pubkeys.len())
            .map(|i| eval_pub_share(&sum_commitment_tweaked, i))
            .collect();

        let transcript = CertEQTranscript::new(
            self.t,
            sum_commitment,
            // ParticipantStep1State implements Drop so while this field is not clonable it
            // can't be moved. Should be possible to optimized by
            // ```rust
            //  let mut this = self;
            //  let host_pubkeys = core::mem::take(&mut this.host_pubkeys);
            // ```
            // but the code becomes dusty IMHO
            self.host_pubkeys.clone(),
            coordinator_msg.pubnonces,
            coordinator_msg.enc_secshares,
        );

        let sig = CertEQSigner::new(&self.s, &transcript, self.idx, aux).sign()?;

        let dkg_output = DKGOutput {
            idx: self.idx,
            t: self.t,
            secshare: *secshare,
            threshold_pubkey,
            pubshares,
        };
        let next_stage = ParticipantStep2State {
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
        verify_certeq_certificate(&self.transcript, &msg.cert)?;

        let recovery_data = RecoveryData {
            transcript: self.transcript,
            cert: msg.cert,
        };

        Ok((None, (self.dkg_output, recovery_data)))
    }
}
