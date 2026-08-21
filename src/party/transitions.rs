#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::{CertEQSigner, CertEQTranscript, verify_certeq_certificate};
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, Hash, ScalarBytes};
use crate::crypto::ec::{eval_pub_share, parse_scalar_from_hash, tap_tweak_no_script};
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
use zeroize::Zeroizing;

pub(crate) fn serialize_enc_context<C: Curve>(t: usize, host_pubkeys: &[C::Point]) -> Vec<u8> {
    let mut enc_context =
        Vec::with_capacity(4 + <C::Point as CurvePoint>::BYTES_SIZE * host_pubkeys.len());
    enc_context.extend_from_slice(&(t as u32).to_be_bytes());

    for P_i in host_pubkeys {
        enc_context.extend_from_slice(P_i.to_bytes().as_ref());
    }

    enc_context
}

pub(crate) fn derive_simpl_seed<C: Curve>(
    s: &C::Scalar,
    random: &[u8; 32],
    enc_context: &[u8],
) -> Zeroizing<Hash<C>> {
    let seed: Zeroizing<ScalarBytes<C>> = Zeroizing::new(s.to_bytes());

    let mut preimage = Zeroizing::new(Vec::with_capacity(
        <C::Scalar as CurveScalar>::BYTES_SIZE + random.len() + enc_context.len(),
    ));
    preimage.extend_from_slice(seed.as_ref());
    preimage.extend_from_slice(random);
    preimage.extend_from_slice(enc_context);

    Zeroizing::new(tagged_hash::<C>(TAG_ENCPEDPOP_SEED, &preimage))
}

impl<C: Curve> ParticipantState for ParticipantInitialState<C> {
    type Message = (Vec<C::Point>, usize, [u8; 32]);
    type Next = ParticipantStep1State<C>;
    type Output = ParticipantMsg1<C>;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (host_pubkeys, t, random) = msg;

        let idx = self.validate_session_params(&host_pubkeys, t)?;

        let enc_context = serialize_enc_context::<C>(t, &host_pubkeys);
        let simpl_seed = derive_simpl_seed::<C>(&self.s, &random, &enc_context);

        let r_nonce_hash = Zeroizing::new(tagged_hash::<C>(TAG_ENCPEDPOP_SECNONCE, &*simpl_seed));
        let r = Zeroizing::new(parse_scalar_from_hash::<C>(&r_nonce_hash)?);

        chill_dkg_ensure!(
            !r.is_zero(),
            ChillDkgError::RuntimeError("EncPedPop secret nonce must not be zero".to_owned()),
        );

        let polynomial = Polynomial::<C>::new(&simpl_seed, t)?;

        let shares = polynomial.eval_shares(host_pubkeys.len() as u64);

        let commitment: Vec<C::Point> = polynomial.commit();

        let a0 = polynomial
            .coeff(0)
            .ok_or_else(|| ChillDkgError::RuntimeError("Free term must exist".to_owned()))?;

        let pop = PopSigner::<C>::new(&a0, &simpl_seed, idx as u32).sign()?;

        let pubnonce = C::Point::GENERATOR * *r;

        let enc_shares = encrypt::<C>(&r, &self.s, &host_pubkeys, &enc_context, idx, &shares)?;

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

impl<C: Curve> ParticipantState for ParticipantStep1State<C> {
    type Message = (CoordinatorMsg1<C>, [u8; 32]);
    type Next = ParticipantStep2State<C>;
    type Output = ParticipantMsg2<C>;

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
                !coordinator_msg.coms_to_secrets[i].is_identity(),
                ChillDkgError::FaultyParticipantOrCoordinatorError {
                    participant: i,
                    message: "Participant sent invalid commitment".to_owned(),
                },
            );

            chill_dkg_ensure!(
                PopVerifier::<C>::new(coordinator_msg.coms_to_secrets[i], i as u32)
                    .verify(coordinator_msg.pops[i])
                    .is_ok(),
                ChillDkgError::FaultyParticipantOrCoordinatorError {
                    participant: i,
                    message: "Participant sent invalid proof-of-knowledge".to_owned(),
                },
            );
        }

        let enc_context = serialize_enc_context::<C>(self.t, &self.host_pubkeys);
        let mut secshare = decrypt::<C>(
            &self.s,
            &coordinator_msg.pubnonces,
            &enc_context,
            self.idx,
            &coordinator_msg.enc_secshares[self.idx],
        )?;

        let mut sum_commitment = Vec::with_capacity(self.t);
        sum_commitment.push(coordinator_msg.coms_to_secrets.iter().sum());
        sum_commitment.extend_from_slice(&coordinator_msg.sum_coms_to_nonconst_terms);

        let (pubtweak, tweak) = tap_tweak_no_script::<C>(&sum_commitment[0])?;
        *secshare += tweak;

        let mut sum_commitment_tweaked = sum_commitment.clone();
        sum_commitment_tweaked[0] += pubtweak;

        let pubshare_tweaked = eval_pub_share::<C>(&sum_commitment_tweaked, self.idx);

        chill_dkg_ensure!(
            C::Point::GENERATOR * *secshare == pubshare_tweaked,
            ChillDkgError::UnknownFaultyParticipantOrCoordinatorError(
                "Received invalid secshare, consider investigation procedure to determine faulty party"
                    .to_owned(),
            ),
        );

        let threshold_pubkey = sum_commitment_tweaked[0];
        let pubshares = (0..self.host_pubkeys.len())
            .map(|i| eval_pub_share::<C>(&sum_commitment_tweaked, i))
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

        let sig = CertEQSigner::<C>::new(&self.s, &transcript, self.idx, aux).sign()?;

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

impl<C: Curve> ParticipantState for ParticipantStep2State<C> {
    type Message = CoordinatorMsg2<C>;
    type Next = Self;
    type Output = (DKGOutput<C>, RecoveryData<C>);

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        verify_certeq_certificate::<C>(&self.transcript, &msg.cert)?;

        let recovery_data = RecoveryData {
            transcript: self.transcript,
            cert: msg.cert,
        };

        Ok((None, (self.dkg_output, recovery_data)))
    }
}
