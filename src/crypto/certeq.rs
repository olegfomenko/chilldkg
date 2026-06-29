#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::ec::{BIP340XOnlyPubKey, compress_default, compress_scalar_bip340};
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tagged_hash;
use crate::crypto::tags::{
    TAG_BIP340_AUX, TAG_BIP340_CHALLENGE, TAG_BIP340_NONCE, TAG_CERTEQ_MESSAGE,
};
use anyhow::{Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};

/// Builds a transcript bytes. Then, this transcript hash will be signed to create
/// a certificate of equality. This data contains public transcript received by participant
/// during the DKG protocol execution.
pub fn get_certeq_transcript(
    t: usize,
    sum_commitment: &[ProjectivePoint],
    host_pubkeys: &[ProjectivePoint],
    pubnonces: &[ProjectivePoint],
    enc_secshares: &[Scalar],
) -> Vec<u8> {
    let mut eq_input = Vec::with_capacity(
        4 + 33 * sum_commitment.len()
            + 33 * host_pubkeys.len()
            + 33 * pubnonces.len()
            + 32 * enc_secshares.len(),
    );

    eq_input.extend_from_slice(&(t as u32).to_be_bytes());
    for C_k in sum_commitment {
        eq_input.extend_from_slice(&compress_default(C_k));
    }
    for P_i in host_pubkeys {
        eq_input.extend_from_slice(&compress_default(P_i));
    }
    for R_i in pubnonces {
        eq_input.extend_from_slice(&compress_default(R_i));
    }
    for enc_secshare in enc_secshares {
        let bytes: [u8; 32] = enc_secshare.to_bytes().into();
        eq_input.extend_from_slice(&bytes);
    }

    eq_input
}

pub struct CertEQSigner {
    hostkey: Scalar,
    message: Vec<u8>,
    aux_rand: [u8; 32],
}

impl CertEQSigner {
    pub fn new(hostkey: Scalar, transcript: &[u8], idx: usize, aux_rand: [u8; 32]) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQSigner {
            hostkey,
            message,
            aux_rand,
        }
    }
}

impl SchnorrSigner for CertEQSigner {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn secret_key(&self) -> Scalar {
        self.hostkey
    }

    fn x_only_nonce(&self) -> Result<(BIP340XOnlyPubKey, Scalar)> {
        let (p_x, d) = self.x_only_key();
        let aux_hash = tagged_hash(TAG_BIP340_AUX, self.aux_rand);

        let mut t: [u8; 32] = d.to_bytes().into();
        for i in 0..32 {
            t[i] ^= aux_hash[i];
        }

        let mut nonce_preimage = Vec::with_capacity(32 + 32 + self.message().len());
        nonce_preimage.extend_from_slice(&t);
        nonce_preimage.extend_from_slice(&p_x);
        nonce_preimage.extend_from_slice(&self.message());

        let k0 = Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_BIP340_NONCE,
            nonce_preimage,
        )));

        ensure!(
            !bool::from(k0.is_zero()),
            "CertEq signing failed: BIP340: nonce is zero"
        );

        Ok(compress_scalar_bip340(&k0))
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_certeq_challenge(R, P, self.message())
    }
}

pub struct CertEQVerifier {
    host_pubkey: ProjectivePoint,
    message: Vec<u8>,
}

impl CertEQVerifier {
    pub fn new(host_pubkey: ProjectivePoint, transcript: &[u8], idx: usize) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQVerifier {
            host_pubkey,
            message,
        }
    }
}

impl SchnorrVerifier for CertEQVerifier {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn pub_key(&self) -> ProjectivePoint {
        self.host_pubkey
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_certeq_challenge(R, P, self.message())
    }
}

fn get_certeq_challenge(
    R: &BIP340XOnlyPubKey,
    P: &BIP340XOnlyPubKey,
    message: &[u8],
) -> Result<Scalar> {
    let mut challenge_preimage = Vec::with_capacity(32 + 32 + message.len());
    challenge_preimage.extend_from_slice(R);
    challenge_preimage.extend_from_slice(P);
    challenge_preimage.extend_from_slice(message);

    Ok(Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_BIP340_CHALLENGE,
        challenge_preimage,
    ))))
}

fn get_certeq_message(transcript: &[u8], idx: usize) -> Vec<u8> {
    //   ("BIP DKG/certeq message" || zero padding to 33 bytes)
    //   || uint32_be(idx)
    //   || transcript

    let tag = TAG_CERTEQ_MESSAGE.as_bytes();
    let mut message = Vec::with_capacity(33 + 4 + transcript.len());

    message.extend_from_slice(tag);
    message.resize(33, 0);
    message.extend_from_slice(&(idx as u32).to_be_bytes());
    message.extend_from_slice(transcript);

    message
}
