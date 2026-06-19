#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::ec::{
    compress_default, compress_point_bip340, compress_scalar_bip340, event_y_point,
};
use crate::crypto::pop::SchnorrSignature;
use crate::crypto::tags::{
    TAG_BIP340_AUX, TAG_BIP340_CHALLENGE, TAG_BIP340_NONCE, TAG_CERTEQ_MESSAGE,
};
use crate::crypto::{scalar_from_bytes, tagged_hash};
use anyhow::{Context, Result, bail, ensure};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
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

pub fn get_certeq(
    s: Scalar,
    idx: usize,
    transcript: &[u8],
    aux_rand: &[u8; 32],
) -> Result<SchnorrSignature> {
    ensure!(
        !bool::from(s.is_zero()),
        "CertEq signing failed: BIP340: secret key is zero"
    );

    let msg = certeq_message(transcript, idx);
    let (p_x, d) = compress_scalar_bip340(&s);
    let aux_hash = tagged_hash(TAG_BIP340_AUX, aux_rand);

    let mut t: [u8; 32] = d.to_bytes().into();
    for i in 0..32 {
        t[i] ^= aux_hash[i];
    }

    let mut nonce_preimage = Vec::with_capacity(32 + 32 + msg.len());
    nonce_preimage.extend_from_slice(&t);
    nonce_preimage.extend_from_slice(&p_x);
    nonce_preimage.extend_from_slice(&msg);

    let k0 = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_BIP340_NONCE,
        nonce_preimage,
    )));
    ensure!(
        !bool::from(k0.is_zero()),
        "CertEq signing failed: BIP340: nonce is zero"
    );

    let (r_x, k) = compress_scalar_bip340(&k0);

    let mut challenge_preimage = Vec::with_capacity(32 + 32 + msg.len());
    challenge_preimage.extend_from_slice(&r_x);
    challenge_preimage.extend_from_slice(&p_x);
    challenge_preimage.extend_from_slice(&msg);

    let e = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_BIP340_CHALLENGE,
        challenge_preimage,
    )));

    let s: [u8; 32] = (k + e * d).to_bytes().into();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_x);
    sig[32..].copy_from_slice(&s);
    Ok(sig)
}

pub fn verify_certeq(
    host_pubkey: &ProjectivePoint,
    idx: usize,
    transcript: &[u8],
    sig: &SchnorrSignature,
) -> Result<()> {
    ensure!(
        !bool::from(host_pubkey.is_identity()),
        "CertEq verification failed: host public key is identity"
    );

    let msg = certeq_message(transcript, idx);

    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&sig[..32]);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);

    let s = scalar_from_bytes(s_bytes)
        .context("CertEq verification failed: invalid response scalar")?;

    let P = event_y_point(host_pubkey);
    let P_x = compress_point_bip340(host_pubkey);

    let mut challenge_preimage = Vec::with_capacity(32 + 32 + msg.len());
    challenge_preimage.extend_from_slice(&r_x);
    challenge_preimage.extend_from_slice(&P_x);
    challenge_preimage.extend_from_slice(&msg);

    let e = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_BIP340_CHALLENGE,
        challenge_preimage,
    )));

    let R = ProjectivePoint::GENERATOR * s - P * e;
    ensure!(
        !bool::from(R.is_identity()),
        "CertEq verification failed: nonce is identity"
    );

    let R = R.to_affine();
    ensure!(
        !bool::from(R.y_is_odd()),
        "CertEq verification failed: nonce has odd Y"
    );

    let computed_r_x: [u8; 32] = R.x().into();
    if computed_r_x != r_x {
        bail!("CertEq verification failed: invalid signature");
    }

    Ok(())
}

pub fn verify_certeq_cert(
    host_pubkeys: &[ProjectivePoint],
    transcript: &[u8],
    cert: &[SchnorrSignature],
) -> Result<()> {
    ensure!(
        cert.len() == host_pubkeys.len(),
        "CertEq certificate has invalid number of signatures"
    );

    for (i, (host_pubkey, sig)) in host_pubkeys.iter().zip(cert.iter()).enumerate() {
        verify_certeq(host_pubkey, i, transcript, sig)
            .with_context(|| format!("CertEq certificate has invalid signature at index {i}"))?;
    }

    Ok(())
}

fn certeq_message(transcript: &[u8], idx: usize) -> Vec<u8> {
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
