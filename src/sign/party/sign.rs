#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

//! Production of a partial signature: the signer-side counterpart of
//! [`coordinator::verify`](crate::sign::coordinator::verify).

use crate::chill_dkg_ensure;
use crate::crypto::ec::compress_point_bip340;
use crate::crypto::lagrange::lagrange;
use crate::crypto::schnorr::bip340_challenge;
use crate::crypto::tweak::{Tweak, TweakContext};
use crate::sign::coordinator::verify::{aggr_pubnonces, signing_nonce, validate_signers};
use crate::sign::errors::{Result, SignError};
use crate::sign::msg::{PartialSignature, PubNonce};
use crate::sign::partial_verify;
use crate::sign::party::nonce::SecNonce;
use k256::{ProjectivePoint, Scalar};
use zeroize::Zeroizing;

/// Produces the partial signature of participant `idx` over `msg` under the
/// threshold key tweaked by `tweaks`, given the public nonces of every signer
/// (this one included) paired with their participant ids.
///
/// Runs the reference `validate_signers_ctx` checks first, then checks the
/// signer's own share, signs, and verifies its own result. Single use of the
/// nonce is the caller's responsibility; the state machine enforces it by
/// consuming the [`SignerStep1State`](crate::sign::SignerStep1State).
///
/// Mirrors the reference `sign`.
///
/// Math: `k_j = -k_j` if `R` has an odd `y`; `d = g * gacc * u_i`;
/// `s_i = k_1 + b * k_2 + e * a_i * d`.
#[expect(clippy::too_many_arguments)]
pub fn partial_sign(
    idx: usize,
    t: usize,
    secshare: &Scalar,
    pubshares: &[ProjectivePoint],
    threshold_pubkey: &ProjectivePoint,
    secnonce: &SecNonce,
    pubnonces: &[(usize, PubNonce)],
    msg: &[u8],
    tweaks: &[Tweak],
) -> Result<PartialSignature> {
    chill_dkg_ensure!(
        !bool::from(secnonce.k1.is_zero()),
        SignError::Value("first secnonce value is out of range.".into()),
    );
    chill_dkg_ensure!(
        !bool::from(secnonce.k2.is_zero()),
        SignError::Value("second secnonce value is out of range.".into()),
    );
    chill_dkg_ensure!(
        !bool::from(secshare.is_zero()),
        SignError::Value("The signer's secret share value is out of range.".into()),
    );

    // Ids are kept in the given order so validation errors name the same
    // index as the reference; duplicates are rejected by `validate_signers`.
    let ids: Vec<usize> = pubnonces.iter().map(|(id, _)| *id).collect();
    validate_signers(t, pubshares, threshold_pubkey, &ids)?;

    let tweak_ctx = TweakContext::new(*threshold_pubkey).apply_all(tweaks)?;
    let (b, R) = signing_nonce(
        &ids,
        aggr_pubnonces(pubnonces.iter().map(|(_, pubnonce)| pubnonce)),
        &tweak_ctx,
        msg,
    );
    let e = bip340_challenge(&compress_point_bip340(&R), &tweak_ctx.xonly_pubkey(), msg)?;

    // Fails if idx is not among the signers (so idx < n from here on).
    let a = lagrange(&ids, idx)?;

    // The share we hold must be the one the group knows us by.
    let pubshare = ProjectivePoint::GENERATOR * secshare;
    chill_dkg_ensure!(
        pubshare == pubshares[idx],
        SignError::Value("The signer's pubshare must be included in the list of pubshares.".into()),
    );

    // Public nonce of the un-negated secret nonce, used for the self-check below.
    let pubnonce = secnonce.pubnonce();
    let k = secnonce.even_y_nonce(&R);

    let d = Zeroizing::new((tweak_ctx.g() * tweak_ctx.gacc) * secshare);
    let b_k2 = Zeroizing::new(b * k.k2);
    let e_a_d = Zeroizing::new((e * a) * d.as_ref());
    let s = k.k1 + b_k2.as_ref() + e_a_d.as_ref();

    // The result of signing must pass partial signature verification.
    partial_verify(&s, idx, &pubnonce, &pubshare, &ids, &tweak_ctx, b, &R, e)
        .map_err(|_| SignError::Runtime("produced partial signature does not verify".into()))?;

    Ok(s)
}
