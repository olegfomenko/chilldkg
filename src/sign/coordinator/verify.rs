#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

//! Verification and aggregation of FROST3 contributions: the checks anyone
//! can run with only the public key material, and the shared math the
//! signer and coordinator state machines are built on.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    X_ONLY_POINT_BYTES_SIZE, compress_default, compress_point_bip340, has_even_y,
    reduce_scalar_from_bytes,
};
use crate::crypto::lagrange::{interpolate_pubkey, lagrange};
use crate::crypto::schnorr::{
    SCHNORR_SIG_BYTES_SIZE, SchnorrSignature, SchnorrVerifier, bip340_challenge,
};
use crate::crypto::tagged_hash;
use crate::crypto::tags::TAG_FROST_NONCECOEF;
use crate::crypto::tweak::{Tweak, TweakContext};
use crate::sign::errors::{Result, SignError};
use crate::sign::msg::{PartialSignature, PubNonce};
use itertools::Itertools;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// Checks that `ids` is a valid signing subset for the key material:
/// `t <= |ids| <= n`, every id is in range, no duplicates, no identity
/// public share, and the subset's public shares interpolate to the
/// threshold key.
///
/// Mirrors the reference `validate_signers_ctx`.
pub fn validate_signers(
    t: usize,
    pubshares: &[ProjectivePoint],
    threshold_pubkey: &ProjectivePoint,
    ids: &[usize],
) -> Result<()> {
    let n = pubshares.len();
    chill_dkg_ensure!(
        t >= 1 && t <= n,
        SignError::Value("The threshold must be 1 <= t <= n.".into()),
    );
    chill_dkg_ensure!(
        t <= ids.len() && ids.len() <= n,
        SignError::Value("The number of signers must be between t and n.".into()),
    );
    for (idx, &id) in ids.iter().enumerate() {
        chill_dkg_ensure!(
            id < n,
            SignError::Value(
                format!("The participant identifier at index {idx} is out of range.").into()
            ),
        );
        chill_dkg_ensure!(
            !bool::from(pubshares[id].is_identity()),
            SignError::Value(format!("Invalid pubshare at index {idx}.").into()),
        );
    }

    chill_dkg_ensure!(
        ids.iter().all_unique(),
        SignError::Value("The participant identifier list contains duplicate elements.".into()),
    );

    let pubshares: Vec<ProjectivePoint> = ids.iter().map(|&id| pubshares[id]).collect();
    chill_dkg_ensure!(
        &interpolate_pubkey(ids, &pubshares)? == threshold_pubkey,
        SignError::Value("The provided key material is incorrect.".into()),
    );
    Ok(())
}

/// The key a signature produced with `tweaks` verifies under (BIP340 x-only
/// semantics).
pub fn signing_pubkey(
    threshold_pubkey: &ProjectivePoint,
    tweaks: &[Tweak],
) -> Result<ProjectivePoint> {
    Ok(TweakContext::new(*threshold_pubkey).apply_all(tweaks)?.q)
}

/// Verifies a final signature over `msg` as a plain BIP340 signature under
/// the threshold key tweaked by `tweaks`.
pub fn verify(
    threshold_pubkey: &ProjectivePoint,
    sig: SchnorrSignature,
    msg: &[u8],
    tweaks: &[Tweak],
) -> Result<()> {
    struct Bip340<'a> {
        msg: &'a [u8],
        Q: ProjectivePoint,
    }

    impl SchnorrVerifier for Bip340<'_> {
        fn message(&self) -> &[u8] {
            self.msg
        }

        fn pub_key(&self) -> ProjectivePoint {
            self.Q
        }
    }

    Bip340 {
        msg,
        Q: signing_pubkey(threshold_pubkey, tweaks)?,
    }
    .verify(sig)?;
    Ok(())
}

/// Nonce coefficient and final nonce of the session, from the signing subset
/// (in any order; committed to as a set) and the aggregate nonce.
///
/// Math: `b = H_noncecoef(ser_ids || aggnonce || Q_x || msg)` where ser_ids is
/// the sorted ids as 4-byte big-endian integers (a set, per ROAST) and aggnonce
/// is `R_1 || R_2` compressed with the identity as 33 zero bytes;
/// `R = R_1 + b * R_2`, or `G` if that is the identity. Fails if `b` is zero, which
/// cannot occur except with negligible probability (the reference asserts it).
pub fn signing_nonce(
    ids: &[usize],
    aggnonce: (ProjectivePoint, ProjectivePoint),
    tweak_ctx: &TweakContext,
    msg: &[u8],
) -> Result<(Scalar, ProjectivePoint)> {
    let mut sorted_ids = ids.to_vec();
    sorted_ids.sort_unstable();
    let ser_ids: Vec<u8> = sorted_ids
        .iter()
        .flat_map(|&id| (id as u32).to_be_bytes())
        .collect();
    let (R1, R2) = aggnonce;

    let b = reduce_scalar_from_bytes(tagged_hash(
        TAG_FROST_NONCECOEF,
        [
            ser_ids.as_slice(),
            &compress_default(&R1),
            &compress_default(&R2),
            &tweak_ctx.xonly_pubkey(),
            msg,
        ]
        .concat(),
    ));

    chill_dkg_ensure!(
        !bool::from(b.is_zero()),
        SignError::Runtime("nonce coefficient is zero".into()),
    );

    let R_ = R1 + R2 * b;
    let R = if bool::from(R_.is_identity()) {
        ProjectivePoint::GENERATOR
    } else {
        R_
    };

    Ok((b, R))
}

/// The session's BIP340 challenge.
///
/// Math: `e = H_challenge(R_x || Q_x || msg)`. Fails if `e` is zero, which
/// cannot occur except with negligible probability (the reference asserts it).
pub fn challenge(R: &ProjectivePoint, tweak_ctx: &TweakContext, msg: &[u8]) -> Result<Scalar> {
    let e = bip340_challenge(&compress_point_bip340(R), &tweak_ctx.xonly_pubkey(), msg)?;
    chill_dkg_ensure!(
        !bool::from(e.is_zero()),
        SignError::Runtime("challenge is zero".into()),
    );

    Ok(e)
}

/// Math: `s_i * G == R_i' + (e * a_i * g * gacc) * Y_i`, where
/// `R_i' = R_{i,1} + b * R_{i,2}`, negated if `R` has an odd `y`.
#[expect(clippy::too_many_arguments)]
pub fn partial_verify(
    psig: &PartialSignature,
    id: usize,
    pubnonce: &PubNonce,
    pubshare: &ProjectivePoint,
    ids: &[usize],
    tweak_ctx: &TweakContext,
    b: Scalar,
    R: &ProjectivePoint,
    e: Scalar,
) -> Result<()> {
    chill_dkg_ensure!(
        !pubnonce.is_identity(),
        SignError::InvalidContribution {
            participant: id,
            message: "invalid pubnonce".into(),
        },
    );

    let Re_s_ = pubnonce.R1 + pubnonce.R2 * b;
    let Re_s = if has_even_y(R) { Re_s_ } else { -Re_s_ };

    // Fails if id is not among the signers.
    let a = lagrange(ids, id)?;
    let g_ = tweak_ctx.g() * tweak_ctx.gacc;

    chill_dkg_ensure!(
        ProjectivePoint::GENERATOR * psig == Re_s + pubshare * &(e * a * g_),
        SignError::InvalidContribution {
            participant: id,
            message: "invalid partial signature".into(),
        },
    );

    Ok(())
}

/// Combines partial signatures into the final BIP340 signature *without*
/// verifying them; the coordinator state machine verifies first. Mirrors the
/// reference `partial_sig_agg`.
///
/// Math: `s = sum_i s_i + e * g * tacc`; signature is `R_x || s`.
pub fn combine<'a>(
    psigs: impl IntoIterator<Item = &'a PartialSignature>,
    tweak_ctx: &TweakContext,
    R: &ProjectivePoint,
    e: Scalar,
) -> SchnorrSignature {
    let mut s = Scalar::ZERO;
    for psig in psigs {
        s += psig;
    }
    s += e * tweak_ctx.g() * tweak_ctx.tacc;

    let mut sig = [0u8; SCHNORR_SIG_BYTES_SIZE];
    sig[..X_ONLY_POINT_BYTES_SIZE].copy_from_slice(&compress_point_bip340(R));
    sig[X_ONLY_POINT_BYTES_SIZE..].copy_from_slice(&s.to_bytes());
    sig
}

/// Combines the signers' public nonces.
///
/// Math: `R_j = sum_i R_{i,j}` for `j = 1, 2`.
pub fn aggr_pubnonces<'a>(
    iter: impl Iterator<Item = &'a PubNonce>,
) -> (ProjectivePoint, ProjectivePoint) {
    let mut R1 = ProjectivePoint::IDENTITY;
    let mut R2 = ProjectivePoint::IDENTITY;
    iter.for_each(|pubnonce| {
        R1 += pubnonce.R1;
        R2 += pubnonce.R2;
    });

    (R1, R2)
}
