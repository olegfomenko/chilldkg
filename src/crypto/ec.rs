#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::tags::TAG_TAP_TWEAK;
use crate::crypto::{scalar_from_bytes, tagged_hash};
use anyhow::{Result, ensure};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};

pub type BIP340XOnlyPubKey = [u8; 32];
pub type CompressedPubKey = [u8; 33];

pub fn tap_tweak_no_script(p: &ProjectivePoint) -> Result<(ProjectivePoint, Scalar)> {
    ensure!(
        !bool::from(p.is_identity()),
        "cannot tap tweak identity point"
    );
    let tweak = scalar_from_bytes(tagged_hash(TAG_TAP_TWEAK, compress_default(p)))?;
    Ok((ProjectivePoint::GENERATOR * tweak, tweak))
}

/// Serializes x * G as x-only point and returns normalizes scalar as well.
pub fn compress_scalar_bip340(x: &Scalar) -> (BIP340XOnlyPubKey, Scalar) {
    let p = ProjectivePoint::GENERATOR * x;
    let p_x = compress_point_bip340(&p);

    // BIP340 key normalization.
    if bool::from(p.to_affine().y_is_odd()) {
        (p_x, -x)
    } else {
        (p_x, *x)
    }
}

/// Serializes BIP340 x-only point
pub fn compress_point_bip340(point: &ProjectivePoint) -> BIP340XOnlyPubKey {
    point.to_affine().x().into()
}

/// Forces point to be even-y
pub fn even_y_point(point: &ProjectivePoint) -> ProjectivePoint {
    if bool::from(point.is_identity()) {
        ProjectivePoint::IDENTITY
    } else if bool::from(point.to_affine().y_is_odd()) {
        -point
    } else {
        *point
    }
}

/// Deserializes a compressed SEC1 secp256k1 point.
pub fn decompress_default(bytes: &CompressedPubKey) -> Option<ProjectivePoint> {
    let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

    Some(ProjectivePoint::from(affine))
}

/// Default secp256k1 point compression. Outputs 33-byte compressed point.
pub fn compress_default(point: &ProjectivePoint) -> CompressedPubKey {
    let encoded = point.to_affine().to_encoded_point(true);

    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Having a list of aggregated commitments, calculate participant's public share
pub fn eval_pub_share(commitment: &[ProjectivePoint], idx: usize) -> ProjectivePoint {
    let x = Scalar::from((idx + 1) as u64);
    let mut x_power = Scalar::ONE;
    let mut pubshare = ProjectivePoint::IDENTITY;

    for C_k in commitment {
        pubshare += *C_k * x_power;
        x_power *= x;
    }

    pubshare
}
