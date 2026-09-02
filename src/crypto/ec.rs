#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::tags::TAG_TAP_TWEAK;
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::{ChillDkgError, Result};
use k256::elliptic_curve::ops::{LinearCombinationExt, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const X_ONLY_POINT_BYTES_SIZE: usize = 32;
pub const COMPRESSED_POINT_BYTES_SIZE: usize = 33;
/// Scalar field size in bytes (F_r)
pub const EC_SCALAR_BYTES_SIZE: usize = 32;
pub type BIP340XOnlyPubKey = [u8; X_ONLY_POINT_BYTES_SIZE];
pub type CompressedPubKey = [u8; COMPRESSED_POINT_BYTES_SIZE];
pub type ScalarBytes = [u8; EC_SCALAR_BYTES_SIZE];

/// parse_scalar_from_bytes parses 32-byte array into Scalar.
/// Note: Only for public scalars.
/// Note: It does not reduce by field modulus.
pub fn parse_scalar_from_bytes(x: [u8; EC_SCALAR_BYTES_SIZE]) -> Result<Scalar> {
    let res = Option::<Scalar>::from(Scalar::from_repr(x.into())).ok_or_else(|| {
        ChillDkgError::Runtime("failed to convert 32 byte array into field element".into())
    })?;

    Ok(res)
}

/// parse_secret_scalar_from_bytes parses 32-byte array into Scalar.
/// Compared to parse_scalar_from_bytes it accepts Zeroizing<[u8; EC_SCALAR_BYTES_SIZE]>
/// to make sure that the secret value will be carefully filled with zeros on drop.
/// Note: It does not reduce by field modulus.
/// TODO: Unfortunately, i haven't found a way to get rid of passing x by value to Scalar::from_repr
pub fn parse_secret_scalar_from_bytes(x: Zeroizing<[u8; EC_SCALAR_BYTES_SIZE]>) -> Result<Scalar> {
    let res = Option::<Scalar>::from(Scalar::from_repr((*x).into())).ok_or_else(|| {
        ChillDkgError::Runtime("failed to convert 32 byte array into field element".into())
    })?;

    Ok(res)
}

/// reduce_secret_scalar_from_bytes parses 32-byte array into Scalar, applying mod n operation,
/// where n is the field order.
pub fn reduce_secret_scalar_from_bytes(x: Zeroizing<[u8; EC_SCALAR_BYTES_SIZE]>) -> SecretScalar {
    Zeroizing::new(<Scalar as Reduce<U256>>::reduce_bytes(x.as_slice().into()))
}

pub fn tap_tweak_no_script(p: &ProjectivePoint) -> Result<(ProjectivePoint, Scalar)> {
    chill_dkg_ensure!(
        !bool::from(p.is_identity()),
        ChillDkgError::Runtime("cannot tap tweak identity point".into()),
    );

    let tweak = parse_scalar_from_bytes(tagged_hash(TAG_TAP_TWEAK, compress_default(p)))?;
    Ok((ProjectivePoint::GENERATOR * tweak, tweak))
}

/// Serializes x * G as x-only point and returns normalizes scalar as well.
pub fn compress_scalar_bip340(x: &Scalar) -> (BIP340XOnlyPubKey, SecretScalar) {
    let P = ProjectivePoint::GENERATOR * x;
    let P_x = compress_point_bip340(&P);

    // BIP340 key normalization.
    if bool::from(P.to_affine().y_is_odd()) {
        (P_x, Zeroizing::new(x.negate()))
    } else {
        (P_x, Zeroizing::new(*x))
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
/// Does not accept identity point.
pub fn decompress_default(bytes: &CompressedPubKey) -> Option<ProjectivePoint> {
    let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
    Some(ProjectivePoint::from(affine))
}

/// Default secp256k1 point compression. Outputs 33-byte compressed point.
/// Accepts infinity point.
pub fn compress_default(point: &ProjectivePoint) -> CompressedPubKey {
    let mut out = [0u8; COMPRESSED_POINT_BYTES_SIZE];
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() == COMPRESSED_POINT_BYTES_SIZE {
        out.copy_from_slice(bytes);
    }

    // identity stays all-zero, matching the reference's
    // to_bytes_compressed_with_infinity
    out
}

/// Having a list of aggregated commitments, calculate participant's public share
pub fn eval_pub_share(commitment: &[ProjectivePoint], idx: usize) -> ProjectivePoint {
    let x = Scalar::from((idx + 1) as u64);
    let mut x_power = Scalar::ONE;
    let mut points_and_scalars = Vec::with_capacity(commitment.len());

    for C_k in commitment {
        points_and_scalars.push((*C_k, x_power));
        x_power *= x;
    }

    ProjectivePoint::lincomb_ext(points_and_scalars.as_slice())
}

pub fn ecdh(P: &ProjectivePoint, s: &Scalar) -> Zeroizing<[u8; 32]> {
    let shared_point = Zeroizing::new(P * s);
    let affine_point = Zeroizing::new(shared_point.to_affine());
    let encoded_point = Zeroizing::new(affine_point.to_encoded_point(true));
    Zeroizing::new(Sha256::digest(encoded_point.as_bytes()).into())
}
