#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::curve::{
    ByteArray, Curve, CurvePoint, CurveScalar, Hash, ScalarBytes, XOnlyBytes,
};
use crate::crypto::tags::TAG_TAP_TWEAK;
use crate::crypto::{SecretScalar, hash, tagged_hash};
use crate::errors::{ChillDkgError, Result};
use zeroize::Zeroizing;

/// parse_scalar_from_bytes parses the canonical encoding of a scalar.
/// Note: It does not reduce by field modulus.
pub fn parse_scalar_from_bytes<C: Curve>(x: &ScalarBytes<C>) -> Result<C::Scalar> {
    C::Scalar::from_bytes(x).ok_or_else(|| {
        ChillDkgError::RuntimeError("failed to convert byte array into field element".to_owned())
    })
}

/// parse_scalar_from_hash reinterprets a hash output as the canonical encoding of a
/// scalar. The intermediate encoding is kept in Zeroizing, so that secret hashes, such
/// as VSS coefficients or encryption nonces, are wiped on drop.
/// Note: It does not reduce by field modulus, hence it requires the hash output and
/// the scalar encoding to be of the same size.
pub fn parse_scalar_from_hash<C: Curve>(x: &Hash<C>) -> Result<C::Scalar> {
    let bytes = Zeroizing::new(ScalarBytes::<C>::from_slice(x.as_ref()).ok_or_else(|| {
        ChillDkgError::RuntimeError(
            "hash output size does not match the scalar encoding size".to_owned(),
        )
    })?);

    parse_scalar_from_bytes::<C>(&bytes)
}

/// reduce_scalar_from_hash parses a hash output into a scalar, applying mod n
/// operation, where n is the group order.
pub fn reduce_scalar_from_hash<C: Curve>(x: &Hash<C>) -> SecretScalar<C> {
    Zeroizing::new(C::hash_to_scalar(x))
}

pub fn tap_tweak_no_script<C: Curve>(p: &C::Point) -> Result<(C::Point, C::Scalar)> {
    chill_dkg_ensure!(
        !p.is_identity(),
        ChillDkgError::RuntimeError("cannot tap tweak identity point".to_owned()),
    );

    let tweak = parse_scalar_from_hash::<C>(&tagged_hash::<C>(TAG_TAP_TWEAK, p.to_bytes()))?;

    Ok((C::Point::GENERATOR * tweak, tweak))
}

/// Serializes x * G as x-only point and returns normalized scalar as well.
pub fn compress_scalar_bip340<C: Curve>(x: &C::Scalar) -> (XOnlyBytes<C>, SecretScalar<C>) {
    let P = C::Point::GENERATOR * *x;
    let P_x = P.to_x_only_bytes();

    // BIP340 key normalization.
    if P.has_odd_y() {
        (P_x, Zeroizing::new(-*x))
    } else {
        (P_x, Zeroizing::new(*x))
    }
}

/// Forces point to be even-y
pub fn even_y_point<C: Curve>(point: &C::Point) -> C::Point {
    if point.is_identity() {
        C::Point::IDENTITY
    } else if point.has_odd_y() {
        -*point
    } else {
        *point
    }
}

/// Having a list of aggregated commitments, calculate participant's public share
pub fn eval_pub_share<C: Curve>(commitment: &[C::Point], idx: usize) -> C::Point {
    let x = C::Scalar::from_u64((idx + 1) as u64);
    let mut x_power = C::Scalar::ONE;
    let mut points_and_scalars = Vec::with_capacity(commitment.len());

    for C_k in commitment {
        points_and_scalars.push((*C_k, x_power));
        x_power *= x;
    }

    C::Point::lincomb(points_and_scalars.as_slice())
}

pub fn ecdh<C: Curve>(P: &C::Point, s: &C::Scalar) -> Zeroizing<Hash<C>> {
    let shared_point = Zeroizing::new(*P * *s);
    let encoded_point = Zeroizing::new(shared_point.to_bytes());

    Zeroizing::new(hash::<C>(encoded_point.as_ref()))
}
