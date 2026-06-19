use crate::crypto::tagged_hash;
use crate::crypto::tags::TAG_TAP_TWEAK;
use k256::elliptic_curve::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

pub type BIP340XOnlyPubKey = [u8; 32];
pub type CompressedPubKey = [u8; 33];

pub fn tap_tweak_no_script(p: &ProjectivePoint) -> (ProjectivePoint, Scalar) {
    let tweak = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_TAP_TWEAK,
        &compress_default(&p).to_vec(),
    )));

    (ProjectivePoint::GENERATOR * tweak, tweak)
}

/// Serializes x * G as x-only point and returns normalizes scalar as well.
pub fn compress_scalar_bip340(x: &Scalar) -> (BIP340XOnlyPubKey, Scalar) {
    let p = ProjectivePoint::GENERATOR * x;
    let p_x = compress_point_bip340(&p);

    // BIP340 key normalization.
    if bool::from(p.to_affine().y_is_odd()) {
        (p_x, -x)
    } else {
        (p_x, x.clone())
    }
}

/// Serializes BIP340 x-only point
pub fn compress_point_bip340(point: &ProjectivePoint) -> BIP340XOnlyPubKey {
    if bool::from(point.is_identity()) {
        [0u8; 32]
    } else {
        point.to_affine().x().into()
    }
}

/// Deserializes BIP340 x-only point
pub fn decompress_point_bip340(x: &BIP340XOnlyPubKey) -> Option<ProjectivePoint> {
    if *x == [0u8; 32] {
        Some(ProjectivePoint::IDENTITY)
    } else {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02; // BIP340 x-only points always mean the even-Y point.
        compressed[1..].copy_from_slice(x);

        let encoded = k256::EncodedPoint::from_bytes(compressed).ok()?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

        Some(ProjectivePoint::from(affine))
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

/// Compressed secp256k1 point encoding used by the reference for VSS commitments.
///
/// Maps the identity point to 33 zero bytes.
pub fn compress_default_with_infinity(point: &ProjectivePoint) -> CompressedPubKey {
    if bool::from(point.is_identity()) {
        [0u8; 33]
    } else {
        compress_default(point)
    }
}
