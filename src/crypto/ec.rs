use anyhow::bail;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};

/// Serializes x * G as x-only point and returns normalizes scalar as well.
pub fn compress_point_bip340(x: Scalar) -> anyhow::Result<([u8; 32], Scalar)> {
    if bool::from(x.is_zero()) {
        bail!("BIP340: can't compress for zero scalar");
    }

    let p = ProjectivePoint::GENERATOR * x;
    let p_x: [u8; 32] = p.to_affine().x().into();

    // BIP340 key normalization.
    if bool::from(p.to_affine().y_is_odd()) {
        Ok((p_x, -x))
    } else {
        Ok((p_x, x))
    }
}

/// Deserializes BIP340 x-only point
pub fn decompress_point_bip340(x: &[u8; 32]) -> Option<ProjectivePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // BIP340 x-only points always mean the even-Y point.
    compressed[1..].copy_from_slice(x);

    let encoded = k256::EncodedPoint::from_bytes(compressed).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

    Some(ProjectivePoint::from(affine))
}

/// Default secp256k1 point compression. Outputs 33-byte compressed point.
pub fn compress_default(point: &ProjectivePoint) -> [u8; 33] {
    let encoded = point.to_affine().to_encoded_point(true);

    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}
