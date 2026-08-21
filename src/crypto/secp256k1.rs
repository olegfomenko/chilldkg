//! secp256k1 instantiation of the [`Curve`] trait, backed by [`k256`].

use k256::elliptic_curve::ops::{LinearCombinationExt, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, EncodedPoint, NonZeroScalar, ProjectivePoint, Scalar, U256};
use rand_core::CryptoRngCore;
use sha2::Sha256;

use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};

/// Scalar field size in bytes (F_r).
pub const EC_SCALAR_BYTES_SIZE: usize = 32;
/// Size of a SEC1 compressed point.
pub const COMPRESSED_POINT_BYTES_SIZE: usize = 33;
/// Size of a BIP340 x-only point.
pub const X_ONLY_POINT_BYTES_SIZE: usize = 32;
/// Size of a SHA256 digest.
pub const HASH_BYTES_SIZE: usize = 32;

/// The secp256k1 curve, as used by BIP-FROST-DKG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secp256k1;

impl Curve for Secp256k1 {
    type Scalar = Scalar;
    type Point = ProjectivePoint;
    type Hasher = Sha256;
    type Hash = [u8; HASH_BYTES_SIZE];

    fn hash_to_scalar(hash: &Self::Hash) -> Self::Scalar {
        Scalar::reduce(U256::from_be_slice(hash))
    }
}

impl CurveScalar for Scalar {
    type Bytes = [u8; EC_SCALAR_BYTES_SIZE];

    const BYTES_SIZE: usize = EC_SCALAR_BYTES_SIZE;
    const ZERO: Self = Scalar::ZERO;
    const ONE: Self = Scalar::ONE;

    fn from_u64(value: u64) -> Self {
        Scalar::from(value)
    }

    fn random_non_zero(rng: &mut impl CryptoRngCore) -> Self {
        *NonZeroScalar::random(rng).as_ref()
    }

    fn to_bytes(&self) -> Self::Bytes {
        Scalar::to_bytes(self).into()
    }

    fn from_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Option::from(Scalar::from_repr((*bytes).into()))
    }

    fn is_zero(&self) -> bool {
        bool::from(Scalar::is_zero(self))
    }
}

impl CurvePoint for ProjectivePoint {
    type Scalar = Scalar;
    type Bytes = [u8; COMPRESSED_POINT_BYTES_SIZE];
    type XOnlyBytes = [u8; X_ONLY_POINT_BYTES_SIZE];

    const BYTES_SIZE: usize = COMPRESSED_POINT_BYTES_SIZE;
    const X_ONLY_BYTES_SIZE: usize = X_ONLY_POINT_BYTES_SIZE;
    const GENERATOR: Self = ProjectivePoint::GENERATOR;
    const IDENTITY: Self = ProjectivePoint::IDENTITY;

    fn is_identity(&self) -> bool {
        bool::from(Group::is_identity(self))
    }

    fn has_odd_y(&self) -> bool {
        bool::from(self.to_affine().y_is_odd())
    }

    fn to_bytes(&self) -> Self::Bytes {
        let encoded = self.to_affine().to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_POINT_BYTES_SIZE];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn from_bytes(bytes: &Self::Bytes) -> Option<Self> {
        let encoded = EncodedPoint::from_bytes(bytes).ok()?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

        Some(ProjectivePoint::from(affine))
    }

    fn to_x_only_bytes(&self) -> Self::XOnlyBytes {
        self.to_affine().x().into()
    }

    fn lincomb(points_and_scalars: &[(Self, Self::Scalar)]) -> Self {
        ProjectivePoint::lincomb_ext(points_and_scalars)
    }
}
