//! This module provides the definition of the [`Curve`] trait.
//!
//! The protocol code never names a concrete curve type: it is written against
//! [`Curve::Point`], [`Curve::Scalar`] and the operations declared by
//! [`CurvePoint`] and [`CurveScalar`]. Supporting another curve is therefore a
//! matter of implementing these traits for its types, the way
//! [`crate::crypto::secp256k1`] does for secp256k1.

#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use core::fmt::Debug;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use rand_core::CryptoRngCore;
use sha2::Digest;
use sha2::digest::Output;
use std::ops::SubAssign;
use zeroize::Zeroize;

/// A fixed-size byte encoding of a curve element.
///
/// Blanket-implemented for every suitable type, so implementors of [`Curve`]
/// pick plain arrays (`[u8; 32]`, `[u8; 33]`, ...) as their encodings.
pub trait ByteArray:
    AsRef<[u8]> + AsMut<[u8]> + Copy + Debug + Eq + Zeroize + for<'a> TryFrom<&'a [u8]>
{
    /// Copies the encoding out of `bytes`, returning `None` on a length mismatch.
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl<T> ByteArray for T where
    T: AsRef<[u8]> + AsMut<[u8]> + Copy + Debug + Eq + Zeroize + for<'a> TryFrom<&'a [u8]>
{
}

/// An element of the scalar field of the curve.
pub trait CurveScalar:
    Sized
    + Copy
    + Debug
    + Eq
    + Zeroize
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + Mul<Output = Self>
    + MulAssign
    + Neg<Output = Self>
    + Sum
    + for<'a> Sum<&'a Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
    /// Canonical byte encoding of a scalar.
    type Bytes: ByteArray;

    /// Size of [`Self::Bytes`].
    const BYTES_SIZE: usize;

    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;

    /// Lifts a small integer into the scalar field.
    fn from_u64(value: u64) -> Self;

    /// Samples a uniformly random scalar which is guaranteed to be non-zero.
    fn random_non_zero(rng: &mut impl CryptoRngCore) -> Self;

    /// Serializes the scalar into its canonical encoding.
    fn to_bytes(&self) -> Self::Bytes;

    /// Parses a canonically encoded scalar.
    ///
    /// Note: it does not reduce by the group order, so encodings of values
    /// greater than or equal to it are rejected.
    fn from_bytes(bytes: &Self::Bytes) -> Option<Self>;

    /// Returns whether this is the zero scalar.
    fn is_zero(&self) -> bool;
}

/// A point of the curve group.
pub trait CurvePoint:
    Sized
    + Copy
    + Debug
    + Eq
    + Zeroize
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + Neg<Output = Self>
    + Mul<Self::Scalar, Output = Self>
    + Sum
    + for<'a> Sum<&'a Self>
    + for<'a> Mul<&'a Self::Scalar, Output = Self>
{
    /// The scalar field the group is defined over.
    type Scalar: CurveScalar;

    /// Compressed byte encoding of a point.
    type Bytes: ByteArray;

    /// Byte encoding of a point without its Y coordinate, as signed over by BIP340.
    type XOnlyBytes: ByteArray;

    /// Size of [`Self::Bytes`].
    const BYTES_SIZE: usize;

    /// Size of [`Self::XOnlyBytes`].
    const X_ONLY_BYTES_SIZE: usize;

    /// The group generator.
    ///
    /// Math: `G`.
    const GENERATOR: Self;

    /// The neutral element of the group.
    const IDENTITY: Self;

    /// Returns whether this is the neutral element of the group.
    fn is_identity(&self) -> bool;

    /// Returns whether the Y coordinate of the point is odd.
    fn has_odd_y(&self) -> bool;

    /// Serializes the point into its compressed encoding.
    fn to_bytes(&self) -> Self::Bytes;

    /// Parses a compressed point encoding.
    fn from_bytes(bytes: &Self::Bytes) -> Option<Self>;

    /// Serializes the point dropping its Y coordinate.
    fn to_x_only_bytes(&self) -> Self::XOnlyBytes;

    /// Multi-scalar multiplication.
    ///
    /// Math: `sum_i P_i * x_i` for `(P_i, x_i)` in `points_and_scalars`.
    ///
    /// The default implementation is a plain sum of single multiplications;
    /// curves backed by an MSM implementation should override it.
    fn lincomb(points_and_scalars: &[(Self, Self::Scalar)]) -> Self {
        points_and_scalars.iter().map(|(P, x)| *P * x).sum()
    }
}

/// A type which defines the components and operations of the curve
/// to make the library generic over it.
pub trait Curve: Copy + Debug + Eq {
    /// The scalar type of the curve;
    type Scalar: CurveScalar;

    /// The point type of the curve;
    type Point: CurvePoint<Scalar = Self::Scalar>;

    /// The hasher of the curve;
    type Hasher: Digest;

    /// Byte encoding of [`Self::Hasher`] output.
    type Hash: ByteArray + From<Output<Self::Hasher>>;

    /// Reduces a hash output into a scalar modulo the group order.
    fn hash_to_scalar(hash: &Self::Hash) -> Self::Scalar;
}

/// Canonical encoding of a scalar of the curve `C`.
pub type ScalarBytes<C> = <<C as Curve>::Scalar as CurveScalar>::Bytes;

/// Compressed encoding of a point of the curve `C`.
pub type PointBytes<C> = <<C as Curve>::Point as CurvePoint>::Bytes;

/// X-only (BIP340) encoding of a point of the curve `C`.
pub type XOnlyBytes<C> = <<C as Curve>::Point as CurvePoint>::XOnlyBytes;

/// Output of the hasher of the curve `C`.
pub type Hash<C> = <C as Curve>::Hash;
