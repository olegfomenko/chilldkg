//! BIP340-compatible key tweaking with accumulated negation.
//!
//! A [`TweakContext`] tracks a public key `Q` together with two accumulators:
//! `gacc`, the product of the sign flips applied so far, and `tacc`, the net
//! scalar tweak. Together they let a signer adjust its secret share and let the
//! aggregator adjust the final signature so the result verifies under the
//! tweaked, x-only key. This is the tweaking scheme of BIP327 (MuSig2), reused
//! unchanged by BIP445 (FROST signing).

#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    BIP340XOnlyPubKey, CompressedPubKey, ScalarBytes, compress_default, compress_point_bip340,
    has_even_y, parse_scalar_from_bytes,
};
use crate::errors::{ChillDkgError, Result};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// A single tweak to apply to a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tweak {
    /// 32-byte tweak value, interpreted as a scalar; must be below the group order.
    pub value: ScalarBytes,
    /// `true` for an x-only (BIP340/BIP341) tweak, `false` for a plain (BIP32) one.
    pub is_xonly: bool,
}

impl Tweak {
    pub fn plain(value: ScalarBytes) -> Self {
        Self {
            value,
            is_xonly: false,
        }
    }

    pub fn xonly(value: ScalarBytes) -> Self {
        Self {
            value,
            is_xonly: true,
        }
    }
}

/// A public key with the tweaks applied to it so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TweakContext {
    /// The (tweaked) public key.
    ///
    /// Math: `Q`.
    pub q: ProjectivePoint,

    /// Accumulated sign flip.
    ///
    /// Math: `gacc`, the product of every `g` applied by [`TweakContext::apply`].
    pub gacc: Scalar,

    /// Accumulated tweak.
    ///
    /// Math: `tacc`.
    pub tacc: Scalar,
}

impl TweakContext {
    /// Starts from an untweaked public key.
    ///
    /// The caller must ensure `q` is not the identity point.
    pub fn new(q: ProjectivePoint) -> Self {
        Self {
            q,
            gacc: Scalar::ONE,
            tacc: Scalar::ZERO,
        }
    }

    /// Applies a 32-byte tweak, x-only (BIP340/BIP341 style) or plain.
    ///
    /// Math: `g = -1` if `is_xonly` and `Q` has an odd `y`, else `1`;
    /// `Q' = g * Q + tweak * G`, `gacc' = g * gacc`, `tacc' = tweak + g * tacc`.
    pub fn apply(&self, tweak: &Tweak) -> Result<Self> {
        let g = if tweak.is_xonly && !has_even_y(&self.q) {
            -Scalar::ONE
        } else {
            Scalar::ONE
        };

        let twk = parse_scalar_from_bytes(tweak.value)
            .map_err(|_| ChillDkgError::Value("The tweak value is out of range.".into()))?;

        let q = self.q * g + ProjectivePoint::GENERATOR * twk;
        chill_dkg_ensure!(
            !bool::from(q.is_identity()),
            ChillDkgError::Value("The result of tweaking cannot be infinity.".into()),
        );

        Ok(Self {
            q,
            gacc: g * self.gacc,
            tacc: twk + g * self.tacc,
        })
    }

    /// Applies a sequence of tweaks in order.
    pub fn apply_all(&self, tweaks: &[Tweak]) -> Result<Self> {
        tweaks
            .iter()
            .try_fold(self.clone(), |ctx, tweak| ctx.apply(tweak))
    }

    /// The tweaked key in BIP340 x-only encoding.
    pub fn xonly_pubkey(&self) -> BIP340XOnlyPubKey {
        compress_point_bip340(&self.q)
    }

    /// The tweaked key in 33-byte compressed encoding.
    #[expect(dead_code)]
    pub fn compressed_pubkey(&self) -> CompressedPubKey {
        compress_default(&self.q)
    }

    pub(crate) fn g(&self) -> Scalar {
        if has_even_y(&self.q) {
            Scalar::ONE
        } else {
            -Scalar::ONE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_tweak_shifts_key_by_tweak_times_generator() {
        let q = ProjectivePoint::GENERATOR * Scalar::from(5u64);
        let tweak = ScalarBytes::from(Scalar::from(3u64).to_bytes());

        let ctx = TweakContext::new(q).apply(&Tweak::plain(tweak)).unwrap();

        assert_eq!(ctx.q, ProjectivePoint::GENERATOR * Scalar::from(8u64));
        assert_eq!(ctx.gacc, Scalar::ONE);
        assert_eq!(ctx.tacc, Scalar::from(3u64));
    }

    #[test]
    fn xonly_tweak_negates_odd_key_first() {
        // Find a key with odd y so the x-only branch flips it.
        let mut k = 1u64;
        let q = loop {
            let q = ProjectivePoint::GENERATOR * Scalar::from(k);
            if !has_even_y(&q) {
                break q;
            }
            k += 1;
        };
        let tweak = ScalarBytes::from(Scalar::from(2u64).to_bytes());

        let ctx = TweakContext::new(q).apply(&Tweak::xonly(tweak)).unwrap();

        assert_eq!(ctx.q, -q + ProjectivePoint::GENERATOR * Scalar::from(2u64));
        assert_eq!(ctx.gacc, -Scalar::ONE);
        assert_eq!(ctx.tacc, Scalar::from(2u64));
    }

    #[test]
    fn rejects_out_of_range_tweak_and_infinity_result() {
        let q = ProjectivePoint::GENERATOR * Scalar::from(5u64);
        assert!(
            TweakContext::new(q)
                .apply(&Tweak::plain([0xFF; 32]))
                .is_err()
        );

        // tweak = -5 drives 5*G to infinity.
        let cancel = ScalarBytes::from((-Scalar::from(5u64)).to_bytes());
        assert!(TweakContext::new(q).apply(&Tweak::plain(cancel)).is_err());
    }
}
