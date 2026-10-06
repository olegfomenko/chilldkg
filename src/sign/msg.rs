#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// Signer -> Coordinator, Round 1.
///
/// A signer's public nonce pair. Neither point may be the identity; a decoder
/// receiving nonces from the network must reject it (see
/// [`decompress_default`](crate::crypto::ec::decompress_default)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubNonce {
    /// Math: `R_1 = k_1 * G`.
    pub R1: ProjectivePoint,
    /// Math: `R_2 = k_2 * G`.
    pub R2: ProjectivePoint,
}

impl PubNonce {
    pub(crate) fn is_identity(&self) -> bool {
        self.R1.is_identity().into() || self.R2.is_identity().into()
    }
}

/// Signer -> Coordinator, Round 2.
///
/// A signer's partial signature.
///
/// Math: `s_i`.
pub type PartialSignature = Scalar;
