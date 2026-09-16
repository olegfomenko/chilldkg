#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    COMPRESSED_POINT_BYTES_SIZE, X_ONLY_POINT_BYTES_SIZE, compress_default, compress_point_bip340,
    has_even_y, reduce_secret_scalar_from_bytes,
};
use crate::crypto::tags::{TAG_FROST_AUX, TAG_FROST_NONCE};
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::{ChillDkgError, Result};
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A signer's secret nonce pair.
///
/// Deliberately neither `Clone` nor `Copy`: [`Signer::sign`](super::Signer::sign)
/// consumes it, so a nonce cannot be used for two signatures. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecNonce {
    /// Math: `k_1`.
    pub k1: Scalar,
    /// Math: `k_2`.
    pub k2: Scalar,
}

impl SecNonce {
    /// Math: `(k_1 * G, k_2 * G)`.
    pub fn pubnonce(&self) -> PubNonce {
        PubNonce {
            R1: ProjectivePoint::GENERATOR * self.k1,
            R2: ProjectivePoint::GENERATOR * self.k2,
        }
    }

    /// The nonce to sign with once the final nonce `R` is known: negated if
    /// `R` has an odd `y`, so that the signature's `R` is even as BIP340
    /// requires.
    ///
    /// Math: `k_j' = k_j` if `R` has even `y`, else `-k_j`.
    pub(crate) fn even_y_nonce(&self, R: &ProjectivePoint) -> SecNonce {
        if has_even_y(R) {
            SecNonce {
                k1: self.k1,
                k2: self.k2,
            }
        } else {
            SecNonce {
                k1: self.k1.negate(),
                k2: self.k2.negate(),
            }
        }
    }
}

/// A signer's public nonce pair.
///
/// Neither point may be the identity; a decoder receiving nonces from the
/// network must reject it (see [`decompress_default`](crate::crypto::ec::decompress_default)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubNonce {
    /// Math: `R_1 = k_1 * G`.
    pub R1: ProjectivePoint,
    /// Math: `R_2 = k_2 * G`.
    pub R2: ProjectivePoint,
}

/// Helper to find a PubNonce for specific id
pub(crate) fn get_pub_nonce<'a>(
    mut iter: impl Iterator<Item = (usize, &'a PubNonce)>,
    id: usize,
) -> Option<&'a PubNonce> {
    iter.find(|(i, _)| *i == id).map(|(_, pubnonce)| pubnonce)
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

/// Generates a fresh nonce pair for one signing session.
///
/// All inputs are optional but strongly recommended: mixing the secret share
/// into the randomness protects against a weak RNG, and binding the nonce to
/// the public share, the (tweaked) threshold key, the message and any extra
/// input protects against some misuse. `secshare`, when given, must be the
/// signer's DKG secret share; `pubshare` its public share and `thresh_pk` the
/// (tweaked) threshold key the session will sign under.
pub fn sample_nonce(
    rng: &mut impl CryptoRngCore,
    secshare: Option<&Scalar>,
    pubshare: Option<&ProjectivePoint>,
    thresh_pk: Option<&ProjectivePoint>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
) -> Result<(PubNonce, SecNonce)> {
    let mut rand_ = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(rand_.as_mut());
    sample_nonce_internal(rand_, secshare, pubshare, thresh_pk, msg, extra_in)
}

fn sample_nonce_internal(
    rand_: Zeroizing<[u8; 32]>,
    secshare: Option<&Scalar>,
    pubshare: Option<&ProjectivePoint>,
    thresh_pk: Option<&ProjectivePoint>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
) -> Result<(PubNonce, SecNonce)> {
    // If secshare is provided - xor with current randomness
    let rand = match secshare {
        Some(secshare) => {
            let mut rand = Zeroizing::new(tagged_hash(TAG_FROST_AUX, rand_.as_ref()));
            let secshare_bytes = Zeroizing::new(secshare.to_bytes());
            for (r, s) in rand.iter_mut().zip(secshare_bytes.iter()) {
                *r ^= s;
            }
            rand
        }
        None => rand_,
    };

    let k1 = nonce_hash(&rand, pubshare, thresh_pk, msg, extra_in, 0)?;
    let k2 = nonce_hash(&rand, pubshare, thresh_pk, msg, extra_in, 1)?;

    // k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    chill_dkg_ensure!(
        !bool::from(k1.is_zero()) && !bool::from(k2.is_zero()),
        ChillDkgError::Runtime("generated nonce is zero".into()),
    );

    let secnonce = SecNonce { k1: *k1, k2: *k2 };
    Ok((secnonce.pubnonce(), secnonce))
}

/// Math: `H_nonce(rand || len1(pubshare) || pubshare || len1(thresh_pk) || thresh_pk
///                 || msg_prefixed || len4(extra_in) || extra_in || i)`,
/// where `msg_prefixed = 0x00` if there is no message, else `0x01 || len8(msg) || msg`.
///
/// Absent optional inputs are hashed as empty byte strings (their length
/// prefix is still present); the message additionally carries a presence flag
/// so "no message" and "empty message" differ.
fn nonce_hash(
    rand: &[u8; 32],
    pubshare: Option<&ProjectivePoint>,
    thresh_pk: Option<&ProjectivePoint>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
    i: u8,
) -> Result<SecretScalar> {
    let tag_hash = Sha256::digest(TAG_FROST_NONCE);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);

    hash.update(rand);

    match pubshare {
        Some(p) => {
            hash.update([COMPRESSED_POINT_BYTES_SIZE as u8]);
            hash.update(compress_default(p));
        }
        None => hash.update([0u8]),
    }

    match thresh_pk {
        Some(p) => {
            hash.update([X_ONLY_POINT_BYTES_SIZE as u8]);
            hash.update(compress_point_bip340(p));
        }
        None => hash.update([0u8]),
    }

    match msg {
        Some(msg) => {
            hash.update([1u8]);
            hash.update((msg.len() as u64).to_be_bytes());
            hash.update(msg);
        }
        None => hash.update([0u8]),
    }

    match extra_in {
        Some(extra_in) => {
            chill_dkg_ensure!(
                u32::try_from(extra_in.len()).is_ok(),
                ChillDkgError::Value("The extra input must be shorter than 2^32 bytes.".into()),
            );
            hash.update((extra_in.len() as u32).to_be_bytes());
            hash.update(extra_in);
        }
        // Absent extra input is the empty string, whose 4-byte length is still hashed.
        None => hash.update(0u32.to_be_bytes()),
    }

    hash.update([i]);

    Ok(reduce_secret_scalar_from_bytes(Zeroizing::new(
        hash.finalize().into(),
    )))
}
