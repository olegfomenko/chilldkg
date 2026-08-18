#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    BIP340XOnlyPubKey, EC_SCALAR_BYTES_SIZE, ScalarBytes, X_ONLY_POINT_BYTES_SIZE,
    compress_scalar_bip340, reduce_secret_scalar_from_bytes,
};
pub use crate::crypto::schnorr::SchnorrSignature;
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::{ChillDkgError, Result};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Generates Proof of Possession (a Schnorr signature):
/// 1. Prepare values:
///    aux_rand = H("BIP DKG/simplpedpop aux", seed)
///
///    d = BIP340-normalize(a0)
///    P_x = xonly(a0 * G)
///
///    t = bytes(d) xor H("BIP DKG/pop message/aux", aux_rand)
///
/// 2. Generate nonce
///    k0 = H("BIP DKG/pop message/nonce", t || P_x || uint32_be(m)) mod n
///    k = BIP340-normalize(k0)
///
/// 3. Put public nonce
///    R_x = xonly(k0 * G)
///
/// 4. Put challenge
///    e = H("BIP DKG/pop message/challenge", R_x || P_x || uint32_be(m)) mod n
///
/// 5. Put response
///    s = k + e*d mod n
///
/// 6. Serialize result into 64 byte array
///    pop = R_x || bytes(s)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PopSigner {
    a0: Scalar,
    seed: [u8; 32],
    message: [u8; 4],
}

impl PopSigner {
    pub fn new(a0: &Scalar, seed: &[u8; 32], m: u32) -> Self {
        PopSigner {
            a0: *a0,
            seed: *seed,
            message: m.to_be_bytes(),
        }
    }
}

impl SchnorrSigner for PopSigner {
    fn message(&self) -> &[u8] {
        &self.message
    }

    fn secret_key(&self) -> SecretScalar {
        Zeroizing::new(self.a0)
    }

    fn x_only_nonce(&self) -> Result<(BIP340XOnlyPubKey, SecretScalar)> {
        let aux_rand = tagged_hash(TAG_SIMPLPEDPOP_AUX, self.seed.as_slice());
        let aux_hash = tagged_hash(TAG_POP_AUX, aux_rand.as_slice());
        let (P_x, d) = self.x_only_key();
        let mut t: Zeroizing<[u8; EC_SCALAR_BYTES_SIZE]> =
            Zeroizing::new(ScalarBytes::from(d.to_bytes()));
        for i in 0..EC_SCALAR_BYTES_SIZE {
            t[i] ^= aux_hash[i];
        }

        let mut nonce_preimage = Zeroizing::new(Vec::with_capacity(
            EC_SCALAR_BYTES_SIZE + X_ONLY_POINT_BYTES_SIZE + 4,
        ));
        nonce_preimage.extend_from_slice(t.as_slice());
        nonce_preimage.extend_from_slice(&P_x);
        nonce_preimage.extend_from_slice(self.message());

        let preimage_bytes = Zeroizing::new(tagged_hash(TAG_POP_NONCE, &nonce_preimage));
        let k = reduce_secret_scalar_from_bytes(preimage_bytes);

        chill_dkg_ensure!(
            !bool::from(k.is_zero()),
            ChillDkgError::RuntimeError("PoP generation failed: BIP340: nonce is zero".to_owned()),
        );

        Ok(compress_scalar_bip340(&k))
    }
    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_pop_challenge(R, P, self.message())
    }
}

/// Verifies ChillDKG Proof of Possession (a Schnorr signature).
///
/// Checks:
///    pop = R_x || s
///    e = H("BIP DKG/pop message/challenge", R_x || Com_x || uint32_be(m)) mod n
///    R = s*G - e*Com
///    accept iff R != infinity, has_even_y(R), and xonly(R) == R_x
pub struct PopVerifier {
    com: ProjectivePoint,
    message: [u8; 4],
}

impl PopVerifier {
    pub fn new(com: ProjectivePoint, m: u32) -> Self {
        PopVerifier {
            com,
            message: m.to_be_bytes(),
        }
    }
}

impl SchnorrVerifier for PopVerifier {
    fn message(&self) -> &[u8] {
        &self.message
    }

    fn pub_key(&self) -> ProjectivePoint {
        self.com
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_pop_challenge(R, P, self.message())
    }
}

fn get_pop_challenge(
    R: &BIP340XOnlyPubKey,
    P: &BIP340XOnlyPubKey,
    message: &[u8],
) -> Result<Scalar> {
    let mut challenge_preimage = Vec::with_capacity(X_ONLY_POINT_BYTES_SIZE * 2 + 4);
    challenge_preimage.extend_from_slice(R);
    challenge_preimage.extend_from_slice(P);
    challenge_preimage.extend_from_slice(message);

    Ok(Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_POP_CHALLENGE,
        challenge_preimage,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn sign_pop(seed: &[u8; 32], a0: &Scalar, idx: u32) -> SchnorrSignature {
        PopSigner::new(a0, seed, idx).sign().unwrap()
    }

    #[test]
    fn generated_pop_verifies_for_matching_key_and_index() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let idx = 3;
        let pop = sign_pop(&seed, &a0, idx);

        PopVerifier::new(ProjectivePoint::GENERATOR * a0, idx)
            .verify(pop)
            .unwrap();
    }

    #[test]
    fn generated_pop_is_deterministic_for_same_inputs() {
        let seed = Zeroizing::new([9u8; 32]);
        let a0 = scalar(123);
        let idx = 1;

        assert_eq!(sign_pop(&seed, &a0, idx), sign_pop(&seed, &a0, idx));
    }

    #[test]
    fn generated_pop_changes_with_seed() {
        let a0 = scalar(42);
        let idx = 3;

        assert_ne!(
            sign_pop(&[1u8; 32], &a0, idx),
            sign_pop(&[2u8; 32], &a0, idx)
        );
    }

    #[test]
    fn verification_rejects_wrong_index() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let pop = sign_pop(&seed, &a0, 3);

        assert!(
            PopVerifier::new(ProjectivePoint::GENERATOR * a0, 4)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_wrong_pubkey() {
        let seed = Zeroizing::new([7u8; 32]);
        let pop = sign_pop(&seed, &scalar(42), 3);
        let wrong_pubkey = ProjectivePoint::GENERATOR * scalar(43);

        assert!(PopVerifier::new(wrong_pubkey, 3).verify(pop).is_err());
    }

    #[test]
    fn verification_rejects_identity_pubkey() {
        let seed = Zeroizing::new([7u8; 32]);
        let pop = sign_pop(&seed, &scalar(42), 3);

        assert!(
            PopVerifier::new(ProjectivePoint::IDENTITY, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_tampered_public_nonce() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let mut pop = sign_pop(&seed, &a0.clone(), 3);

        pop[0] ^= 1;

        assert!(
            PopVerifier::new(ProjectivePoint::GENERATOR * a0, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_tampered_response() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let mut pop = sign_pop(&seed, &a0, 3);

        pop[63] ^= 1;

        assert!(
            PopVerifier::new(ProjectivePoint::GENERATOR * a0, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn signing_rejects_zero_secret() {
        let seed = Zeroizing::new([7u8; 32]);

        assert!(PopSigner::new(&Scalar::ZERO, &seed, 0).sign().is_err());
    }
}
