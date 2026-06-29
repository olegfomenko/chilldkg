#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::ec::{BIP340XOnlyPubKey, compress_scalar_bip340};
pub use crate::crypto::schnorr::SchnorrSignature;
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use anyhow::{Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};

/// Generates Proof of Possession (a Schnorr signature):
/// 1. Prepare values:
/// aux_rand = H("BIP DKG/simplpedpop aux", seed)
///
/// d = BIP340-normalize(a0)
/// P_x = xonly(a0 * G)
///
/// t = bytes(d) xor H("BIP DKG/pop message/aux", aux_rand)
///
/// 2. Generate nonce
/// k0 = H("BIP DKG/pop message/nonce", t || P_x || uint32_be(m)) mod n
/// k = BIP340-normalize(k0)
///
/// 3. Put public nonce
/// R_x = xonly(k0 * G)
///
/// 4. Put challenge
/// e = H("BIP DKG/pop message/challenge", R_x || P_x || uint32_be(m)) mod n
///
/// 5. Put response
/// s = k + e*d mod n
///
/// 6. Serialize result into 64 byte array
/// pop = R_x || bytes(s)
pub struct PopSigner {
    a0: Scalar,
    seed: [u8; 32],
    message: [u8; 4],
}

impl PopSigner {
    pub fn new(a0: Scalar, seed: [u8; 32], m: u32) -> Self {
        PopSigner {
            a0,
            seed,
            message: m.to_be_bytes(),
        }
    }
}

impl SchnorrSigner for PopSigner {
    fn message(&self) -> &[u8] {
        &self.message
    }

    fn secret_key(&self) -> Scalar {
        self.a0
    }

    fn x_only_nonce(&self) -> Result<(BIP340XOnlyPubKey, Scalar)> {
        let aux_rand = tagged_hash(TAG_SIMPLPEDPOP_AUX, self.seed);
        let aux_hash = tagged_hash(TAG_POP_AUX, aux_rand);
        let (p_x, d) = self.x_only_key();
        let mut t: [u8; 32] = d.to_bytes().into();
        for i in 0..32 {
            t[i] ^= aux_hash[i];
        }

        let mut nonce_preimage = Vec::with_capacity(32 + 32 + 4);
        nonce_preimage.extend_from_slice(&t);
        nonce_preimage.extend_from_slice(&p_x);
        nonce_preimage.extend_from_slice(self.message());

        let k = Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_POP_NONCE,
            nonce_preimage,
        )));

        ensure!(
            !bool::from(k.is_zero()),
            "PoP generation failed: BIP340: nonce is zero"
        );

        Ok(compress_scalar_bip340(&k))
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        let mut challenge_preimage = Vec::with_capacity(32 + 32 + 4);
        challenge_preimage.extend_from_slice(R);
        challenge_preimage.extend_from_slice(P);
        challenge_preimage.extend_from_slice(&self.message);

        Ok(Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_POP_CHALLENGE,
            challenge_preimage,
        ))))
    }
}

/// Verifies ChillDKG Proof of Possession (a Schnorr signature).
///
/// Checks:
/// pop = R_x || s
/// e = H("BIP DKG/pop message/challenge", R_x || Com_x || uint32_be(m)) mod n
/// R = s*G - e*Com
/// accept iff R != infinity, has_even_y(R), and xonly(R) == R_x
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
        let mut challenge_preimage = Vec::with_capacity(32 + 32 + 4);
        challenge_preimage.extend_from_slice(R);
        challenge_preimage.extend_from_slice(P);
        challenge_preimage.extend_from_slice(&self.message);

        Ok(Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_POP_CHALLENGE,
            challenge_preimage,
        ))))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     fn scalar(value: u64) -> Scalar {
//         Scalar::from(value)
//     }
//
//     #[test]
//     fn generated_pop_verifies_for_matching_key_and_index() {
//         let seed = [7u8; 32];
//         let a0 = scalar(42);
//         let idx = 3;
//         let pop = chilldkg_pop_sign(&seed, a0, idx).unwrap();
//
//         chilldkg_pop_verify(&pop, &(ProjectivePoint::GENERATOR * a0), idx).unwrap();
//     }
//
//     #[test]
//     fn generated_pop_is_deterministic_for_same_inputs() {
//         let seed = [9u8; 32];
//         let a0 = scalar(123);
//         let idx = 1;
//
//         assert_eq!(
//             chilldkg_pop_sign(&seed, a0, idx).unwrap(),
//             chilldkg_pop_sign(&seed, a0, idx).unwrap()
//         );
//     }
//
//     #[test]
//     fn generated_pop_changes_with_seed() {
//         let a0 = scalar(42);
//         let idx = 3;
//
//         assert_ne!(
//             chilldkg_pop_sign(&[1u8; 32], a0, idx).unwrap(),
//             chilldkg_pop_sign(&[2u8; 32], a0, idx).unwrap()
//         );
//     }
//
//     #[test]
//     fn verification_rejects_wrong_index() {
//         let seed = [7u8; 32];
//         let a0 = scalar(42);
//         let pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
//
//         assert!(chilldkg_pop_verify(&pop, &(ProjectivePoint::GENERATOR * a0), 4).is_err());
//     }
//
//     #[test]
//     fn verification_rejects_wrong_pubkey() {
//         let seed = [7u8; 32];
//         let pop = chilldkg_pop_sign(&seed, scalar(42), 3).unwrap();
//         let wrong_pubkey = ProjectivePoint::GENERATOR * scalar(43);
//
//         assert!(chilldkg_pop_verify(&pop, &wrong_pubkey, 3).is_err());
//     }
//
//     #[test]
//     fn verification_rejects_tampered_public_nonce() {
//         let seed = [7u8; 32];
//         let a0 = scalar(42);
//         let mut pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
//
//         pop[0] ^= 1;
//
//         assert!(chilldkg_pop_verify(&pop, &(ProjectivePoint::GENERATOR * a0), 3).is_err());
//     }
//
//     #[test]
//     fn verification_rejects_tampered_response() {
//         let seed = [7u8; 32];
//         let a0 = scalar(42);
//         let mut pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
//
//         pop[63] ^= 1;
//
//         assert!(chilldkg_pop_verify(&pop, &(ProjectivePoint::GENERATOR * a0), 3).is_err());
//     }
//
//     #[test]
//     fn signing_rejects_zero_secret() {
//         let seed = [7u8; 32];
//
//         assert!(chilldkg_pop_sign(&seed, Scalar::ZERO, 0).is_err());
//     }
// }
