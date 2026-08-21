#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, Hash, ScalarBytes, XOnlyBytes};
use crate::crypto::ec::{compress_scalar_bip340, reduce_scalar_from_hash};
pub use crate::crypto::schnorr::SchnorrSignature;
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::{ChillDkgError, Result};
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
/// 6. Serialize result into signature
///    pop = R_x || bytes(s)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PopSigner<C: Curve> {
    a0: C::Scalar,
    seed: Hash<C>,
    message: [u8; 4],
}

impl<C: Curve> PopSigner<C> {
    pub fn new(a0: &C::Scalar, seed: &Hash<C>, m: u32) -> Self {
        PopSigner {
            a0: *a0,
            seed: *seed,
            message: m.to_be_bytes(),
        }
    }
}

impl<C: Curve> SchnorrSigner<C> for PopSigner<C> {
    fn message(&self) -> &[u8] {
        &self.message
    }

    fn secret_key(&self) -> SecretScalar<C> {
        Zeroizing::new(self.a0)
    }

    fn x_only_nonce(
        &self,
        P_x: &XOnlyBytes<C>,
        d: &C::Scalar,
    ) -> Result<(XOnlyBytes<C>, SecretScalar<C>)> {
        let aux_rand = tagged_hash::<C>(TAG_SIMPLPEDPOP_AUX, self.seed);
        let aux_hash = tagged_hash::<C>(TAG_POP_AUX, aux_rand);
        let mut t: Zeroizing<ScalarBytes<C>> = Zeroizing::new(d.to_bytes());
        for (t_i, aux_i) in t.as_mut().iter_mut().zip(aux_hash.as_ref()) {
            *t_i ^= aux_i;
        }

        let mut nonce_preimage = Zeroizing::new(Vec::with_capacity(
            <C::Scalar as CurveScalar>::BYTES_SIZE
                + <C::Point as CurvePoint>::X_ONLY_BYTES_SIZE
                + 4,
        ));
        nonce_preimage.extend_from_slice(t.as_ref());
        nonce_preimage.extend_from_slice(P_x.as_ref());
        nonce_preimage.extend_from_slice(self.message());

        let preimage_hash = Zeroizing::new(tagged_hash::<C>(TAG_POP_NONCE, &nonce_preimage));
        let k = reduce_scalar_from_hash::<C>(&preimage_hash);

        chill_dkg_ensure!(
            !k.is_zero(),
            ChillDkgError::RuntimeError("PoP generation failed: BIP340: nonce is zero".to_owned()),
        );

        Ok(compress_scalar_bip340::<C>(&k))
    }
    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar> {
        get_pop_challenge::<C>(R, P, self.message())
    }
}

/// Verifies ChillDKG Proof of Possession (a Schnorr signature).
///
/// Checks:
///    pop = R_x || s
///    e = H("BIP DKG/pop message/challenge", R_x || Com_x || uint32_be(m)) mod n
///    R = s*G - e*Com
///    accept iff R != infinity, has_even_y(R), and xonly(R) == R_x
pub struct PopVerifier<C: Curve> {
    com: C::Point,
    message: [u8; 4],
}

impl<C: Curve> PopVerifier<C> {
    pub fn new(com: C::Point, m: u32) -> Self {
        PopVerifier {
            com,
            message: m.to_be_bytes(),
        }
    }
}

impl<C: Curve> SchnorrVerifier<C> for PopVerifier<C> {
    fn message(&self) -> &[u8] {
        &self.message
    }

    fn pub_key(&self) -> C::Point {
        self.com
    }

    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar> {
        get_pop_challenge::<C>(R, P, self.message())
    }
}

fn get_pop_challenge<C: Curve>(
    R: &XOnlyBytes<C>,
    P: &XOnlyBytes<C>,
    message: &[u8],
) -> Result<C::Scalar> {
    let mut challenge_preimage =
        Vec::with_capacity(<C::Point as CurvePoint>::X_ONLY_BYTES_SIZE * 2 + message.len());
    challenge_preimage.extend_from_slice(R.as_ref());
    challenge_preimage.extend_from_slice(P.as_ref());
    challenge_preimage.extend_from_slice(message);

    Ok(C::hash_to_scalar(&tagged_hash::<C>(
        TAG_POP_CHALLENGE,
        challenge_preimage,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::Secp256k1;
    use k256::{ProjectivePoint, Scalar};

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn sign_pop(seed: &[u8; 32], a0: &Scalar, idx: u32) -> SchnorrSignature<Secp256k1> {
        PopSigner::<Secp256k1>::new(a0, seed, idx).sign().unwrap()
    }

    #[test]
    fn generated_pop_verifies_for_matching_key_and_index() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let idx = 3;
        let pop = sign_pop(&seed, &a0, idx);

        PopVerifier::<Secp256k1>::new(ProjectivePoint::GENERATOR * a0, idx)
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
            PopVerifier::<Secp256k1>::new(ProjectivePoint::GENERATOR * a0, 4)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_wrong_pubkey() {
        let seed = Zeroizing::new([7u8; 32]);
        let pop = sign_pop(&seed, &scalar(42), 3);
        let wrong_pubkey = ProjectivePoint::GENERATOR * scalar(43);

        assert!(
            PopVerifier::<Secp256k1>::new(wrong_pubkey, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_identity_pubkey() {
        let seed = Zeroizing::new([7u8; 32]);
        let pop = sign_pop(&seed, &scalar(42), 3);

        assert!(
            PopVerifier::<Secp256k1>::new(ProjectivePoint::IDENTITY, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_tampered_public_nonce() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let mut pop = sign_pop(&seed, &a0, 3);

        pop.pubnonce[0] ^= 1;

        assert!(
            PopVerifier::<Secp256k1>::new(ProjectivePoint::GENERATOR * a0, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_tampered_response() {
        let seed = Zeroizing::new([7u8; 32]);
        let a0 = scalar(42);
        let mut pop = sign_pop(&seed, &a0, 3);

        pop.response[31] ^= 1;

        assert!(
            PopVerifier::<Secp256k1>::new(ProjectivePoint::GENERATOR * a0, 3)
                .verify(pop)
                .is_err()
        );
    }

    #[test]
    fn signing_rejects_zero_secret() {
        let seed = Zeroizing::new([7u8; 32]);

        assert!(
            PopSigner::<Secp256k1>::new(&Scalar::ZERO, &seed, 0)
                .sign()
                .is_err()
        );
    }
}
