use crate::crypto::ec::{BIP340XOnlyPubKey, compress_point_bip340, decompress_point_bip340};
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use anyhow::{Context, Result, bail, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};

pub type SchnorrSignature = [u8; 64];

/// Generates Proof of Possession:
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
pub fn chilldkg_pop_sign(seed: &[u8; 32], a0: Scalar, m: u32) -> Result<SchnorrSignature> {
    ensure!(
        !bool::from(a0.is_zero()),
        "PoP generation failed: BIP340: a0 is zero"
    );

    let aux_rand = tagged_hash(TAG_SIMPLPEDPOP_AUX, seed);
    let aux_hash = tagged_hash(TAG_POP_AUX, aux_rand);
    let (p_x, d) = compress_point_bip340(a0).context("PoP generation failed:")?;
    let mut t: [u8; 32] = d.to_bytes().into();
    for i in 0..32 {
        t[i] ^= aux_hash[i];
    }

    let msg = m.to_be_bytes();

    let mut nonce_preimage = Vec::with_capacity(32 + 32 + 4);
    nonce_preimage.extend_from_slice(&t);
    nonce_preimage.extend_from_slice(&p_x);
    nonce_preimage.extend_from_slice(&msg);

    let k = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_POP_NONCE,
        nonce_preimage,
    )));

    ensure!(
        !bool::from(k.is_zero()),
        "PoP generation failed: BIP340: nonce is zero"
    );

    let (r_x, k) = compress_point_bip340(k)?;

    let mut challenge_preimage = Vec::with_capacity(32 + 32 + 4);
    challenge_preimage.extend_from_slice(&r_x);
    challenge_preimage.extend_from_slice(&p_x);
    challenge_preimage.extend_from_slice(&msg);

    let e = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_POP_CHALLENGE,
        challenge_preimage,
    )));

    let s: [u8; 32] = (k + e * d).to_bytes().into();

    let mut pop = [0u8; 64];
    pop[..32].copy_from_slice(&r_x);
    pop[32..].copy_from_slice(&s);
    Ok(pop)
}

/// Verifies ChillDKG Proof of Possession.
///
/// Checks:
/// pop = R_x || s
/// e = H("BIP DKG/pop message/challenge", R_x || P_x || uint32_be(m)) mod n
/// R = s*G - e*P
/// accept iff R != infinity, has_even_y(R), and xonly(R) == R_x
pub fn chilldkg_pop_verify(
    pop: &SchnorrSignature,
    pubkey_xonly: &BIP340XOnlyPubKey,
    m: u32,
) -> Result<()> {
    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&pop[..32]);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pop[32..]);

    let s = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes)));
    let Some(s) = s else {
        bail!("PoP verification failed: invalid s");
    };

    let Some(p) = decompress_point_bip340(pubkey_xonly) else {
        bail!("PoP verification failed: invalid commitment");
    };

    let msg = m.to_be_bytes();

    let mut challenge_preimage = Vec::with_capacity(32 + 32 + 4);
    challenge_preimage.extend_from_slice(&r_x);
    challenge_preimage.extend_from_slice(pubkey_xonly);
    challenge_preimage.extend_from_slice(&msg);

    let e = Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_POP_CHALLENGE,
        challenge_preimage,
    )));

    let r = ProjectivePoint::GENERATOR * s - p * e;

    ensure!(
        !bool::from(r.is_identity()),
        "PoP generation failed: BIP340: r is identity"
    );

    let r_affine = r.to_affine();

    ensure!(
        !bool::from(r_affine.y_is_odd()),
        "PoP generation failed: BIP340: r is odd"
    );

    let computed_r_x: [u8; 32] = r_affine.x().into();

    if computed_r_x != r_x {
        bail!("PoP verification failed: invalid proof");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn pubkey_xonly(secret: Scalar) -> [u8; 32] {
        compress_point_bip340(secret).unwrap().0
    }

    #[test]
    fn generated_pop_verifies_for_matching_key_and_index() {
        let seed = [7u8; 32];
        let a0 = scalar(42);
        let idx = 3;
        let pop = chilldkg_pop_sign(&seed, a0, idx).unwrap();
        let pubkey = pubkey_xonly(a0);

        chilldkg_pop_verify(&pop, &pubkey, idx).unwrap();
    }

    #[test]
    fn generated_pop_is_deterministic_for_same_inputs() {
        let seed = [9u8; 32];
        let a0 = scalar(123);
        let idx = 1;

        assert_eq!(
            chilldkg_pop_sign(&seed, a0, idx).unwrap(),
            chilldkg_pop_sign(&seed, a0, idx).unwrap()
        );
    }

    #[test]
    fn generated_pop_changes_with_seed() {
        let a0 = scalar(42);
        let idx = 3;

        assert_ne!(
            chilldkg_pop_sign(&[1u8; 32], a0, idx).unwrap(),
            chilldkg_pop_sign(&[2u8; 32], a0, idx).unwrap()
        );
    }

    #[test]
    fn verification_rejects_wrong_index() {
        let seed = [7u8; 32];
        let a0 = scalar(42);
        let pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
        let pubkey = pubkey_xonly(a0);

        assert!(chilldkg_pop_verify(&pop, &pubkey, 4).is_err());
    }

    #[test]
    fn verification_rejects_wrong_pubkey() {
        let seed = [7u8; 32];
        let pop = chilldkg_pop_sign(&seed, scalar(42), 3).unwrap();
        let wrong_pubkey = pubkey_xonly(scalar(43));

        assert!(chilldkg_pop_verify(&pop, &wrong_pubkey, 3).is_err());
    }

    #[test]
    fn verification_rejects_tampered_public_nonce() {
        let seed = [7u8; 32];
        let a0 = scalar(42);
        let mut pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
        let pubkey = pubkey_xonly(a0);

        pop[0] ^= 1;

        assert!(chilldkg_pop_verify(&pop, &pubkey, 3).is_err());
    }

    #[test]
    fn verification_rejects_tampered_response() {
        let seed = [7u8; 32];
        let a0 = scalar(42);
        let mut pop = chilldkg_pop_sign(&seed, a0, 3).unwrap();
        let pubkey = pubkey_xonly(a0);

        pop[63] ^= 1;

        assert!(chilldkg_pop_verify(&pop, &pubkey, 3).is_err());
    }

    #[test]
    fn verification_rejects_invalid_pubkey_x_coordinate() {
        let pop = [0u8; 64];
        let invalid_pubkey = [0xffu8; 32];

        assert!(chilldkg_pop_verify(&pop, &invalid_pubkey, 0).is_err());
    }

    #[test]
    fn signing_rejects_zero_secret() {
        let seed = [7u8; 32];

        assert!(chilldkg_pop_sign(&seed, Scalar::ZERO, 0).is_err());
    }
}
