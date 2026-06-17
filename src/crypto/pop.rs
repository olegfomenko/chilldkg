use k256::{ProjectivePoint, Scalar, U256};

use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use anyhow::Result;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;

/// Serializes x * G as x-only point and returns normalizes scalar as well.
fn serialize_point_bip340(x: Scalar) -> ([u8; 32], Scalar) {
    let p = ProjectivePoint::GENERATOR * x;
    let p_x: [u8; 32] = p.to_affine().x().into();

    // BIP340 key normalization.
    if bool::from(p.to_affine().y_is_odd()) {
        (p_x, -x)
    } else {
        (p_x, x)
    }
}

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
pub fn chilldkg_pop_sign(seed: &[u8; 32], a0: Scalar, m: u32) -> Result<[u8; 64]> {
    let aux_rand = tagged_hash(TAG_SIMPLPEDPOP_AUX, seed);
    let aux_hash = tagged_hash(TAG_POP_AUX, aux_rand);
    let (p_x, d) = serialize_point_bip340(a0);
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

    let (r_x, k) = serialize_point_bip340(k);

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
