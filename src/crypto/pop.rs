use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256};

use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_POP_AUX, TAG_POP_CHALLENGE, TAG_POP_NONCE, TAG_SIMPLPEDPOP_AUX};
use anyhow::{Context, Result, bail};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::{Group, PrimeField};

/// Serializes x * G as x-only point and returns normalizes scalar as well.
fn compress_point_bip340(x: Scalar) -> Result<([u8; 32], Scalar)> {
    if bool::from(x.is_zero()) {
        bail!("BIP340: can't compress for zero scalar");
    }

    let p = ProjectivePoint::GENERATOR * x;
    let p_x: [u8; 32] = p.to_affine().x().into();

    // BIP340 key normalization.
    if bool::from(p.to_affine().y_is_odd()) {
        Ok((p_x, -x))
    } else {
        Ok((p_x, x))
    }
}

/// Deserializes BIP340 x-only point
fn decompress_point_bip340(x: &[u8; 32]) -> Option<ProjectivePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // BIP340 x-only points always mean the even-Y point.
    compressed[1..].copy_from_slice(x);

    let encoded = k256::EncodedPoint::from_bytes(compressed).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

    Some(ProjectivePoint::from(affine))
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
    if bool::from(a0.is_zero()) {
        bail!("PoP generation failed: BIP340: a0 is zero");
    }

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

    if bool::from(k.is_zero()) {
        bail!("PoP generation failed: BIP340: nonce is zero");
    }

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
pub fn chilldkg_pop_verify(pop: &[u8; 64], pubkey_xonly: &[u8; 32], m: u32) -> Result<()> {
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

    if bool::from(r.is_identity()) {
        bail!("PoP verification failed: r is identity");
    }

    let affine = r.to_affine();

    if bool::from(affine.y_is_odd()) {
        bail!("PoP verification failed: r is odd");
    }

    let computed_r_x: [u8; 32] = affine.x().into();

    if computed_r_x != r_x {
        bail!("PoP verification failed: invalid proof");
    }

    Ok(())
}
