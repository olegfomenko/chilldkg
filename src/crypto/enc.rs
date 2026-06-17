use crate::crypto::ec::compress_default;
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_ENCAPS_MULTI_SELF_PAD, TAG_ENCPEDPOP_ECDH};
use anyhow::{Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

/// ChillDKG ECDH sending pad.
///
/// Puts ecdh_key = SHA256(compressed(r_i * P_j))
/// Then, puts pad_{i,j} =
///     H_tag(
///         "BIP DKG/encpedpop ecdh",
///         ecdh_key || R_i || P_j
///     ) mod n
pub fn ecdh_send_pad(r_i: &Scalar, P_j: &ProjectivePoint, context: &[u8]) -> Scalar {
    let ecdh_bytes = Sha256::digest(compress_default(&(P_j * r_i)));
    let mut data = Vec::with_capacity(32 + 33 + 33 + context.len());
    data.extend_from_slice(&ecdh_bytes);
    data.extend_from_slice(&compress_default(&(ProjectivePoint::GENERATOR * r_i)));
    data.extend_from_slice(&compress_default(&P_j));
    data.extend_from_slice(context);
    Scalar::reduce(U256::from_be_slice(&tagged_hash(TAG_ENCPEDPOP_ECDH, data)))
}

/// ChillDKG ECDH receiving pad.
///
/// Puts ecdh_key = SHA256(compressed(s_i * R_j))
/// Then, puts pad_{j,i} =
///     H_tag(
///         "BIP DKG/encpedpop ecdh",
///         ecdh_key || R_j || P_i
///     ) mod n
pub fn ecdh_receive_pad(s_i: &Scalar, R_j: &ProjectivePoint, context: &[u8]) -> Scalar {
    let ecdh_bytes = Sha256::digest(compress_default(&(R_j * s_i)));
    let mut data = Vec::with_capacity(32 + 33 + 33 + context.len());
    data.extend_from_slice(&ecdh_bytes);
    data.extend_from_slice(&compress_default(&R_j));
    data.extend_from_slice(&compress_default(&(ProjectivePoint::GENERATOR * s_i)));
    data.extend_from_slice(context);
    Scalar::reduce(U256::from_be_slice(&tagged_hash(TAG_ENCPEDPOP_ECDH, data)))
}

/// ChillDKG self-encryption pad.
///
/// Used when sender encrypts to itself, i = j:
///
/// pad_{i,i} =
///     H_tag(
///         "BIP DKG/encaps_multi self_pad",
///         S_i || R_i || ctx_i
///     ) mod n
pub fn self_pad(s_i: &Scalar, r_i: &Scalar, context: &[u8]) -> Scalar {
    let seckey_bytes: [u8; 32] = s_i.to_bytes().into();

    let mut data = Vec::with_capacity(32 + 33 + context.len());
    data.extend_from_slice(&seckey_bytes);
    data.extend_from_slice(&compress_default(&(ProjectivePoint::GENERATOR * r_i)));
    data.extend_from_slice(context);

    Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_ENCAPS_MULTI_SELF_PAD,
        data,
    )))
}

/// Encrypts this participant's VSS shares for all recipients.
///
/// For each recipient j:
/// ctx_j = uint32_be(j) || context
///
/// if j == idx:
///     pad_{idx,j} = self_pad(s_idx, r_idx, ctx_j)
/// else:
///     pad_{idx,j} = ecdh_send_pad(r_idx, P_j, ctx_j)
///
/// ciphertext_j = share_j + pad_{idx,j}
pub fn encrypt(
    r_idx: &Scalar,
    s_idx: &Scalar,
    P: &[ProjectivePoint],
    context: &[u8],
    idx: usize,
    shares: &[Scalar],
) -> Result<Vec<Scalar>> {
    ensure!(
        idx < P.len(),
        "Encryption failed: participant index out of range"
    );
    ensure!(
        shares.len() == P.len(),
        "Encryption failed: number of shares must match number of encryption keys"
    );

    let mut ciphertexts = Vec::with_capacity(shares.len());

    for (j, (share, P_j)) in shares.iter().copied().zip(P.iter()).enumerate() {
        let mut context_j = Vec::with_capacity(4 + context.len());
        context_j.extend_from_slice(&(j as u32).to_be_bytes());
        context_j.extend_from_slice(context);

        let pad = if j == idx {
            self_pad(s_idx, r_idx, &context_j)
        } else {
            ecdh_send_pad(s_idx, P_j, &context_j)
        };

        ciphertexts.push(share + pad);
    }

    Ok(ciphertexts)
}

/// Encrypts aggregated VSS shares for this participant
///
/// ctx_idx = uint32_be(idx) || context
///
/// if j == idx:
///     pad_{j, idx} = self_pad(s_idx, r_idx, ctx_idx)
/// else:
///     pad_{j, idx} = ecdh_receive_pad(s_idx, R_j, ctx_idx)
///
/// aggr_shares = aggr_ciphertexts - pads
pub fn decrypt(
    r_idx: &Scalar,
    s_idx: &Scalar,
    R: &[ProjectivePoint],
    context: &[u8],
    idx: usize,
    aggr_ciphertexts: &Scalar,
) -> Result<Scalar> {
    ensure!(
        idx < R.len(),
        "Encryption failed: participant index out of range"
    );

    let mut aggr_pads = Scalar::ZERO;

    let mut context_idx = Vec::with_capacity(4 + context.len());
    context_idx.extend_from_slice(&(idx as u32).to_be_bytes());
    context_idx.extend_from_slice(context);

    for (j, R_j) in R.iter().enumerate() {
        let pad = if j == idx {
            self_pad(s_idx, r_idx, &context_idx)
        } else {
            ecdh_receive_pad(s_idx, R_j, &context_idx)
        };

        aggr_pads += pad;
    }

    Ok(aggr_ciphertexts - &aggr_pads)
}
