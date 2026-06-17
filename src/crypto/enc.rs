#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

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
///         ecdh_key || R_i || P_j || context
///     ) mod n
pub fn ecdh_send_pad(r_i: &Scalar, P_j: &ProjectivePoint, context: &[u8]) -> Scalar {
    let ecdh_bytes = Sha256::digest(compress_default(&(P_j * r_i)));
    let mut data = Vec::with_capacity(32 + 33 + 33 + context.len());
    data.extend_from_slice(&ecdh_bytes);
    data.extend_from_slice(&compress_default(&(ProjectivePoint::GENERATOR * r_i)));
    data.extend_from_slice(&compress_default(P_j));
    data.extend_from_slice(context);
    Scalar::reduce(U256::from_be_slice(&tagged_hash(TAG_ENCPEDPOP_ECDH, data)))
}

/// ChillDKG ECDH receiving pad.
///
/// Puts ecdh_key = SHA256(compressed(s_i * R_j))
/// Then, puts pad_{j,i} =
///     H_tag(
///         "BIP DKG/encpedpop ecdh",
///         ecdh_key || R_j || P_i || context
///     ) mod n
pub fn ecdh_receive_pad(s_i: &Scalar, R_j: &ProjectivePoint, context: &[u8]) -> Scalar {
    let ecdh_bytes = Sha256::digest(compress_default(&(R_j * s_i)));
    let mut data = Vec::with_capacity(32 + 33 + 33 + context.len());
    data.extend_from_slice(&ecdh_bytes);
    data.extend_from_slice(&compress_default(R_j));
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
pub fn self_pad(s_i: &Scalar, R_i: &ProjectivePoint, context: &[u8]) -> Scalar {
    let seckey_bytes: [u8; 32] = s_i.to_bytes().into();

    let mut data = Vec::with_capacity(32 + 33 + context.len());
    data.extend_from_slice(&seckey_bytes);
    data.extend_from_slice(&compress_default(R_i));
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
///     pad_{idx,j} = self_pad(s_idx, R_idx, ctx_j)
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

    let R_idx = ProjectivePoint::GENERATOR * r_idx;

    let mut ciphertexts = Vec::with_capacity(shares.len());

    for (j, (share, P_j)) in shares.iter().copied().zip(P.iter()).enumerate() {
        let mut context_j = Vec::with_capacity(4 + context.len());
        context_j.extend_from_slice(&(j as u32).to_be_bytes());
        context_j.extend_from_slice(context);

        let pad = if j == idx {
            self_pad(s_idx, &R_idx, &context_j)
        } else {
            ecdh_send_pad(r_idx, P_j, &context_j)
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
///     pad_{j, idx} = self_pad(s_idx, R_idx, ctx_idx)
/// else:
///     pad_{j, idx} = ecdh_receive_pad(s_idx, R_j, ctx_idx)
///
/// aggr_shares = aggr_ciphertexts - pads
pub fn decrypt(
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
            self_pad(s_idx, R_j, &context_idx)
        } else {
            ecdh_receive_pad(s_idx, R_j, &context_idx)
        };

        aggr_pads += pad;
    }

    Ok(*aggr_ciphertexts - aggr_pads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn public_key(secret: Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * secret
    }

    #[test]
    fn ecdh_send_and_receive_pads_match_for_same_pair() {
        let sender_secnonce = scalar(11);
        let sender_pubnonce = public_key(sender_secnonce);
        let receiver_deckey = scalar(19);
        let receiver_enckey = public_key(receiver_deckey);
        let context = b"enc-context";

        assert_eq!(
            ecdh_send_pad(&sender_secnonce, &receiver_enckey, context),
            ecdh_receive_pad(&receiver_deckey, &sender_pubnonce, context)
        );
    }

    #[test]
    fn ecdh_pad_depends_on_context() {
        let sender_secnonce = scalar(11);
        let receiver_enckey = public_key(scalar(19));

        assert_ne!(
            ecdh_send_pad(&sender_secnonce, &receiver_enckey, b"first-context"),
            ecdh_send_pad(&sender_secnonce, &receiver_enckey, b"second-context")
        );
    }

    #[test]
    fn ecdh_pad_depends_on_key_pair() {
        let context = b"enc-context";

        assert_ne!(
            ecdh_send_pad(&scalar(11), &public_key(scalar(19)), context),
            ecdh_send_pad(&scalar(13), &public_key(scalar(19)), context)
        );
        assert_ne!(
            ecdh_send_pad(&scalar(11), &public_key(scalar(19)), context),
            ecdh_send_pad(&scalar(11), &public_key(scalar(23)), context)
        );
    }

    #[test]
    fn self_pad_is_deterministic_and_context_bound() {
        let deckey = scalar(19);
        let pubnonce = public_key(scalar(11));

        assert_eq!(
            self_pad(&deckey, &pubnonce, b"self-context"),
            self_pad(&deckey, &pubnonce, b"self-context")
        );
        assert_ne!(
            self_pad(&deckey, &pubnonce, b"self-context"),
            self_pad(&deckey, &pubnonce, b"other-context")
        );
    }

    #[test]
    fn encrypt_and_decrypt_aggregated_shares() {
        let deckeys = [scalar(3), scalar(5), scalar(7)];
        let secnonces = [scalar(11), scalar(13), scalar(17)];
        let enckeys: Vec<ProjectivePoint> = deckeys.iter().copied().map(public_key).collect();
        let pubnonces: Vec<ProjectivePoint> =
            secnonces.iter().copied().map(public_key).collect();
        let context = b"session-context";
        let shares = [
            [scalar(101), scalar(102), scalar(103)],
            [scalar(201), scalar(202), scalar(203)],
            [scalar(301), scalar(302), scalar(303)],
        ];

        let encrypted: Vec<Vec<Scalar>> = shares
            .iter()
            .enumerate()
            .map(|(idx, sender_shares)| {
                encrypt(
                    &secnonces[idx],
                    &deckeys[idx],
                    &enckeys,
                    context,
                    idx,
                    sender_shares,
                )
                .unwrap()
            })
            .collect();

        for recipient_idx in 0..deckeys.len() {
            let aggregated_ciphertext = encrypted
                .iter()
                .fold(Scalar::ZERO, |acc, ciphertexts| {
                    acc + ciphertexts[recipient_idx]
                });
            let expected_share = shares
                .iter()
                .fold(Scalar::ZERO, |acc, sender_shares| {
                    acc + sender_shares[recipient_idx]
                });

            assert_eq!(
                decrypt(
                    &deckeys[recipient_idx],
                    &pubnonces,
                    context,
                    recipient_idx,
                    &aggregated_ciphertext,
                )
                .unwrap(),
                expected_share
            );
        }
    }

    #[test]
    fn encrypt_rejects_invalid_inputs() {
        let secnonce = scalar(11);
        let deckey = scalar(3);
        let enckeys = vec![public_key(deckey)];

        assert!(encrypt(&secnonce, &deckey, &enckeys, b"context", 1, &[scalar(1)]).is_err());
        assert!(encrypt(&secnonce, &deckey, &enckeys, b"context", 0, &[]).is_err());
    }

    #[test]
    fn decrypt_rejects_invalid_index() {
        let deckey = scalar(3);
        let pubnonces = vec![public_key(scalar(11))];

        assert!(decrypt(&deckey, &pubnonces, b"context", 1, &scalar(1)).is_err());
    }
}
