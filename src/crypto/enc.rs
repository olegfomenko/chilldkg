use crate::crypto::ec::compress_default;
use crate::crypto::tagged_hash;
use crate::crypto::tags::{TAG_ENCAPS_MULTI_SELF_PAD, TAG_ENCPEDPOP_ECDH};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

/// ChillDKG ECDH pad.
///
/// Sender:
/// seckey = r_i
/// my_pubkey = R_i
/// their_pubkey = P_j
/// sending = true
///
/// Receiver:
/// seckey = S_j
/// my_pubkey = P_j
/// their_pubkey = R_i
/// sending = false
///
/// Puts ecdh_key = SHA256(compressed(their_pubkey * seckey))
/// Then, puts pad_{i,i} =
///     H_tag(
///         "BIP DKG/encpedpop ecdh",
///         ecdh_key || my_pubkey || their_pubkey
///     ) mod n
/// if sending, and puts pad_{i,i} =
///     H_tag(
///         "BIP DKG/encpedpop ecdh",
///         ecdh_key || their_pubkey || my_pubkey
///     ) mod n
/// otherwise.
pub fn ecdh_pad(
    seckey: &Scalar,
    my_pubkey: &ProjectivePoint,
    their_pubkey: &ProjectivePoint,
    context: &[u8],
    sending: bool,
) -> Scalar {
    let ecdh_bytes = Sha256::digest(compress_default(&(their_pubkey * seckey)));
    let my_pubkey = compress_default(&my_pubkey);
    let their_pubkey = compress_default(&their_pubkey);

    let mut data = Vec::with_capacity(32 + 33 + 33 + context.len());
    data.extend_from_slice(&ecdh_bytes);

    if sending {
        data.extend_from_slice(&my_pubkey); // R_i
        data.extend_from_slice(&their_pubkey); // P_j
    } else {
        data.extend_from_slice(&their_pubkey); // R_i
        data.extend_from_slice(&my_pubkey); // P_j
    }

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
///
/// where:
/// S_i   = 32-byte host secret key scalar
/// R_i   = compressed 33-byte public encryption nonce
/// ctx_i = uint32_be(i) || ctx
pub fn self_pad(seckey: &Scalar, nonce: &ProjectivePoint, context: &[u8]) -> Scalar {
    let seckey_bytes: [u8; 32] = seckey.to_bytes().into();
    let nonce_bytes = compress_default(&nonce);

    let mut data = Vec::with_capacity(32 + 33 + context.len());
    data.extend_from_slice(&seckey_bytes);
    data.extend_from_slice(&nonce_bytes);
    data.extend_from_slice(context);

    Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_ENCAPS_MULTI_SELF_PAD,
        data,
    )))
}
