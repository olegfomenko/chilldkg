#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use chilldkg_rs::crypto::ec::{CompressedPubKey, decompress_default};
use chilldkg_rs::crypto::ec::{EC_SCALAR_BYTES_SIZE, parse_scalar_from_bytes};
use chilldkg_rs::crypto::schnorr::SCHNORR_SIG_BYTES_SIZE;
use chilldkg_rs::errors::{ChillDkgError, Result};
use chilldkg_rs::msg::{CoordinatorMsg1, CoordinatorMsg2, ParticipantMsg1, RecoveryData};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

pub fn parse_participant_msg1(hex: &str, t: usize, n: usize) -> Result<ParticipantMsg1> {
    let bytes = decode(hex)?;
    let fixed_len = 33 * t + 64 + 33;
    if bytes.len() < fixed_len || !(bytes.len() - fixed_len).is_multiple_of(32) {
        return Err(ChillDkgError::Runtime("invalid pmsg1 length".into()));
    }

    let mut offset = 0;
    let commitment = (0..t)
        .map(|_| parse_point(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pop = take(&bytes, &mut offset);
    let pubnonce = parse_point(take(&bytes, &mut offset))?;
    let enc_share_count = (bytes.len() - offset) / 32;
    if enc_share_count > n {
        return Err(ChillDkgError::Runtime("invalid pmsg1 length".into()));
    }
    let enc_shares = (0..enc_share_count)
        .map(|_| parse_scalar_from_bytes(take::<EC_SCALAR_BYTES_SIZE>(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;

    Ok(ParticipantMsg1 {
        commitment,
        pop,
        pubnonce,
        enc_shares,
    })
}

pub fn parse_coordinator_msg1(hex: &str, t: usize, n: usize) -> Result<CoordinatorMsg1> {
    let bytes = decode(hex)?;
    let mut offset = 0;

    if bytes.len() < 33 * n
        || bytes.len() - 33 * n < 33 * (t - 1)
        || bytes.len() - 33 * n - 33 * (t - 1) < 64 * n
        || bytes.len() - 33 * n - 33 * (t - 1) - 64 * n < 33 * n
        || bytes.len() - 33 * n - 33 * (t - 1) - 64 * n - 33 * n < 32 * n
    {
        return Err(ChillDkgError::Runtime("invalid cmsg1 length".into()));
    }

    let coms_to_secrets = (0..n)
        .map(|_| parse_point_with_infinity(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let sum_coms_to_nonconst_terms = (0..t - 1)
        .map(|_| parse_point_with_infinity(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pops = (0..n).map(|_| take(&bytes, &mut offset)).collect();
    let pubnonce_bytes: Vec<CompressedPubKey> = (0..n).map(|_| take(&bytes, &mut offset)).collect();
    let enc_secshares = (0..n)
        .map(|_| parse_scalar_from_bytes(take::<EC_SCALAR_BYTES_SIZE>(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;

    if offset != bytes.len() {
        return Err(ChillDkgError::Runtime(
            "incorrect input bytes length".into(),
        ));
    }

    Ok(CoordinatorMsg1 {
        coms_to_secrets,
        sum_coms_to_nonconst_terms,
        pops,
        pubnonces: pubnonce_bytes
            .into_iter()
            .map(parse_point)
            .collect::<Result<Vec<_>>>()?,
        enc_secshares,
    })
}

pub fn parse_coordinator_msg2(hex: &str) -> Result<CoordinatorMsg2> {
    let bytes = decode(hex)?;

    Ok(CoordinatorMsg2 {
        cert: bytes.as_chunks::<SCHNORR_SIG_BYTES_SIZE>().0.to_vec(),
    })
}

pub fn serialize_recovery_data(recovery_data: &RecoveryData) -> Vec<u8> {
    let mut bytes: Vec<u8> = (&recovery_data.transcript).into();
    bytes.extend(recovery_data.cert.iter().flatten().copied());
    bytes
}

pub fn parse_scalar_hex(hex: &str) -> Result<Scalar> {
    parse_scalar_from_bytes(parse_hex_array::<EC_SCALAR_BYTES_SIZE>(hex)?)
}

pub fn parse_point_hex(hex: &str) -> Result<ProjectivePoint> {
    parse_hex_array(hex).and_then(parse_point)
}

pub fn parse_hex_array<const N: usize>(hex: &str) -> Result<[u8; N]> {
    decode(hex)?
        .try_into()
        .map_err(|_| ChillDkgError::Runtime("invalid hex length".into()))
}

fn decode(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|err| ChillDkgError::Runtime(err.to_string().into()))
}

pub fn parse_point(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    let point = decompress_default(&bytes)
        .ok_or_else(|| ChillDkgError::Runtime("invalid compressed point".into()))?;
    if bool::from(point.is_identity()) {
        Err(ChillDkgError::Runtime("point is identity".into()))
    } else {
        Ok(point)
    }
}

pub fn parse_point_with_infinity(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    if bytes == [0u8; 33] {
        Ok(ProjectivePoint::IDENTITY)
    } else {
        parse_point(bytes)
    }
}

pub fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let out = bytes[*offset..*offset + N]
        .try_into()
        .expect("slice length is fixed");
    *offset += N;
    out
}

#[cfg(feature = "signing")]
pub fn parse_pubnonce_hex(hex: &str) -> Result<chilldkg_rs::sign::PubNonce> {
    let bytes: [u8; 66] = parse_hex_array(hex)?;
    let mut offset = 0;
    Ok(chilldkg_rs::sign::PubNonce {
        R1: parse_point(take(&bytes, &mut offset))?,
        R2: parse_point(take(&bytes, &mut offset))?,
    })
}

/// Aggregate nonce `R_1 || R_2`, where 33 zero bytes denote the identity.
#[cfg(feature = "signing")]
pub fn parse_aggnonce_hex(hex: &str) -> Result<(ProjectivePoint, ProjectivePoint)> {
    let bytes: [u8; 66] = parse_hex_array(hex)?;
    let mut offset = 0;
    Ok((
        parse_point_with_infinity(take(&bytes, &mut offset))?,
        parse_point_with_infinity(take(&bytes, &mut offset))?,
    ))
}

/// `R_1 || R_2` in compressed form, identity as 33 zero bytes.
#[cfg(feature = "signing")]
pub fn serialize_nonce(R1: &ProjectivePoint, R2: &ProjectivePoint) -> String {
    use chilldkg_rs::crypto::ec::compress_default;
    hex::encode_upper([compress_default(R1), compress_default(R2)].concat())
}

/// BIP340 verification of `sig` over `msg` under the x-only key of `pk`.
#[cfg(feature = "signing")]
pub fn verify_bip340(
    sig: chilldkg_rs::crypto::schnorr::SchnorrSignature,
    pk: &ProjectivePoint,
    msg: &[u8],
) -> Result<()> {
    use chilldkg_rs::crypto::ec::{BIP340XOnlyPubKey, reduce_scalar_from_bytes};
    use chilldkg_rs::crypto::schnorr::SchnorrVerifier;
    use chilldkg_rs::crypto::tagged_hash;
    use chilldkg_rs::crypto::tags::TAG_BIP340_CHALLENGE;

    struct Bip340<'a>(&'a [u8], ProjectivePoint);

    impl SchnorrVerifier for Bip340<'_> {
        fn message(&self) -> &[u8] {
            self.0
        }
        fn pub_key(&self) -> ProjectivePoint {
            self.1
        }
        fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
            Ok(reduce_scalar_from_bytes(tagged_hash(
                TAG_BIP340_CHALLENGE,
                [R.as_slice(), P, self.0].concat(),
            )))
        }
    }

    Bip340(msg, *pk).verify(sig)
}
