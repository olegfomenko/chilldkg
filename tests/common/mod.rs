use chilldkg_rs::crypto::curve::CurvePoint;
use chilldkg_rs::crypto::ec::parse_scalar_from_bytes;
use chilldkg_rs::crypto::schnorr::SchnorrSignature;
use chilldkg_rs::crypto::secp256k1::{
    COMPRESSED_POINT_BYTES_SIZE, EC_SCALAR_BYTES_SIZE, Secp256k1,
};
use chilldkg_rs::errors::{ChillDkgError, Result};
use chilldkg_rs::msg::{CoordinatorMsg1, CoordinatorMsg2, ParticipantMsg1, RecoveryData};
use k256::{ProjectivePoint, Scalar};

/// The test vectors of BIP-FROST-DKG are defined over secp256k1.
pub type CompressedPubKey = [u8; COMPRESSED_POINT_BYTES_SIZE];
pub type Signature = SchnorrSignature<Secp256k1>;

pub const SCHNORR_SIG_BYTES_SIZE: usize = Signature::BYTES_SIZE;

pub fn parse_participant_msg1(hex: &str, t: usize, n: usize) -> Result<ParticipantMsg1<Secp256k1>> {
    let bytes = decode(hex)?;
    let fixed_len = 33 * t + 64 + 33;
    if bytes.len() < fixed_len || !(bytes.len() - fixed_len).is_multiple_of(32) {
        return Err(ChillDkgError::RuntimeError(
            "invalid pmsg1 length".to_owned(),
        ));
    }

    let mut offset = 0;
    let commitment = (0..t)
        .map(|_| parse_point(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pop = parse_signature(take::<SCHNORR_SIG_BYTES_SIZE>(&bytes, &mut offset))?;
    let pubnonce = parse_point(take(&bytes, &mut offset))?;
    let enc_share_count = (bytes.len() - offset) / 32;
    if enc_share_count > n {
        return Err(ChillDkgError::RuntimeError(
            "invalid pmsg1 length".to_owned(),
        ));
    }
    let enc_shares = (0..enc_share_count)
        .map(|_| {
            parse_scalar_from_bytes::<Secp256k1>(&take::<EC_SCALAR_BYTES_SIZE>(&bytes, &mut offset))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ParticipantMsg1 {
        commitment,
        pop,
        pubnonce,
        enc_shares,
    })
}

pub fn parse_coordinator_msg1(hex: &str, t: usize, n: usize) -> Result<CoordinatorMsg1<Secp256k1>> {
    let bytes = decode(hex)?;
    let mut offset = 0;

    if bytes.len() < 33 * n
        || bytes.len() - 33 * n < 33 * (t - 1)
        || bytes.len() - 33 * n - 33 * (t - 1) < 64 * n
        || bytes.len() - 33 * n - 33 * (t - 1) - 64 * n < 33 * n
        || bytes.len() - 33 * n - 33 * (t - 1) - 64 * n - 33 * n < 32 * n
    {
        return Err(ChillDkgError::RuntimeError(
            "invalid cmsg1 length".to_owned(),
        ));
    }

    let coms_to_secrets = (0..n)
        .map(|_| parse_point_with_infinity(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let sum_coms_to_nonconst_terms = (0..t - 1)
        .map(|_| parse_point_with_infinity(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pops = (0..n)
        .map(|_| parse_signature(take::<SCHNORR_SIG_BYTES_SIZE>(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pubnonce_bytes: Vec<CompressedPubKey> = (0..n).map(|_| take(&bytes, &mut offset)).collect();
    let enc_secshares = (0..n)
        .map(|_| {
            parse_scalar_from_bytes::<Secp256k1>(&take::<EC_SCALAR_BYTES_SIZE>(&bytes, &mut offset))
        })
        .collect::<Result<Vec<_>>>()?;

    if offset != bytes.len() {
        return Err(ChillDkgError::RuntimeError(
            "incorrect input bytes length".to_owned(),
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

pub fn parse_coordinator_msg2(hex: &str) -> Result<CoordinatorMsg2<Secp256k1>> {
    Ok(CoordinatorMsg2 {
        cert: decode(hex)?
            .chunks_exact(SCHNORR_SIG_BYTES_SIZE)
            .map(Signature::from_slice)
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn serialize_recovery_data(recovery_data: &RecoveryData<Secp256k1>) -> Vec<u8> {
    let mut bytes: Vec<u8> = (&recovery_data.transcript).into();
    bytes.extend(recovery_data.cert.iter().flat_map(Signature::to_bytes));
    bytes
}

pub fn parse_scalar_hex(hex: &str) -> Result<Scalar> {
    parse_scalar_from_bytes::<Secp256k1>(&parse_hex_array::<EC_SCALAR_BYTES_SIZE>(hex)?)
}

pub fn parse_point_hex(hex: &str) -> Result<ProjectivePoint> {
    parse_hex_array(hex).and_then(parse_point)
}

pub fn parse_signature_hex(hex: &str) -> Result<Signature> {
    parse_hex_array::<SCHNORR_SIG_BYTES_SIZE>(hex).and_then(parse_signature)
}

pub fn parse_hex_array<const N: usize>(hex: &str) -> Result<[u8; N]> {
    decode(hex)?
        .try_into()
        .map_err(|_| ChillDkgError::RuntimeError("invalid hex length".to_owned()))
}

fn decode(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|err| ChillDkgError::RuntimeError(err.to_string()))
}

fn parse_signature(bytes: [u8; SCHNORR_SIG_BYTES_SIZE]) -> Result<Signature> {
    Signature::from_slice(&bytes)
}

fn parse_point(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    let point = <ProjectivePoint as CurvePoint>::from_bytes(&bytes)
        .ok_or_else(|| ChillDkgError::RuntimeError("invalid compressed point".to_owned()))?;
    if point.is_identity() {
        Err(ChillDkgError::RuntimeError("point is identity".to_owned()))
    } else {
        Ok(point)
    }
}

fn parse_point_with_infinity(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    if bytes == [0u8; COMPRESSED_POINT_BYTES_SIZE] {
        Ok(<ProjectivePoint as CurvePoint>::IDENTITY)
    } else {
        parse_point(bytes)
    }
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let out = bytes[*offset..*offset + N]
        .try_into()
        .expect("slice length is fixed");
    *offset += N;
    out
}
