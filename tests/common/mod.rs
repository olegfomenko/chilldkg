use anyhow::{Context, Result, ensure};
use chilldkg::crypto::ec::{CompressedPubKey, decompress_default};
use chilldkg::crypto::scalar_from_bytes;
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::{
    CoordinatorMsg1, CoordinatorMsg2, ParticipantMsg1, ParticipantMsg2, RecoveryData,
};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ExpectedError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub participant: Option<usize>,
    pub participant1: Option<usize>,
    pub participant2: Option<usize>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Params {
    pub hostpubkeys: Vec<String>,
    pub t: usize,
}

pub fn parse_host_pubkeys(params: &Params) -> Result<Vec<ProjectivePoint>> {
    params
        .hostpubkeys
        .iter()
        .map(|hex| parse_point_hex(hex))
        .collect()
}

pub fn parse_participant_msg1(hex: &str, t: usize, n: usize) -> Result<ParticipantMsg1> {
    let bytes = hex::decode(hex)?;
    let fixed_len = 33 * t + 64 + 33;
    ensure!(bytes.len() >= fixed_len, "invalid pmsg1 length");
    ensure!((bytes.len() - fixed_len) % 32 == 0, "invalid pmsg1 length");

    let mut offset = 0;
    let commitment = (0..t)
        .map(|_| parse_point(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pop = take(&bytes, &mut offset);
    let pubnonce = parse_point(take(&bytes, &mut offset))?;
    let enc_share_count = (bytes.len() - offset) / 32;
    ensure!(enc_share_count <= n, "invalid pmsg1 length");
    let enc_shares = (0..enc_share_count)
        .map(|_| scalar_from_bytes(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;

    Ok(ParticipantMsg1 {
        commitment,
        pop,
        pubnonce,
        enc_shares,
    })
}

pub fn parse_coordinator_msg1(hex: &str, t: usize, n: usize) -> Result<CoordinatorMsg1> {
    let bytes = hex::decode(hex)?;
    let mut offset = 0;

    ensure!(bytes.len() >= 33 * n, "missing commitments to secrets",);
    let coms_to_secrets = (0..n)
        .map(|_| {
            parse_point_with_infinity(take(&bytes, &mut offset))
                .context("invalid commitment to secret")
        })
        .collect::<Result<Vec<_>>>()?;

    ensure!(
        bytes.len() - offset >= 33 * (t - 1),
        "missing sum commitments to non-constant terms",
    );
    let sum_coms_to_nonconst_terms = (0..t - 1)
        .map(|_| {
            parse_point_with_infinity(take(&bytes, &mut offset))
                .context("invalid sum commitment to non-constant term")
        })
        .collect::<Result<Vec<_>>>()?;

    ensure!(
        bytes.len() - offset >= 64 * n,
        "missing proofs of possession",
    );
    let pops = (0..n).map(|_| take(&bytes, &mut offset)).collect();

    ensure!(bytes.len() - offset >= 33 * n, "missing public nonces",);
    let pubnonce_bytes: Vec<CompressedPubKey> = (0..n).map(|_| take(&bytes, &mut offset)).collect();

    ensure!(
        bytes.len() - offset >= 32 * n,
        "missing encrypted secret shares",
    );
    let enc_secshares = (0..n)
        .map(|_| {
            scalar_from_bytes(take(&bytes, &mut offset)).context("invalid encrypted secret shares")
        })
        .collect::<Result<Vec<_>>>()?;

    ensure!(offset == bytes.len(), "incorrect input bytes length",);

    let pubnonces = pubnonce_bytes
        .into_iter()
        .map(parse_point)
        .collect::<Result<Vec<_>>>()?;

    Ok(CoordinatorMsg1 {
        coms_to_secrets,
        sum_coms_to_nonconst_terms,
        pops,
        pubnonces,
        enc_secshares,
    })
}

pub fn parse_participant_msg2(hex: &str) -> Result<ParticipantMsg2> {
    Ok(ParticipantMsg2 {
        sig: parse_hex_array(hex)?,
    })
}

pub fn serialize_coordinator_msg2(coordinator_msg: &CoordinatorMsg2) -> Vec<u8> {
    coordinator_msg.cert.iter().flatten().copied().collect()
}

pub fn serialize_recovery_data(recovery_data: &RecoveryData) -> Vec<u8> {
    let mut bytes = recovery_data.transcript.clone();
    bytes.extend(recovery_data.cert.iter().flatten().copied());
    bytes
}

pub fn parse_scalar_hex(hex: &str) -> Result<Scalar> {
    parse_hex_array(hex).and_then(scalar_from_bytes)
}

pub fn parse_point_hex(hex: &str) -> Result<ProjectivePoint> {
    parse_hex_array(hex).and_then(parse_point)
}

pub fn assert_expected_error(actual: &ChillDkgError, expected: &ExpectedError, tc_id: usize) {
    assert_eq!(
        actual.to_string(),
        expected.error_type,
        "error test case {tc_id} returned unexpected error type",
    );

    if let Some(participant) = expected.participant {
        assert_eq!(
            actual_participant(actual),
            Some(participant),
            "error test case {tc_id} returned unexpected participant",
        );
    }

    if let Some(participant1) = expected.participant1 {
        assert_eq!(
            actual_duplicate_participants(actual).map(|(participant1, _)| participant1),
            Some(participant1),
            "error test case {tc_id} returned unexpected first duplicate participant",
        );
    }

    if let Some(participant2) = expected.participant2 {
        assert_eq!(
            actual_duplicate_participants(actual).map(|(_, participant2)| participant2),
            Some(participant2),
            "error test case {tc_id} returned unexpected second duplicate participant",
        );
    }

    if let Some(message) = &expected.message {
        let actual_message = actual_message(actual)
            .unwrap_or_else(|| panic!("error test case {tc_id} returned no error message"));
        assert!(
            actual_message.starts_with(message),
            "error test case {tc_id} returned unexpected error message prefix: expected {message:?}, got {actual_message:?}",
        );
    }
}

pub fn parse_hex_array<const N: usize>(hex: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex)?;
    ensure!(bytes.len() == N, "invalid hex length");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_point(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    let point = decompress_default(&bytes).context("invalid compressed point")?;
    ensure!(!bool::from(point.is_identity()), "point is identity");
    Ok(point)
}

fn parse_point_with_infinity(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    if bytes == [0u8; 33] {
        Ok(ProjectivePoint::IDENTITY)
    } else {
        parse_point(bytes)
    }
}

fn actual_participant(error: &ChillDkgError) -> Option<usize> {
    match error {
        ChillDkgError::FaultyParticipantError { participant, .. }
        | ChillDkgError::FaultyParticipantOrCoordinatorError { participant, .. }
        | ChillDkgError::InvalidHostPubkeyError { participant }
        | ChillDkgError::InvalidSignatureInCertificateError { participant } => Some(*participant),
        _ => None,
    }
}

fn actual_duplicate_participants(error: &ChillDkgError) -> Option<(usize, usize)> {
    match error {
        ChillDkgError::DuplicateHostPubkeyError {
            participant1,
            participant2,
        } => Some((*participant1, *participant2)),
        _ => None,
    }
}

fn actual_message(error: &ChillDkgError) -> Option<&str> {
    match error {
        ChillDkgError::ProtocolError(message)
        | ChillDkgError::FaultyCoordinatorError(message)
        | ChillDkgError::UnknownFaultyParticipantOrCoordinatorError(message)
        | ChillDkgError::MsgParseError(message)
        | ChillDkgError::HostSeckeyError(message)
        | ChillDkgError::SessionParamsError(message)
        | ChillDkgError::RecoveryDataError(message)
        | ChillDkgError::SecshareSumError(message)
        | ChillDkgError::ValueError(message)
        | ChillDkgError::IndexError(message)
        | ChillDkgError::RuntimeError(message) => Some(message),
        ChillDkgError::FaultyParticipantError { message, .. }
        | ChillDkgError::FaultyParticipantOrCoordinatorError { message, .. } => Some(message),
        _ => None,
    }
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
    out
}
