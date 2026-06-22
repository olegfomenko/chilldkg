use anyhow::{Context, Result, ensure};
use chilldkg::chill_dkg_ensure;
use chilldkg::crypto::ec::{CompressedPubKey, decompress_default};
use chilldkg::crypto::scalar_from_bytes;
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::{CoordinatorMsg1, ParticipantMsg1, ParticipantMsg2};
use chilldkg::party::{ParticipantInitialState, ParticipantState, ParticipantStep1State};
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

pub fn run_participant_step1(
    hostseckey_hex: &str,
    params: &Params,
    random_hex: &str,
) -> Result<(ParticipantStep1State, ParticipantMsg1)> {
    let s = parse_hex_array(hostseckey_hex)
        .and_then(scalar_from_bytes)
        .map_err(|_| ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()))?;
    if s == Scalar::ZERO {
        return Err(ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()).into());
    }

    let host_pubkeys: Vec<ProjectivePoint> = params
        .hostpubkeys
        .iter()
        .enumerate()
        .map(|(participant, hex)| {
            parse_hex_array(hex)
                .and_then(parse_point)
                .map_err(|_| ChillDkgError::InvalidHostPubkeyError { participant }.into())
        })
        .collect::<Result<Vec<_>>>()?;

    let host_pubkey = ProjectivePoint::GENERATOR * s;
    let idx = host_pubkeys
        .iter()
        .position(|P_i| *P_i == host_pubkey)
        .ok_or_else(|| {
            ChillDkgError::HostSeckeyError(
                "Host secret key does not match any host public key".to_owned(),
            )
        })?;

    let initial = ParticipantInitialState { idx, s };
    let (next, ()) = initial.next((host_pubkeys, params.t))?;
    let (next, msg) = next
        .context("missing participant params state")?
        .next(parse_hex_array(random_hex).map_err(|_| ChillDkgError::RandomnessError)?)?;

    Ok((next.context("missing participant step1 state")?, msg))
}

pub fn parse_participant_msg1(hex: &str, t: usize, n: usize) -> Result<ParticipantMsg1> {
    let bytes = hex::decode(hex)?;
    ensure!(
        bytes.len() == 33 * t + 64 + 33 + 32 * n,
        "invalid pmsg1 length"
    );

    let mut offset = 0;
    let commitment = (0..t)
        .map(|_| parse_point(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;
    let pop = take(&bytes, &mut offset);
    let pubnonce = parse_point(take(&bytes, &mut offset))?;
    let enc_shares = (0..n)
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

    chill_dkg_ensure!(
        bytes.len() >= 33 * n,
        ChillDkgError::FaultyCoordinatorError("missing commitments to secrets".to_owned()),
    );
    let coms_to_secrets = (0..n)
        .map(|_| {
            parse_point_with_infinity(take(&bytes, &mut offset)).map_err(|_| {
                ChillDkgError::FaultyCoordinatorError("invalid commitment to secret".to_owned())
                    .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    chill_dkg_ensure!(
        bytes.len() - offset >= 33 * (t - 1),
        ChillDkgError::FaultyCoordinatorError(
            "missing sum commitments to non-constant terms".to_owned()
        ),
    );
    let sum_coms_to_nonconst_terms = (0..t - 1)
        .map(|_| {
            parse_point_with_infinity(take(&bytes, &mut offset)).map_err(|_| {
                ChillDkgError::FaultyCoordinatorError(
                    "invalid sum commitment to non-constant term".to_owned(),
                )
                .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    chill_dkg_ensure!(
        bytes.len() - offset >= 64 * n,
        ChillDkgError::FaultyCoordinatorError("missing proofs of possession".to_owned()),
    );
    let pops = (0..n).map(|_| take(&bytes, &mut offset)).collect();

    chill_dkg_ensure!(
        bytes.len() - offset >= 33 * n,
        ChillDkgError::FaultyCoordinatorError("missing public nonces".to_owned()),
    );
    let pubnonce_bytes: Vec<CompressedPubKey> = (0..n).map(|_| take(&bytes, &mut offset)).collect();

    chill_dkg_ensure!(
        bytes.len() - offset >= 32 * n,
        ChillDkgError::FaultyCoordinatorError("missing encrypted secret shares".to_owned()),
    );
    let enc_secshares = (0..n)
        .map(|_| {
            scalar_from_bytes(take(&bytes, &mut offset)).map_err(|_| {
                ChillDkgError::FaultyCoordinatorError("invalid encrypted secret shares".to_owned())
                    .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    chill_dkg_ensure!(
        offset == bytes.len(),
        ChillDkgError::FaultyCoordinatorError("incorrect input bytes length".to_owned()),
    );

    let pubnonces = pubnonce_bytes
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            parse_point(bytes).map_err(|_| {
                ChillDkgError::FaultyCoordinatorError(format!("invalid public nonce at index {i}"))
                    .into()
            })
        })
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
        assert_eq!(
            actual_message(actual),
            Some(message.as_str()),
            "error test case {tc_id} returned unexpected error message",
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
