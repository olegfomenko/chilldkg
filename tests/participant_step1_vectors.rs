#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::crypto::ec::{CompressedPubKey, decompress_default};
use chilldkg::crypto::scalar_from_bytes;
use chilldkg::msg::ParticipantMsg1;
use chilldkg::party::{ParticipantInitialState, ParticipantState};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    hostseckey: String,
    params: Params,
    random: String,
    expected_pmsg1: String,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    hostseckey: String,
    params: Params,
    random: String,
}

#[derive(Debug, Deserialize)]
struct Params {
    hostpubkeys: Vec<String>,
    t: usize,
}

#[test]
fn test_participant_step1_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in vectors.valid_test_cases {
        let actual = run_participant_step1(&case.hostseckey, &case.params, &case.random)
            .with_context(|| format!("valid test case {} failed", case.tc_id))?;
        let expected = parse_participant_msg1(
            &case.expected_pmsg1,
            case.params.t,
            case.params.hostpubkeys.len(),
        )?;

        assert_eq!(actual, expected);
    }

    for case in vectors.error_test_cases {
        assert!(
            run_participant_step1(&case.hostseckey, &case.params, &case.random).is_err(),
            "error test case {} unexpectedly succeeded",
            case.tc_id
        );
    }

    Ok(())
}

fn load_vectors() -> Result<VectorFile> {
    let vectors: VectorFile =
        serde_json::from_str(include_str!("vectors/participant_step1_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_participant_step1(
    hostseckey_hex: &str,
    params: &Params,
    random_hex: &str,
) -> Result<ParticipantMsg1> {
    let s = scalar_from_bytes(parse_hex_array(hostseckey_hex)?)?;
    ensure!(s != Scalar::ZERO, "host secret key is zero");

    let host_pubkeys: Vec<ProjectivePoint> = params
        .hostpubkeys
        .iter()
        .map(|hex| parse_point(parse_hex_array(hex)?))
        .collect::<Result<Vec<_>>>()?;

    let host_pubkey = ProjectivePoint::GENERATOR * s;

    let idx = host_pubkeys
        .iter()
        .position(|P_i| *P_i == host_pubkey)
        .context("host secret key does not match any host public key")?;

    let initial = ParticipantInitialState { idx, s };
    let (next, ()) = initial.next((host_pubkeys, params.t))?;
    let (_, msg) = next
        .context("missing participant params state")?
        .next(parse_hex_array(random_hex)?)?;

    Ok(msg)
}

fn parse_participant_msg1(hex: &str, t: usize, n: usize) -> Result<ParticipantMsg1> {
    let bytes = hex::decode(hex)?;
    ensure!(
        bytes.len() == 33 * t + 64 + 33 + 32 * n,
        "invalid pmsg1 length"
    );

    let mut offset = 0;

    let commitment: Vec<ProjectivePoint> = (0..t)
        .map(|_| parse_point(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;

    let pop = take(&bytes, &mut offset);

    let pubnonce = parse_point(take(&bytes, &mut offset))?;

    let enc_shares: Vec<Scalar> = (0..n)
        .map(|_| scalar_from_bytes(take(&bytes, &mut offset)))
        .collect::<Result<Vec<_>>>()?;

    Ok(ParticipantMsg1 {
        commitment,
        pop,
        pubnonce,
        enc_shares,
    })
}

fn parse_point(bytes: CompressedPubKey) -> Result<ProjectivePoint> {
    let point = decompress_default(&bytes).context("invalid compressed point")?;
    ensure!(!bool::from(point.is_identity()), "point is identity");
    Ok(point)
}

fn parse_hex_array<const N: usize>(hex: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex)?;
    ensure!(bytes.len() == N, "invalid hex length");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
    out
}
