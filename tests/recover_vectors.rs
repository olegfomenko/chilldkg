#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{
    ExpectedError, Params, assert_expected_error, parse_host_pubkeys, parse_point_hex,
    parse_scalar_hex,
};
use anyhow::{Context, Result, ensure};
use chilldkg::coordinator::CoordinatorDKGOutput;
use chilldkg::coordinator::recovery::recover as recover_coordinator;
use chilldkg::crypto::schnorr::SchnorrSignature;
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::RecoveryData;
use chilldkg::party::DKGOutput;
use chilldkg::party::recovery::recover as recover_participant;
use k256::ProjectivePoint;
use serde::Deserialize;

pub mod common;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    threshold: usize,
    n: usize,
    hostseckey: Option<String>,
    recovery_data: String,
    expected_output: ExpectedOutput,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    threshold: usize,
    n: usize,
    hostseckey: Option<String>,
    recovery_data: String,
    expected_error: ExpectedError,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutput {
    dkg_output: ExpectedDkgOutput,
    params: Params,
}

#[derive(Debug, Deserialize)]
struct ExpectedDkgOutput {
    secshare: Option<String>,
    threshold_pubkey: String,
    pubshares: Vec<String>,
}

#[test]
fn test_recover_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in &vectors.valid_test_cases {
        if let Some(hostseckey) = case.hostseckey.as_deref() {
            let actual =
                run_participant_recover(hostseckey, &case.recovery_data, case.threshold, case.n)
                    .context(format!("valid test case {} failed", case.tc_id))?;

            assert_expected_participant_output(&actual, hostseckey, &case.expected_output)?;
        } else {
            let actual = run_coordinator_recover(&case.recovery_data, case.threshold, case.n)
                .context(format!("valid test case {} failed", case.tc_id))?;

            assert_expected_coordinator_output(&actual, &case.expected_output)?;
        };
    }

    for case in &vectors.error_test_cases {
        let err = match case.hostseckey.as_deref() {
            Some(hostseckey) => {
                run_participant_recover(hostseckey, &case.recovery_data, case.threshold, case.n)
                    .err()
            }
            None => run_coordinator_recover(&case.recovery_data, case.threshold, case.n).err(),
        }
        .context("error test case unexpectedly succeeded")?;

        let actual_error: &ChillDkgError = (&err).try_into().context(format!(
            "error test case {} returned untyped error",
            case.tc_id
        ))?;

        assert_expected_error(actual_error, &case.expected_error, case.tc_id);
    }

    Ok(())
}

fn load_vectors() -> Result<VectorFile> {
    let vectors: VectorFile = serde_json::from_str(include_str!("vectors/recover_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_participant_recover(
    hostseckey_hex: &str,
    recovery_data_hex: &str,
    threshold: usize,
    n: usize,
) -> Result<DKGOutput> {
    let s = parse_scalar_hex(hostseckey_hex)?;
    let recovery_data = split_recovery_data(recovery_data_hex, threshold, n)?;
    recover_participant(s, &recovery_data)
}

fn run_coordinator_recover(
    recovery_data_hex: &str,
    threshold: usize,
    n: usize,
) -> Result<CoordinatorDKGOutput> {
    let recovery_data = split_recovery_data(recovery_data_hex, threshold, n)?;
    recover_coordinator(&recovery_data)
}

fn split_recovery_data(hex: &str, threshold: usize, n: usize) -> Result<RecoveryData> {
    let bytes = hex::decode(hex)?;
    let transcript_len = 4 + 33 * threshold + (33 + 33 + 32) * n;
    let cert = bytes[transcript_len..]
        .chunks_exact(64)
        .map(|chunk| Ok(chunk.try_into()?))
        .collect::<Result<Vec<SchnorrSignature>>>()?;

    Ok(RecoveryData {
        transcript: bytes[..transcript_len].to_vec(),
        cert,
    })
}

fn assert_expected_participant_output(
    actual: &DKGOutput,
    hostseckey_hex: &str,
    expected: &ExpectedOutput,
) -> Result<()> {
    let s = parse_scalar_hex(hostseckey_hex)?;
    let expected_host_pubkeys = parse_host_pubkeys(&expected.params)?;
    assert_eq!(
        actual.idx,
        expected_host_pubkeys
            .iter()
            .position(|P_i| *P_i == ProjectivePoint::GENERATOR * s)
            .context("host secret key does not match expected params")?
    );
    assert_eq!(actual.t, expected.params.t);
    assert_eq!(
        actual.secshare,
        parse_scalar_hex(
            expected
                .dkg_output
                .secshare
                .as_deref()
                .context("participant recovery output must include a secshare")?
        )?
    );
    assert_eq!(
        actual.threshold_pubkey,
        parse_point_hex(&expected.dkg_output.threshold_pubkey)?
    );

    let expected_pubshares = expected
        .dkg_output
        .pubshares
        .iter()
        .map(|pubshare| parse_point_hex(pubshare))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(actual.pubshares, expected_pubshares);

    Ok(())
}

fn assert_expected_coordinator_output(
    actual: &CoordinatorDKGOutput,
    expected: &ExpectedOutput,
) -> Result<()> {
    ensure!(
        expected.dkg_output.secshare.is_none(),
        "coordinator recovery output must not include a secshare"
    );
    assert_eq!(actual.t, expected.params.t);
    assert_eq!(
        actual.threshold_pubkey,
        parse_point_hex(&expected.dkg_output.threshold_pubkey)?
    );

    let expected_pubshares = expected
        .dkg_output
        .pubshares
        .iter()
        .map(|pubshare| parse_point_hex(pubshare))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(actual.pubshares, expected_pubshares);

    Ok(())
}
