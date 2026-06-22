#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::common::{
    ExpectedError, Params, assert_expected_error, get_idx, parse_hex_array, parse_host_pubkeys,
    parse_participant_msg1, parse_scalar_hex,
};
use anyhow::{Context, Result, ensure};
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::ParticipantMsg1;
use chilldkg::party::{ParticipantInitialState, ParticipantState, ParticipantStep1State};
use k256::{ProjectivePoint, Scalar};
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
    expected_error: ExpectedError,
}

#[test]
fn test_participant_step1_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in vectors.valid_test_cases {
        let (_, actual) = run_participant_step1(&case.hostseckey, &case.params, &case.random)
            .context(format!("valid test case {} failed", case.tc_id))?;

        let expected = parse_participant_msg1(
            &case.expected_pmsg1,
            case.params.t,
            case.params.hostpubkeys.len(),
        )?;

        assert_eq!(actual, expected);
    }

    for case in vectors.error_test_cases {
        let err = run_participant_step1(&case.hostseckey, &case.params, &case.random)
            .expect_err("error test case unexpectedly succeeded");

        let actual_error: &ChillDkgError = (&err).try_into().context(format!(
            "error test case {} returned untyped error",
            case.tc_id
        ))?;

        assert_expected_error(actual_error, &case.expected_error, case.tc_id);
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
) -> Result<(ParticipantStep1State, ParticipantMsg1)> {
    let s = parse_scalar_hex(hostseckey_hex)
        .map_err(|_| ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()))?;
    if s == Scalar::ZERO {
        return Err(ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()).into());
    }

    let host_pubkeys = parse_host_pubkeys(&params)?;
    let host_pubkey = ProjectivePoint::GENERATOR * s;
    let idx = get_idx(&host_pubkeys, &host_pubkey)?;
    let initial = ParticipantInitialState { idx, s };
    let (next, ()) = initial.next((host_pubkeys, params.t))?;
    let (next, msg) = next
        .context("missing participant params state")?
        .next(parse_hex_array(random_hex).map_err(|_| ChillDkgError::RandomnessError)?)?;

    Ok((next.context("missing participant step1 state")?, msg))
}
