#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::errors::ChillDkgError;
use serde::Deserialize;
use crate::common::{assert_expected_error, parse_participant_msg1, run_participant_step1, ExpectedError, Params};

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
