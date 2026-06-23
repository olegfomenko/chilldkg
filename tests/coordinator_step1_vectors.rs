#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::coordinator::{CoordinatorInitialState, CoordinatorState};
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::CoordinatorMsg1;
use serde::Deserialize;

use crate::common::{
    ExpectedError, Params, assert_expected_error, parse_coordinator_msg1, parse_host_pubkeys,
    parse_participant_msg1,
};

pub mod common;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    pmsg1_pool: Vec<String>,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    pmsg1_indices: Vec<usize>,
    params: Params,
    expected_cmsg1: String,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    pmsg1_indices: Vec<usize>,
    params: Params,
    expected_error: ExpectedError,
}

#[test]
fn test_coordinator_step1_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in &vectors.valid_test_cases {
        let actual = run_coordinator_step1(&vectors.pmsg1_pool, &case.pmsg1_indices, &case.params)
            .context(format!("valid test case {} failed", case.tc_id))?;

        let expected = parse_coordinator_msg1(
            &case.expected_cmsg1,
            case.params.t,
            case.params.hostpubkeys.len(),
        )?;

        assert_eq!(actual, expected);
    }

    for case in &vectors.error_test_cases {
        let err = run_coordinator_step1(&vectors.pmsg1_pool, &case.pmsg1_indices, &case.params)
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
        serde_json::from_str(include_str!("vectors/coordinator_step1_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_coordinator_step1(
    pmsg1_pool: &[String],
    pmsg1_indices: &[usize],
    params: &Params,
) -> Result<CoordinatorMsg1> {
    let host_pubkeys = parse_host_pubkeys(params)?;
    let initial = CoordinatorInitialState::new(host_pubkeys, params.t)?;
    let n = initial.host_pubkeys.len();
    let pmsgs1 = pmsg1_indices
        .iter()
        .map(|idx| parse_participant_msg1(&pmsg1_pool[*idx], initial.t, n))
        .collect::<Result<Vec<_>>>()?;

    let (_, cmsg1) = initial.next(pmsgs1)?;

    Ok(cmsg1)
}
