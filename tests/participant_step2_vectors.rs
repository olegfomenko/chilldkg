#![allow(dead_code, non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::errors::ChillDkgError;
use serde::Deserialize;
use chilldkg::msg::ParticipantMsg2;
use chilldkg::party::ParticipantState;
use crate::common::{assert_expected_error, parse_coordinator_msg1, parse_hex_array, parse_participant_msg1, parse_participant_msg2, run_participant_step1, ExpectedError, Params};

pub mod common;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    params: Params,
    hostseckey: String,
    random: String,
    aux_rand: String,
    pmsg1: String,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    cmsg1: String,
    expected_pmsg2: String,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    cmsg1: String,
    expected_error: ExpectedError,
}

#[test]
fn test_participant_step2_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in &vectors.valid_test_cases {
        let actual = run_participant_step2(&vectors, &case.cmsg1)
            .context(format!("valid test case {} failed", case.tc_id))?;

        assert_eq!(actual, parse_participant_msg2(&case.expected_pmsg2)?);
    }

    for case in &vectors.error_test_cases {
        let err = run_participant_step2(&vectors, &case.cmsg1)
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
        serde_json::from_str(include_str!("vectors/participant_step2_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_participant_step2(vectors: &VectorFile, cmsg1_hex: &str) -> Result<ParticipantMsg2> {
    let (state, pmsg1) =
        run_participant_step1(&vectors.hostseckey, &vectors.params, &vectors.random)?;
    assert_eq!(
        pmsg1,
        parse_participant_msg1(
            &vectors.pmsg1,
            vectors.params.t,
            vectors.params.hostpubkeys.len(),
        )?
    );

    let cmsg1 = parse_coordinator_msg1(
        cmsg1_hex,
        vectors.params.t,
        vectors.params.hostpubkeys.len(),
    )?;
    let aux_rand = parse_hex_array(&vectors.aux_rand)?;
    let (_, pmsg2) = state.next((cmsg1, aux_rand))?;

    Ok(pmsg2)
}
