#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::coordinator::{CoordinatorDkgOutput, CoordinatorInitialState, CoordinatorState};
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::{CoordinatorMsg2, RecoveryData};
use serde::Deserialize;

use crate::common::{
    ExpectedError, Params, assert_expected_error, parse_coordinator_msg1, parse_host_pubkeys,
    parse_participant_msg1, parse_participant_msg2, parse_point_hex, serialize_coordinator_msg2,
    serialize_recovery_data,
};

pub mod common;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    params: Params,
    pmsgs1: Vec<String>,
    cmsg1: String,
    pmsg2_pool: Vec<String>,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    pmsg2_indices: Vec<usize>,
    expected_output: ExpectedOutput,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    pmsg2_indices: Vec<usize>,
    expected_error: ExpectedError,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutput {
    cmsg2: String,
    dkg_output: ExpectedDkgOutput,
    recovery_data: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedDkgOutput {
    secshare: Option<String>,
    threshold_pubkey: String,
    pubshares: Vec<String>,
}

#[test]
fn test_coordinator_finalize_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in &vectors.valid_test_cases {
        let (cmsg2, dkg_output, recovery_data) =
            run_coordinator_finalize(&vectors, &case.pmsg2_indices)
                .context(format!("valid test case {} failed", case.tc_id))?;

        assert_expected_output(
            &cmsg2,
            &dkg_output,
            &recovery_data,
            &case.expected_output,
            &vectors.params,
        )?;
    }

    for case in &vectors.error_test_cases {
        let err = run_coordinator_finalize(&vectors, &case.pmsg2_indices)
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
        serde_json::from_str(include_str!("vectors/coordinator_finalize_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_coordinator_finalize(
    vectors: &VectorFile,
    pmsg2_indices: &[usize],
) -> Result<(CoordinatorMsg2, CoordinatorDkgOutput, RecoveryData)> {
    let host_pubkeys = parse_host_pubkeys(&vectors.params)?;
    let initial = CoordinatorInitialState::new(host_pubkeys, vectors.params.t)?;
    let n = initial.host_pubkeys.len();
    let pmsgs1 = vectors
        .pmsgs1
        .iter()
        .map(|pmsg1| parse_participant_msg1(pmsg1, initial.t, n))
        .collect::<Result<Vec<_>>>()?;

    let (next, cmsg1) = initial.next(pmsgs1)?;
    assert_eq!(
        cmsg1,
        parse_coordinator_msg1(&vectors.cmsg1, vectors.params.t, n)?
    );

    let pmsgs2 = pmsg2_indices
        .iter()
        .map(|idx| parse_participant_msg2(&vectors.pmsg2_pool[*idx]))
        .collect::<Result<Vec<_>>>()?;

    let (_, output) = next
        .context("missing coordinator step1 state")?
        .next(pmsgs2)?;

    Ok(output)
}

fn assert_expected_output(
    cmsg2: &CoordinatorMsg2,
    dkg_output: &CoordinatorDkgOutput,
    recovery_data: &RecoveryData,
    expected: &ExpectedOutput,
    params: &Params,
) -> Result<()> {
    assert_eq!(
        serialize_coordinator_msg2(cmsg2),
        hex::decode(&expected.cmsg2)?
    );
    assert!(expected.dkg_output.secshare.is_none());
    assert_eq!(dkg_output.t, params.t);
    assert_eq!(
        dkg_output.threshold_pubkey,
        parse_point_hex(&expected.dkg_output.threshold_pubkey)?
    );

    let expected_pubshares = expected
        .dkg_output
        .pubshares
        .iter()
        .map(|pubshare| parse_point_hex(pubshare))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(dkg_output.pubshares, expected_pubshares);

    assert_eq!(
        serialize_recovery_data(recovery_data),
        hex::decode(&expected.recovery_data)?,
    );

    Ok(())
}
