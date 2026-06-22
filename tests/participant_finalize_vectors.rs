#![allow(dead_code, non_snake_case)] // Uppercase identifiers denote curve points.

use anyhow::{Context, Result, ensure};
use chilldkg::errors::ChillDkgError;
use chilldkg::msg::RecoveryData;
use chilldkg::party::{DKGOutput, ParticipantInitialState, ParticipantState};
use k256::{ProjectivePoint, Scalar};
use serde::Deserialize;

use crate::common::{
    ExpectedError, Params, assert_expected_error, get_idx, parse_coordinator_msg1,
    parse_coordinator_msg2, parse_hex_array, parse_host_pubkeys, parse_participant_msg1,
    parse_participant_msg2, parse_point_hex, parse_scalar_hex,
};

pub mod common;

#[derive(Debug, Deserialize)]
struct VectorFile {
    total_tests: usize,
    params: Params,
    hostseckey: String,
    random: String,
    aux_rand: String,
    pmsg1: String,
    cmsg1: String,
    pmsg2: String,
    valid_test_cases: Vec<ValidCase>,
    error_test_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct ValidCase {
    tc_id: usize,
    cmsg2: String,
    expected_output: ExpectedOutput,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    tc_id: usize,
    cmsg2: String,
    expected_error: ExpectedError,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutput {
    dkg_output: ExpectedDkgOutput,
    recovery_data: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedDkgOutput {
    secshare: String,
    threshold_pubkey: String,
    pubshares: Vec<String>,
}

#[test]
fn test_participant_finalize_vectors() -> Result<()> {
    let vectors = load_vectors()?;

    for case in &vectors.valid_test_cases {
        let (dkg_output, recovery_data) = run_participant_finalize(&vectors, &case.cmsg2)
            .context(format!("valid test case {} failed", case.tc_id))?;

        assert_expected_output(
            &dkg_output,
            &recovery_data,
            &case.expected_output,
            &vectors.params,
        )?;
    }

    for case in &vectors.error_test_cases {
        let err = run_participant_finalize(&vectors, &case.cmsg2)
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
        serde_json::from_str(include_str!("vectors/participant_finalize_vectors.json"))?;

    ensure!(
        vectors.total_tests == vectors.valid_test_cases.len() + vectors.error_test_cases.len(),
        "invalid vector count"
    );

    Ok(vectors)
}

fn run_participant_finalize(
    vectors: &VectorFile,
    cmsg2_hex: &str,
) -> Result<(DKGOutput, RecoveryData)> {
    let s = parse_scalar_hex(&vectors.hostseckey)
        .map_err(|_| ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()))?;
    if s == Scalar::ZERO {
        return Err(ChillDkgError::HostSeckeyError("invalid host secret key".to_owned()).into());
    }

    let host_pubkeys = parse_host_pubkeys(&vectors.params)?;
    let idx = get_idx(&host_pubkeys, &(ProjectivePoint::GENERATOR * s))?;
    let initial = ParticipantInitialState { idx, s };
    let (next, ()) = initial.next((host_pubkeys, vectors.params.t))?;
    let (next, pmsg1) = next
        .context("missing participant params state")?
        .next(parse_hex_array(&vectors.random).map_err(|_| ChillDkgError::RandomnessError)?)?;
    assert_eq!(
        pmsg1,
        parse_participant_msg1(
            &vectors.pmsg1,
            vectors.params.t,
            vectors.params.hostpubkeys.len(),
        )?
    );

    let cmsg1 = parse_coordinator_msg1(
        &vectors.cmsg1,
        vectors.params.t,
        vectors.params.hostpubkeys.len(),
    )?;
    let aux_rand = parse_hex_array(&vectors.aux_rand)?;
    let (next, pmsg2) = next
        .context("missing participant step1 state")?
        .next((cmsg1, aux_rand))?;
    assert_eq!(pmsg2, parse_participant_msg2(&vectors.pmsg2)?);

    let cmsg2 = parse_coordinator_msg2(cmsg2_hex, vectors.params.hostpubkeys.len())?;
    let (_, output) = next
        .context("missing participant step2 state")?
        .next(cmsg2)?;

    Ok(output)
}

fn serialize_recovery_data(recovery_data: &RecoveryData) -> Vec<u8> {
    let mut bytes = recovery_data.transcript.clone();
    for sig in &recovery_data.cert {
        bytes.extend_from_slice(sig);
    }
    bytes
}

fn assert_expected_output(
    actual: &DKGOutput,
    recovery_data: &RecoveryData,
    expected: &ExpectedOutput,
    params: &Params,
) -> Result<()> {
    assert_eq!(actual.idx, 0);
    assert_eq!(actual.t, params.t);
    assert_eq!(
        actual.secshare,
        parse_scalar_hex(&expected.dkg_output.secshare)?
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

    assert_eq!(
        serialize_recovery_data(recovery_data),
        hex::decode(&expected.recovery_data)?,
    );

    Ok(())
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
    out
}
