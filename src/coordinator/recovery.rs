#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::coordinator::{CoordinatorDKGOutput, CoordinatorInitialState};
use crate::crypto::certeq::{parse_certeq_transcript, verify_certeq_certificate};
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::errors::ChillDkgError;
use crate::msg::RecoveryData;
use anyhow::Result;

/// Recover the coordinator's public DKG output from successful-session recovery data.
pub fn recover(recovery_data: &RecoveryData) -> Result<CoordinatorDKGOutput> {
    let n = recovery_data.cert.len();

    let (t, mut sum_commitment, host_pubkeys, _, _) =
        parse_certeq_transcript(&recovery_data.transcript, n).map_err(|err| {
            ChillDkgError::RecoveryDataError(match <&ChillDkgError>::try_from(&err) {
                Ok(ChillDkgError::InvalidHostPubkeyError { .. }) => {
                    "Invalid session parameters in recovery data".to_owned()
                }
                _ => "Failed to deserialize recovery data".to_owned(),
            })
        })?;

    let state = CoordinatorInitialState::new(host_pubkeys, t).map_err(|_| {
        ChillDkgError::RecoveryDataError("Invalid session parameters in recovery data".to_owned())
    })?;

    verify_certeq_certificate(
        &state.host_pubkeys,
        &recovery_data.transcript,
        &recovery_data.cert,
    )
    .map_err(|_| {
        ChillDkgError::RecoveryDataError("Invalid certificate in recovery data".to_owned())
    })?;

    let (pubtweak, _) = tap_tweak_no_script(&sum_commitment[0])?;
    sum_commitment[0] += pubtweak;

    Ok(CoordinatorDKGOutput {
        t: state.t,
        threshold_pubkey: sum_commitment[0],
        pubshares: (0..n)
            .map(|idx| eval_pub_share(&sum_commitment, idx))
            .collect(),
    })
}
