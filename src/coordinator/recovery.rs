#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::coordinator::{CoordinatorDKGOutput, CoordinatorInitialState};
use crate::crypto::certeq::verify_certeq_certificate;
use crate::crypto::curve::Curve;
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::errors::{ChillDkgError, Result};
use crate::msg::RecoveryData;

/// Recover the coordinator's public DKG output from successful-session recovery data.
pub fn recover<C: Curve>(recovery_data: &RecoveryData<C>) -> Result<CoordinatorDKGOutput<C>> {
    let transcript = &recovery_data.transcript;

    CoordinatorInitialState::<C>::new(transcript.host_pubkeys.clone(), transcript.t).map_err(
        |_| {
            ChillDkgError::RecoveryDataError(
                "Invalid session parameters in recovery data".to_owned(),
            )
        },
    )?;

    verify_certeq_certificate::<C>(transcript, &recovery_data.cert).map_err(|_| {
        ChillDkgError::RecoveryDataError("Invalid certificate in recovery data".to_owned())
    })?;

    let mut sum_commitment = transcript.sum_commitment.clone();
    let (pubtweak, _) = tap_tweak_no_script::<C>(&sum_commitment[0])?;
    sum_commitment[0] += pubtweak;

    Ok(CoordinatorDKGOutput {
        t: transcript.t,
        threshold_pubkey: sum_commitment[0],
        pubshares: (0..transcript.n())
            .map(|idx| eval_pub_share::<C>(&sum_commitment, idx))
            .collect(),
    })
}
