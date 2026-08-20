#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::coordinator::{CoordinatorDKGOutput, CoordinatorInitialState};
use crate::crypto::certeq::verify_certeq_certificate;
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::errors::{ChillDkgError, Result};
use crate::msg::RecoveryData;

/// Recover the coordinator's public DKG output from successful-session recovery data.
pub fn recover(recovery_data: &RecoveryData) -> Result<CoordinatorDKGOutput> {
    let transcript = &recovery_data.transcript;

    CoordinatorInitialState::new(transcript.host_pubkeys.clone(), transcript.t).map_err(|_| {
        ChillDkgError::RecoveryData("Invalid session parameters in recovery data".into())
    })?;

    verify_certeq_certificate(transcript, &recovery_data.cert)
        .map_err(|_| ChillDkgError::RecoveryData("Invalid certificate in recovery data".into()))?;

    let mut sum_commitment = transcript.sum_commitment.clone();
    let (pubtweak, _) = tap_tweak_no_script(&sum_commitment[0])?;
    sum_commitment[0] += pubtweak;

    Ok(CoordinatorDKGOutput {
        t: transcript.t,
        threshold_pubkey: sum_commitment[0],
        pubshares: (0..transcript.n())
            .map(|idx| eval_pub_share(&sum_commitment, idx))
            .collect(),
    })
}
