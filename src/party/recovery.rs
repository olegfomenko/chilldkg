#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::{CertEQVerifier, parse_certeq_transcript};
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::crypto::enc::decrypt;
use crate::crypto::schnorr::SchnorrVerifier;
use crate::errors::ChillDkgError;
use crate::msg::RecoveryData;
use crate::party::transitions::serialize_enc_context;
use crate::party::{DKGOutput, ParticipantInitialState};
use anyhow::{Context, Result};
use k256::{ProjectivePoint, Scalar};

/// Recover this participant's DKG output from successful-session recovery data.
pub fn recover(s: Scalar, recovery_data: &RecoveryData) -> Result<DKGOutput> {
    let n = recovery_data.cert.len();

    let (t, sum_commitment, host_pubkeys, pubnonces, enc_secshares) =
        parse_certeq_transcript(&recovery_data.transcript, n).map_err(|_| {
            ChillDkgError::RecoveryDataError("Failed to deserialize recovery data".to_owned())
        })?;

    let initial_state = ParticipantInitialState { s };
    let idx = initial_state.validate_session_params(&host_pubkeys, t)?;

    for i in 0..host_pubkeys.len() {
        if let Err(err) = CertEQVerifier::new(host_pubkeys[i], &recovery_data.transcript, i)
            .verify(recovery_data.cert[i])
        {
            return Err(ChillDkgError::FaultyParticipantOrCoordinatorError {
                participant: i,
                message: format!("Participant has provided an invalid signature for the certificate, error = {:?}", err),
            }.into());
        }
    }

    let (pubtweak, tweak) = tap_tweak_no_script(&sum_commitment[0])?;

    let mut sum_commitment_tweaked = sum_commitment;
    sum_commitment_tweaked[0] += pubtweak;

    let threshold_pubkey = sum_commitment_tweaked[0];

    let pubshares: Vec<ProjectivePoint> = (0..n)
        .map(|idx| eval_pub_share(&sum_commitment_tweaked, idx))
        .collect();

    let enc_context = serialize_enc_context(t, &host_pubkeys);
    let mut secshare = decrypt(&s, &pubnonces, &enc_context, idx, &enc_secshares[idx])
        .context("failed to decrypt recovered secret share")?;
    secshare += tweak;

    chill_dkg_ensure!(
        ProjectivePoint::GENERATOR * secshare == pubshares[idx],
        ChillDkgError::RecoveryDataError(
            "Recovered secret share does not match public share".to_owned()
        ),
    );

    Ok(DKGOutput {
        idx,
        t,
        secshare,
        threshold_pubkey,
        pubshares,
    })
}
