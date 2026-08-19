#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::certeq::verify_certeq_certificate;
use crate::crypto::curve::{Curve, CurvePoint};
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::crypto::enc::decrypt;
use crate::errors::{ChillDkgError, Result};
use crate::msg::RecoveryData;
use crate::party::transitions::serialize_enc_context;
use crate::party::{DKGOutput, ParticipantInitialState};

/// Recover this participant's DKG output from successful-session recovery data.
pub fn recover<C: Curve>(s: &C::Scalar, recovery_data: &RecoveryData<C>) -> Result<DKGOutput<C>> {
    let transcript = &recovery_data.transcript;
    let n = transcript.host_pubkeys.len();
    let t = transcript.t;

    let idx = ParticipantInitialState::<C> { s: *s }
        .validate_session_params(&transcript.host_pubkeys, t)
        .map_err(|err| match err {
            ChillDkgError::HostSeckeyError(_) => ChillDkgError::HostSeckeyError(
                "Host secret key does not match any host public key in the recovery data"
                    .to_owned(),
            ),
            _ => ChillDkgError::RecoveryDataError(
                "Invalid session parameters in recovery data".to_owned(),
            ),
        })?;

    verify_certeq_certificate::<C>(transcript, &recovery_data.cert).map_err(|_| {
        ChillDkgError::RecoveryDataError("Invalid certificate in recovery data".to_owned())
    })?;

    let (pubtweak, tweak) = tap_tweak_no_script::<C>(&transcript.sum_commitment[0])?;

    let mut sum_commitment_tweaked = transcript.sum_commitment.clone();
    sum_commitment_tweaked[0] += pubtweak;

    let threshold_pubkey = sum_commitment_tweaked[0];

    let pubshares: Vec<C::Point> = (0..n)
        .map(|idx| eval_pub_share::<C>(&sum_commitment_tweaked, idx))
        .collect();

    let enc_context = serialize_enc_context::<C>(t, &transcript.host_pubkeys);
    let mut secshare = decrypt::<C>(
        s,
        &transcript.pubnonces,
        &enc_context,
        idx,
        &transcript.enc_secshares[idx],
    )?;
    *secshare += tweak;

    chill_dkg_ensure!(
        C::Point::GENERATOR * *secshare == pubshares[idx],
        ChillDkgError::RecoveryDataError(
            "Recovered secret share does not match public share".to_owned()
        ),
    );

    Ok(DKGOutput {
        idx,
        t,
        secshare: *secshare,
        threshold_pubkey,
        pubshares,
    })
}
