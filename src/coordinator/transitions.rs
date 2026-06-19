#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::coordinator::{
    CoordinatorDkgOutput, CoordinatorInitialState, CoordinatorState, CoordinatorStep1State,
};
use crate::crypto::certeq::{get_certeq_transcript, verify_certeq_cert};
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::msg::{
    CoordinatorMsg1, CoordinatorMsg2, CoordinatorStep1TransitionMsg, CoordinatorStep2TransitionMsg,
    RecoveryData,
};
use anyhow::{Context, Result, ensure};
use k256::ProjectivePoint;
use k256::elliptic_curve::Group;

fn validate_participant_msg1(
    msg: &CoordinatorStep1TransitionMsg,
    t: usize,
    n: usize,
) -> Result<()> {
    ensure!(
        msg.participant_msgs.len() == n,
        "Coordinator step 1 received invalid number of participant messages"
    );

    for (i, participant_msg) in msg.participant_msgs.iter().enumerate() {
        ensure!(
            participant_msg.commitment.len() == t,
            "Participant {i} sent invalid number of VSS commitments"
        );
        ensure!(
            participant_msg.enc_shares.len() == n,
            "Participant {i} sent invalid number of encrypted shares"
        );
        ensure!(
            !bool::from(participant_msg.pubnonce.is_identity()),
            "Participant {i} sent invalid public nonce"
        );

        for (k, C_k) in participant_msg.commitment.iter().enumerate() {
            ensure!(
                !bool::from(C_k.is_identity()),
                "Participant {i} sent invalid VSS commitment at coefficient {k}"
            );
        }
    }

    Ok(())
}

impl CoordinatorState for CoordinatorInitialState {
    type Message = CoordinatorStep1TransitionMsg;
    type Next = CoordinatorStep1State;
    type Output = CoordinatorMsg1;

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        validate_participant_msg1(&msg, self.t, self.host_pubkeys.len())?;

        let coms_to_secrets: Vec<ProjectivePoint> = msg
            .participant_msgs
            .iter()
            .map(|msg| msg.commitment[0])
            .collect();

        let sum_commitment: Vec<ProjectivePoint> = (0..self.t)
            .map(|i| {
                msg.participant_msgs
                    .iter()
                    .map(|p_msg| p_msg.commitment[i])
                    .sum()
            })
            .collect();

        let pops = msg.participant_msgs.iter().map(|p_msg| p_msg.pop).collect();

        let pubnonces = msg
            .participant_msgs
            .iter()
            .map(|p_msg| p_msg.pubnonce)
            .collect();

        let enc_secshares = (0..self.host_pubkeys.len())
            .map(|i| {
                msg.participant_msgs
                    .iter()
                    .map(|p_msg| p_msg.enc_shares[i])
                    .sum()
            })
            .collect();

        let coordinator_msg = CoordinatorMsg1 {
            coms_to_secrets,
            sum_coms_to_nonconst_terms: sum_commitment[1..sum_commitment.len()].to_vec(),
            pops,
            pubnonces,
            enc_secshares,
        };

        let (pubtweak, _) = tap_tweak_no_script(&sum_commitment[0])?;
        let mut sum_commitment_tweaked = sum_commitment.clone();
        sum_commitment_tweaked[0] += pubtweak;

        let threshold_pubkey = sum_commitment_tweaked[0];
        let pubshares = (0..self.host_pubkeys.len())
            .map(|i| eval_pub_share(&sum_commitment_tweaked, i))
            .collect();

        let transcript = get_certeq_transcript(
            self.t,
            &sum_commitment,
            &self.host_pubkeys,
            &coordinator_msg.pubnonces,
            &coordinator_msg.enc_secshares,
        );

        let dkg_output = CoordinatorDkgOutput {
            t: self.t,
            threshold_pubkey,
            pubshares,
        };

        let next_stage = CoordinatorStep1State {
            t: self.t,
            host_pubkeys: self.host_pubkeys,
            transcript,
            dkg_output,
        };

        Ok((Some(next_stage), coordinator_msg))
    }
}

impl CoordinatorState for CoordinatorStep1State {
    type Message = CoordinatorStep2TransitionMsg;
    type Next = Self;
    type Output = (CoordinatorMsg2, CoordinatorDkgOutput, RecoveryData);

    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        ensure!(
            msg.participant_msgs.len() == self.host_pubkeys.len(),
            "Coordinator step 2 received invalid number of participant messages"
        );

        let coordinator_msg = CoordinatorMsg2 {
            cert: msg
                .participant_msgs
                .into_iter()
                .map(|p_msg| p_msg.sig)
                .collect(),
        };

        verify_certeq_cert(&self.host_pubkeys, &self.transcript, &coordinator_msg.cert)
            .context("Coordinator step 2 received invalid CertEq certificate")?;

        let recovery_data = RecoveryData {
            transcript: self.transcript,
            cert: coordinator_msg.cert.clone(),
        };

        Ok((None, (coordinator_msg, self.dkg_output, recovery_data)))
    }
}
