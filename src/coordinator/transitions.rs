#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::coordinator::{
    CoordinatorDkgOutput, CoordinatorInitialState, CoordinatorState, CoordinatorStep1State,
};
use crate::crypto::certeq::{get_certeq_transcript, verify_certeq_cert};
use crate::crypto::ec::{eval_pub_share, tap_tweak_no_script};
use crate::msg::{
    CoordinatorMsg1, CoordinatorMsg2, ParticipantMsg1, ParticipantMsg2, RecoveryData,
};
use anyhow::{Context, Result, ensure};
use k256::ProjectivePoint;

impl CoordinatorState for CoordinatorInitialState {
    type Message = Vec<ParticipantMsg1>;
    type Next = CoordinatorStep1State;
    type Output = CoordinatorMsg1;

    fn next(self, msgs: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        self.validate_participant_msg1(&msgs)?;

        let coms_to_secrets: Vec<ProjectivePoint> =
            msgs.iter().map(|msg| msg.commitment[0]).collect();

        let sum_commitment: Vec<ProjectivePoint> = (0..self.t)
            .map(|i| msgs.iter().map(|p_msg| p_msg.commitment[i]).sum())
            .collect();

        let pops = msgs.iter().map(|p_msg| p_msg.pop).collect();

        let pubnonces = msgs.iter().map(|p_msg| p_msg.pubnonce).collect();

        let enc_secshares = (0..self.host_pubkeys.len())
            .map(|i| msgs.iter().map(|p_msg| p_msg.enc_shares[i]).sum())
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
    type Message = Vec<ParticipantMsg2>;
    type Next = Self;
    type Output = (CoordinatorMsg2, CoordinatorDkgOutput, RecoveryData);

    fn next(self, msgs: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        ensure!(
            msgs.len() == self.host_pubkeys.len(),
            "Coordinator step 2 received invalid number of participant messages"
        );

        let coordinator_msg = CoordinatorMsg2 {
            cert: msgs.into_iter().map(|p_msg| p_msg.sig).collect(),
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
