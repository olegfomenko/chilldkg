//! # ChillDKG
//!
//! High-level SDK for the ChillDKG distributed key generation protocol
//! (BIP-FROST-DKG). This module wraps the lower-level state machines in
//! [`party`] and [`coordinator`] behind two driver types, [`Participant`] and
//! [`Coordinator`], that track the protocol phase for you and cannot be advanced
//! out of order.
//!
//! A session runs in three messaging rounds:
//! 1. every participant calls [`Participant::step1`] and sends its message to the
//!    coordinator, which aggregates them with [`Coordinator::step1`];
//! 2. every participant calls [`Participant::step2`] on the coordinator's reply
//!    and sends its message back, which the coordinator finalizes with
//!    [`Coordinator::step2`];
//! 3. every participant calls [`Participant::finalize`] on the coordinator's
//!    certificate to obtain its [`DKGOutput`] and
//!    [`RecoveryData`].
//!
//! See the module-level types in [`msg`] for the wire messages exchanged between
//! rounds.
//!
//! ## Handling secrets
//!
//! [`Participant::new`] returns the host secret key as a [`SecretScalar`], and
//! the per-participant secret share lives in
//! [`DKGOutput::secshare`](msg::DKGOutput::secshare). Both are long-lived secret
//! key material: store them securely and keep them wrapped in zeroizing types
//! until persisted.
//!
//! ## Handling failure
//!
//! An error from any step transitions the driver to a terminal *failed* state
//! (see [`Participant::is_failed`]).

use crate::coordinator::recovery::recover;
use crate::coordinator::{CoordinatorInitialState, CoordinatorState, CoordinatorStep1State};
use crate::crypto::SecretScalar;
use crate::errors::{ChillDkgError, Result};
use crate::msg::{
    CoordinatorDKGOutput, CoordinatorMsg1, CoordinatorMsg2, DKGOutput, ParticipantMsg1,
    ParticipantMsg2, RecoveryData,
};
use crate::party::{
    ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
};
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub mod coordinator;
pub mod crypto;
pub mod errors;
pub mod msg;
pub mod party;

/// Driver for a single participant across a full ChillDKG session.
///
/// The participant is advanced one round at a time with [`Participant::step1`],
/// [`Participant::step2`] and [`Participant::finalize`]. Each call consumes the
/// current internal state and produces the next one, so a step can never be run
/// twice or out of order; doing so returns an error and moves the participant to
/// a terminal failed state.
pub struct Participant {
    state: ParticipantStateValue,
}

enum ParticipantStateValue {
    Initial(ParticipantInitialState),
    Step1(ParticipantStep1State),
    Step2(ParticipantStep2State),
    Failed,
    Successful,
    Replaced, // An intermediate state between transitions
}

impl Participant {
    /// Creates a participant with a freshly sampled, non-zero host secret key.
    ///
    /// Returns the host secret key alongside the participant. The key is the
    /// participant's long-term identity; store it securely (it is returned as a
    /// [`SecretScalar`] so it is wiped from memory on drop) — it is required to
    /// [`recover`](Participant::recover) the DKG output later.
    pub fn new(rng: &mut impl CryptoRngCore) -> (SecretScalar, Self) {
        let state = ParticipantInitialState::new(rng);

        (
            Zeroizing::new(state.s),
            Self {
                state: ParticipantStateValue::Initial(state),
            },
        )
    }

    /// Creates a participant from an existing host secret key.
    ///
    /// Use this to resume with a persisted key instead of sampling a new one via
    /// [`new`](Participant::new). The caller is responsible for the secrecy and
    /// non-zero-ness of `scalar`.
    pub fn new_with_secret(scalar: &Scalar) -> Self {
        Self {
            state: ParticipantStateValue::Initial(ParticipantInitialState::new_with_secret(scalar)),
        }
    }

    /// Recovers a participant's DKG output from recovery data.
    ///
    /// Given the participant's host secret key and the
    /// [`RecoveryData`] produced by a successful session, this
    /// reconstructs the [`DKGOutput`] without re-running the
    /// protocol. It is the fallback a participant uses when it did not observe
    /// its own [`finalize`](Participant::finalize) but is later presented with
    /// valid recovery data.
    pub fn recover(scalar: &Scalar, recovery_data: &RecoveryData) -> Result<DKGOutput> {
        party::recovery::recover(scalar, recovery_data)
    }

    /// Runs the participant's first round.
    ///
    /// Takes the session parameters (host public keys, threshold, and per-session
    /// randomness) and produces the [`ParticipantMsg1`] to
    /// send to the coordinator. On error the participant moves to the failed
    /// state; see the crate-level note on handling failure.
    pub fn step1(
        &mut self,
        msg: <ParticipantInitialState as ParticipantState>::Message,
    ) -> Result<ParticipantMsg1> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (next, pmsg1) = Self::step1_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = next;

        Ok(pmsg1)
    }

    fn step1_inner(
        state: ParticipantStateValue,
        msg: <ParticipantInitialState as ParticipantState>::Message,
    ) -> Result<(ParticipantStateValue, ParticipantMsg1)> {
        match state {
            ParticipantStateValue::Initial(state) => {
                let (next, pmsg1) = state.next(msg)?;

                let next_state = ParticipantStateValue::Step1(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Runs the participant's second round.
    ///
    /// Takes the coordinator's aggregated first-round reply
    /// ([`CoordinatorMsg1`]) plus auxiliary randomness and
    /// produces the [`ParticipantMsg2`] to send back. On
    /// error the participant moves to the failed state.
    pub fn step2(
        &mut self,
        msg: <ParticipantStep1State as ParticipantState>::Message,
    ) -> Result<ParticipantMsg2> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (next, pmsg2) = Self::step2_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = next;

        Ok(pmsg2)
    }

    fn step2_inner(
        state: ParticipantStateValue,
        msg: <ParticipantStep1State as ParticipantState>::Message,
    ) -> Result<(ParticipantStateValue, ParticipantMsg2)> {
        match state {
            ParticipantStateValue::Step1(state) => {
                let (next, pmsg1) = state.next(msg)?;

                let next_state = ParticipantStateValue::Step2(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Completes the session for this participant.
    ///
    /// Verifies the coordinator's certificate
    /// ([`CoordinatorMsg2`]) and, on success, returns the
    /// participant's [`DKGOutput`] and the
    /// [`RecoveryData`]. The output holds the secret share and
    /// must be stored securely; the recovery data should also be persisted so the
    /// output can be [`recover`](Participant::recover)ed later. Returning an error
    /// moves the participant to the failed state but does **not** mean the session
    /// failed for the group — do not erase the host secret key on error.
    pub fn finalize(
        &mut self,
        msg: <ParticipantStep2State as ParticipantState>::Message,
    ) -> Result<(DKGOutput, RecoveryData)> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (out, recovery_data) = Self::finalize_inner(
            std::mem::replace(&mut self.state, ParticipantStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = ParticipantStateValue::Failed;
        })?;

        self.state = ParticipantStateValue::Successful;

        Ok((out, recovery_data))
    }

    fn finalize_inner(
        state: ParticipantStateValue,
        msg: <ParticipantStep2State as ParticipantState>::Message,
    ) -> Result<(DKGOutput, RecoveryData)> {
        match state {
            ParticipantStateValue::Step2(state) => {
                let (_, res) = state.next(msg)?;
                Ok(res)
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Returns `true` if a step returned an error and the participant can no
    /// longer be advanced. See the crate-level note: a failed participant does
    /// not imply the session failed for the group.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, ParticipantStateValue::Failed)
    }

    /// Returns `true` once [`finalize`](Participant::finalize) has succeeded.
    pub fn is_successful(&self) -> bool {
        matches!(self.state, ParticipantStateValue::Successful)
    }

    /// Returns `true` while the participant is still mid-session (neither failed
    /// nor successful) and can accept the next step.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            ParticipantStateValue::Initial(_)
                | ParticipantStateValue::Step1(_)
                | ParticipantStateValue::Step2(_)
                | ParticipantStateValue::Replaced
        )
    }

    fn only_active(&self) -> Result<()> {
        if !self.is_active() {
            return Err(ChillDkgError::Runtime(
                "can not not apply message to the terminal state".into(),
            ));
        }

        Ok(())
    }
}

/// Driver for the coordinator across a full ChillDKG session.
///
/// The coordinator aggregates the participants' round messages with
/// [`Coordinator::step1`] and [`Coordinator::step2`]. Like [`Participant`], it is
/// a linear state machine: steps run once, in order, and an error moves it to a
/// terminal failed state. The coordinator only ever handles public data.
pub struct Coordinator {
    state: CoordinatorStateValue,
}

#[allow(clippy::large_enum_variant)]
enum CoordinatorStateValue {
    Initial(CoordinatorInitialState),
    Step1(CoordinatorStep1State),
    Failed,
    Successful,
    Replaced, // An intermediate state between transitions
}

impl Coordinator {
    /// Creates a coordinator for a session with the given participant host
    /// public keys and threshold `t`.
    ///
    /// Returns an error if the parameters are invalid (e.g. `t` out of range or
    /// duplicate/invalid host keys).
    pub fn new(host_pubkeys: Vec<ProjectivePoint>, t: usize) -> Result<Self> {
        Ok(Self {
            state: CoordinatorStateValue::Initial(CoordinatorInitialState::new(host_pubkeys, t)?),
        })
    }

    /// Recovers the coordinator's public DKG output from recovery data.
    ///
    /// Unlike [`Participant::recover`], this needs no secret key: it reconstructs
    /// the public [`CoordinatorDKGOutput`] (threshold
    /// public key and public shares) from a successful session's
    /// [`RecoveryData`].
    pub fn recover(recovery_data: &RecoveryData) -> Result<CoordinatorDKGOutput> {
        recover(recovery_data)
    }

    /// Runs the coordinator's first round.
    ///
    /// Aggregates the participants' [`ParticipantMsg1`]
    /// messages and produces the [`CoordinatorMsg1`] to
    /// broadcast back to them. On error the coordinator moves to the failed
    /// state.
    pub fn step1(
        &mut self,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<CoordinatorMsg1> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;
        let (next, cmsg1) = Self::step1_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = CoordinatorStateValue::Failed;
        })?;

        self.state = next;

        Ok(cmsg1)
    }

    fn step1_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<(CoordinatorStateValue, CoordinatorMsg1)> {
        match state {
            CoordinatorStateValue::Initial(state) => {
                let (next, cmsg1) = state.next(msg)?;

                let next_state = CoordinatorStateValue::Step1(next.ok_or_else(|| {
                    ChillDkgError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, cmsg1))
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }
    /// Completes the session on the coordinator side.
    ///
    /// Aggregates the participants' [`ParticipantMsg2`]
    /// messages into the certificate [`CoordinatorMsg2`]
    /// (to broadcast to the participants), and returns the public
    /// [`CoordinatorDKGOutput`] and the
    /// [`RecoveryData`]. The coordinator obtains its output
    /// here, but the session is only truly successful once every participant has
    /// finalized. On error the coordinator moves to the failed state.
    pub fn step2(
        &mut self,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<(CoordinatorMsg2, CoordinatorDKGOutput, RecoveryData)> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (cmsg2, out, recovery_data) = Self::step2_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|_| {
            self.state = CoordinatorStateValue::Failed;
        })?;

        self.state = CoordinatorStateValue::Successful;

        Ok((cmsg2, out, recovery_data))
    }

    fn step2_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<(CoordinatorMsg2, CoordinatorDKGOutput, RecoveryData)> {
        match state {
            CoordinatorStateValue::Step1(state) => {
                let (_, res) = state.next(msg)?;
                Ok(res)
            }
            _ => Err(ChillDkgError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Returns `true` if a step returned an error and the coordinator can no
    /// longer be advanced.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Failed)
    }

    /// Returns `true` once [`step2`](Coordinator::step2) has succeeded.
    pub fn is_successful(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Successful)
    }

    /// Returns `true` while the coordinator is still mid-session (neither failed
    /// nor successful) and can accept the next step.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            CoordinatorStateValue::Initial(_)
                | CoordinatorStateValue::Step1(_)
                | CoordinatorStateValue::Replaced
        )
    }

    fn only_active(&self) -> Result<()> {
        if !self.is_active() {
            return Err(ChillDkgError::Runtime(
                "can not not apply message to the terminal state".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::coordinator::{CoordinatorInitialState, CoordinatorState};
    use crate::msg::{ParticipantMsg1, ParticipantMsg2};
    use crate::party::{
        ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
    };
    use crate::{Coordinator, Participant};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn success_generate_key_hl() {
        const T: usize = 3;

        let mut rng = OsRng;

        // --------------- INIT PHASE ---------------
        let (s1, mut p1) = Participant::new(&mut rng);
        let (s2, mut p2) = Participant::new(&mut rng);
        let (s3, mut p3) = Participant::new(&mut rng);
        let (s4, mut p4) = Participant::new(&mut rng);
        let (s5, mut p5) = Participant::new(&mut rng);

        let host_seckeys = [s1, s2, s3, s4, s5];

        let host_keys: Vec<ProjectivePoint> = host_seckeys
            .iter()
            .map(|k| ProjectivePoint::GENERATOR * k.as_ref())
            .collect();

        let mut c = Coordinator::new(host_keys.clone(), T).unwrap();

        // --------------- DKG PHASE ---------------

        // ---- STEP 1 ----

        let msg1 = vec![
            p1.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p2.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p3.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p4.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
            p5.step1((host_keys.clone(), T, [0u8; 32])).unwrap(),
        ];

        let msg1_resp = c.step1(msg1).unwrap();

        // ---- STEP 2 ----

        let msg2 = vec![
            p1.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p2.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p3.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p4.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
            p5.step2((msg1_resp.clone(), [0u8; 32])).unwrap(),
        ];

        let (msg2_resp, output, _) = c.step2(msg2).unwrap();

        println!("Coordinator DKG output:");
        println!(
            "\t\tGroup public key {:?}",
            output.threshold_pubkey.to_encoded_point(true).to_string()
        );
        println!("\n\n");

        // ---- CertEq ----

        let res1 = p1.finalize(msg2_resp.clone()).unwrap();
        let res2 = p2.finalize(msg2_resp.clone()).unwrap();
        let res3 = p3.finalize(msg2_resp.clone()).unwrap();
        let res4 = p4.finalize(msg2_resp.clone()).unwrap();
        let res5 = p5.finalize(msg2_resp.clone()).unwrap();

        for (i, res) in [res1, res2, res3, res4, res5].iter().enumerate() {
            let (p_output, recovery_data) = res;
            assert_eq!(
                p_output.threshold_pubkey, output.threshold_pubkey,
                "Invalid group key for party {}",
                p_output.idx
            );

            assert_eq!(p_output.pubshares, output.pubshares);

            println!("Participant {} DKG output:", p_output.idx);
            println!(
                "\t\tGroup public key {:?}",
                p_output.threshold_pubkey.to_encoded_point(true).to_string()
            );
            println!("\t\tSecret share {:x}", p_output.secshare.to_bytes());

            let p_output_recovered = ParticipantInitialState {
                s: *host_seckeys[i],
            }
            .recover(recovery_data)
            .unwrap();

            println!(
                "\t\tRecovered secret share {:x}",
                p_output_recovered.secshare.to_bytes()
            );
            println!("\n");
        }
    }

    #[test]
    fn success_generate_key() {
        const N: usize = 5;
        const T: usize = 3;

        let mut rng = OsRng;

        // --------------- INIT PHASE ---------------

        let parties: Vec<ParticipantInitialState> = (0..N)
            .map(|_| ParticipantInitialState::new(&mut rng))
            .collect();

        let host_seckeys: Vec<Scalar> = parties.iter().map(|p| p.s).collect();

        let host_keys: Vec<ProjectivePoint> = parties.iter().map(|p| p.get_host_key()).collect();

        let coordinator = CoordinatorInitialState::new(host_keys.clone(), T).unwrap();

        // --------------- DKG PHASE ---------------

        // ---- STEP 1 ----

        let mut msg1: Vec<ParticipantMsg1> = Vec::with_capacity(N);

        let parties: Vec<ParticipantStep1State> = parties
            .into_iter()
            .map(|p| {
                let (next, msg) = p.next((host_keys.clone(), T, [0u8; 32])).unwrap();
                msg1.push(msg);
                next.unwrap()
            })
            .collect();

        let (next_coordinator, msg1_resp) = coordinator.next(msg1).unwrap();
        let coordinator = next_coordinator.unwrap();

        // ---- STEP 2 ----

        let mut msg2: Vec<ParticipantMsg2> = Vec::with_capacity(N);

        let parties: Vec<ParticipantStep2State> = parties
            .into_iter()
            .map(|p| {
                let (next, msg) = p.next((msg1_resp.clone(), [0u8; 32])).unwrap();
                msg2.push(msg);
                next.unwrap()
            })
            .collect();

        let (_, (msg2_resp, output, _)) = coordinator.next(msg2).unwrap();

        println!("Coordinator DKG output:");
        println!(
            "\t\tGroup public key {:?}",
            output.threshold_pubkey.to_encoded_point(true).to_string()
        );
        println!("\n\n");

        // ---- CertEq ----

        for (i, p) in parties.into_iter().enumerate() {
            let (_, (p_output, recovery_data)) = p.next(msg2_resp.clone()).unwrap();
            assert_eq!(
                p_output.threshold_pubkey, output.threshold_pubkey,
                "Invalid group key for party {}",
                p_output.idx
            );

            assert_eq!(p_output.pubshares, output.pubshares);

            println!("Participant {} DKG output:", p_output.idx);
            println!(
                "\t\tGroup public key {:?}",
                p_output.threshold_pubkey.to_encoded_point(true).to_string()
            );
            println!("\t\tSecret share {:x}", p_output.secshare.to_bytes());

            let p_output_recovered =
                Participant::recover(&host_seckeys[i], &recovery_data).unwrap();

            println!(
                "\t\tRecovered secret share {:x}",
                p_output_recovered.secshare.to_bytes()
            );
            println!("\n");
        }
    }
}
