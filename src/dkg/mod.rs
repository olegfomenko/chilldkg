//! # ChillDKG
//!
//! The high-level SDK for the ChillDKG distributed key generation protocol
//! (BIP-FROST-DKG). This module defines the lower-level state machines in
//! [`party`] and [`coordinator`] and wraps them into two driver types, [`Participant`] and
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

pub mod coordinator;
pub mod errors;
pub mod msg;
pub mod party;

pub use party::{
    ParticipantInitialState, ParticipantState, ParticipantStep1State, ParticipantStep2State,
};

pub use coordinator::{CoordinatorInitialState, CoordinatorState, CoordinatorStep1State};

pub use errors::{ChillDkgError, Result};

use crate::crypto::SecretScalar;
use k256::{ProjectivePoint, Scalar};
use msg::{
    CoordinatorDKGOutput, CoordinatorMsg1, CoordinatorMsg2, DKGOutput, ParticipantMsg1,
    ParticipantMsg2, RecoveryData,
};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

/// Driver for a single participant across a full ChillDKG session.
///
/// The participant is advanced one round at a time with [`Participant::step1`],
/// [`Participant::step2`] and [`Participant::finalize`]. Each call consumes the
/// current internal state and produces the next one, so a step can never be run
/// twice or out of order; doing so returns an error and moves the participant to
/// a terminal failed state.
#[derive(Clone)]
pub struct Participant {
    state: ParticipantStateValue,
}

#[derive(Clone, PartialEq, Eq)]
enum ParticipantStateValue {
    Initial(ParticipantInitialState),
    Step1(ParticipantStep1State),
    Step2(ParticipantStep2State),
    Failed(ChillDkgError),
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
    pub fn new_with_secret(scalar: &Scalar) -> Result<Self> {
        if bool::from(scalar.is_zero()) {
            return Err(ChillDkgError::HostSeckey(
                "host secret key can't be zero".into(),
            ));
        }

        Ok(Self {
            state: ParticipantStateValue::Initial(ParticipantInitialState::new_with_secret(scalar)),
        })
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
        self.transition::<ParticipantInitialState>(msg)
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
        self.transition::<ParticipantStep1State>(msg)
    }

    /// Completes the session for this participant.
    ///
    /// Verifies the coordinator's certificate
    /// ([`CoordinatorMsg2`]) and, on success, returns the
    /// participant's [`DKGOutput`] and the
    /// [`RecoveryData`]. The output holds the secret share and
    /// must be stored securely; the recovery data should also be persisted so the
    /// output can be [`recover`](Participant::recover)ed later. Returning an error
    /// moves the participant to the failed state.
    pub fn finalize(
        &mut self,
        msg: <ParticipantStep2State as ParticipantState>::Message,
    ) -> Result<(DKGOutput, RecoveryData)> {
        self.transition::<ParticipantStep2State>(msg)
    }

    fn transition<S>(&mut self, msg: S::Message) -> Result<S::Output>
    where
        S: ParticipantState + TryFrom<ParticipantStateValue, Error = ChillDkgError>,
        ParticipantStateValue: From<S::Next>,
    {
        // Call on the terminal state shouldn't change it
        self.only_active()?;
        let state = std::mem::replace(&mut self.state, ParticipantStateValue::Replaced);

        match S::try_from(state).and_then(|s| s.next(msg)) {
            Ok((next, output)) => {
                self.state = next.map_or(ParticipantStateValue::Successful, Into::into);
                Ok(output)
            }
            Err(e) => {
                self.state = ParticipantStateValue::Failed(e.clone());
                Err(e)
            }
        }
    }

    /// Returns `true` if a step returned an error and the participant can no
    /// longer be advanced. See the crate-level note: a failed participant does
    /// not imply the session failed for the group.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, ParticipantStateValue::Failed(_))
    }

    /// Returns `Some(ChillDkgError)` if current state
    /// is `ParticipantStateValue::Failed` and None otherwise.
    pub fn failure(&self) -> Option<&ChillDkgError> {
        match &self.state {
            ParticipantStateValue::Failed(e) => Some(e),
            _ => None,
        }
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
                "can not apply message to the terminal state".into(),
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
#[derive(Clone)]
pub struct Coordinator {
    state: CoordinatorStateValue,
}

#[expect(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
enum CoordinatorStateValue {
    Initial(CoordinatorInitialState),
    Step1(CoordinatorStep1State),
    Failed(ChillDkgError),
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
        coordinator::recovery::recover(recovery_data)
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
        self.transition::<CoordinatorInitialState>(msg)
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
        self.transition::<CoordinatorStep1State>(msg)
    }

    fn transition<S>(&mut self, msg: S::Message) -> Result<S::Output>
    where
        S: CoordinatorState + TryFrom<CoordinatorStateValue, Error = ChillDkgError>,
        CoordinatorStateValue: From<S::Next>,
    {
        // Call on the terminal state shouldn't change it
        self.only_active()?;
        let state = std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced);

        match S::try_from(state).and_then(|s| s.next(msg)) {
            Ok((next, output)) => {
                self.state = next.map_or(CoordinatorStateValue::Successful, Into::into);
                Ok(output)
            }
            Err(e) => {
                self.state = CoordinatorStateValue::Failed(e.clone());
                Err(e)
            }
        }
    }

    /// Returns `true` if a step returned an error and the coordinator can no
    /// longer be advanced.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Failed(_))
    }

    /// Returns `Some(ChillDkgError)` if current state
    /// is `CoordinatorStateValue::Failed` and None otherwise.
    pub fn failure(&self) -> Option<&ChillDkgError> {
        match &self.state {
            CoordinatorStateValue::Failed(e) => Some(e),
            _ => None,
        }
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
                "can not apply message to the terminal state".into(),
            ));
        }

        Ok(())
    }
}

// State conversions used by the drivers' `transition`.
impl TryFrom<ParticipantStateValue> for ParticipantInitialState {
    type Error = ChillDkgError;
    fn try_from(v: ParticipantStateValue) -> Result<Self> {
        match v {
            ParticipantStateValue::Initial(s) => Ok(s),
            _ => Err(ChillDkgError::Runtime(
                "expected another state than given".into(),
            )),
        }
    }
}

impl TryFrom<ParticipantStateValue> for ParticipantStep1State {
    type Error = ChillDkgError;
    fn try_from(v: ParticipantStateValue) -> Result<Self> {
        match v {
            ParticipantStateValue::Step1(s) => Ok(s),
            _ => Err(ChillDkgError::Runtime(
                "expected another state than given".into(),
            )),
        }
    }
}

impl TryFrom<ParticipantStateValue> for ParticipantStep2State {
    type Error = ChillDkgError;
    fn try_from(v: ParticipantStateValue) -> Result<Self> {
        match v {
            ParticipantStateValue::Step2(s) => Ok(s),
            _ => Err(ChillDkgError::Runtime(
                "expected another state than given".into(),
            )),
        }
    }
}

impl From<ParticipantInitialState> for ParticipantStateValue {
    fn from(s: ParticipantInitialState) -> Self {
        ParticipantStateValue::Initial(s)
    }
}

impl From<ParticipantStep1State> for ParticipantStateValue {
    fn from(s: ParticipantStep1State) -> Self {
        ParticipantStateValue::Step1(s)
    }
}

impl From<ParticipantStep2State> for ParticipantStateValue {
    fn from(s: ParticipantStep2State) -> Self {
        ParticipantStateValue::Step2(s)
    }
}

impl TryFrom<CoordinatorStateValue> for CoordinatorInitialState {
    type Error = ChillDkgError;
    fn try_from(v: CoordinatorStateValue) -> Result<Self> {
        match v {
            CoordinatorStateValue::Initial(s) => Ok(s),
            _ => Err(ChillDkgError::Runtime(
                "expected another state then given".into(),
            )),
        }
    }
}

impl TryFrom<CoordinatorStateValue> for CoordinatorStep1State {
    type Error = ChillDkgError;
    fn try_from(v: CoordinatorStateValue) -> Result<Self> {
        match v {
            CoordinatorStateValue::Step1(s) => Ok(s),
            _ => Err(ChillDkgError::Runtime(
                "expected another state then given".into(),
            )),
        }
    }
}

impl From<CoordinatorInitialState> for CoordinatorStateValue {
    fn from(s: CoordinatorInitialState) -> Self {
        CoordinatorStateValue::Initial(s)
    }
}

impl From<CoordinatorStep1State> for CoordinatorStateValue {
    fn from(s: CoordinatorStep1State) -> Self {
        CoordinatorStateValue::Step1(s)
    }
}
