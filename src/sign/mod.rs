//! # FROST signing (BIP445)
//!
//! Threshold Schnorr signing over the output of a ChillDKG session, following
//! the BIP-FROST-signing reference implementation (FROST3 variant). Any `t` of
//! the `n` participants can produce a signature that verifies under the
//! threshold public key exactly like a single-signer BIP340 signature.
//!
//! Participant ids are the ChillDKG indices; the subset that signs is the set
//! of ids that contribute a nonce. Every party must agree on the message and
//! on the [`Tweak`]s applied to the threshold key (none for a plain key).
//!
//! Like the DKG, the protocol is modelled as consuming state transitions
//! (see [`SignerState`] and [`CoordinatorState`]), wrapped by two driver
//! types, [`Signer`] and [`Coordinator`], that track the round for you and
//! cannot be advanced out of order:
//!
//! 1. Every signer starts a [`SignerInitialState`] from its DKG output and
//!    steps it with the message, the tweaks and fresh randomness, obtaining
//!    the [`PubNonce`] to send to the coordinator. The coordinator starts a
//!    [`CoordinatorInitialState`] from its DKG output, steps it with the
//!    collected `(id, pubnonce)` pairs and relays the resulting list.
//! 2. Every signer steps its [`SignerStep1State`] with that list, the
//!    message and the tweaks, obtaining its [`PartialSignature`]. The
//!    coordinator steps its [`CoordinatorStep1State`] with the `(id, psig)`
//!    pairs, the message and the tweaks: each partial signature is verified (a bad one is reported as [`SignError::InvalidContribution`]
//!    naming the participant) and they are combined into the final BIP340
//!    signature.
//!
//! [`validate_signers`], [`partial_verify`] and [`verify`] are the stateless
//! building blocks for anyone holding only the public key material.
//!
//! ## Nonce reuse
//!
//! Reusing a secret nonce leaks the secret share. The [`SecNonce`] lives only
//! inside a [`SignerStep1State`], which is consumed by the signing step, so a
//! nonce can only ever be used once — and only for the message and tweaks it
//! was generated for. It is wiped from memory when the state is dropped.
//!
//! Note that a ChillDKG threshold key already commits to an unspendable
//! Taproot script path, as BIP445 requires of key generation.

pub mod coordinator;
pub mod errors;
pub mod msg;
pub mod party;

pub use crate::crypto::tweak::Tweak;
pub use coordinator::verify::{
    aggr_pubnonces, partial_verify, signing_pubkey, validate_signers, verify,
};
pub use coordinator::{CoordinatorInitialState, CoordinatorState, CoordinatorStep1State};
pub use errors::{Result, SignError};
pub use msg::{PartialSignature, PubNonce};
pub use party::nonce::{SecNonce, sample_nonce};
pub use party::sign::partial_sign;
pub use party::{SignerInitialState, SignerState, SignerStep1State};

use crate::crypto::schnorr::SchnorrSignature;
use crate::dkg::msg::{CoordinatorDKGOutput, DKGOutput};

/// Driver for a single signer across one signing session.
///
/// The signer is advanced with [`Signer::step1`] (nonce) and
/// [`Signer::finalize`] (partial signature). Each call consumes the current
/// internal state and produces the next one, so a step can never be run
/// twice or out of order; doing so returns an error and moves the signer to
/// a terminal failed state. The secret nonce is dropped, and wiped, with the
/// state that held it.
pub struct Signer {
    state: SignerStateValue,
}

enum SignerStateValue {
    Initial(SignerInitialState),
    Step1(SignerStep1State),
    Failed(SignError),
    Successful,
    Replaced, // An intermediate state between transitions
}

impl Signer {
    /// Creates a signer for one session from the participant's DKG output.
    pub fn new(output: &DKGOutput) -> Self {
        Self {
            state: SignerStateValue::Initial(SignerInitialState::new(output)),
        }
    }

    /// Runs the signer's first round.
    ///
    /// Takes the message and the tweaks, if already known, plus 32 bytes of
    /// fresh randomness, and produces the [`PubNonce`] (paired with this
    /// participant's id) to send to the coordinator. Whatever is given here
    /// is fixed for the session: [`finalize`](Signer::finalize) refuses a
    /// different message or tweaks. On error the signer moves to the failed
    /// state; see the module-level note on handling failure.
    pub fn step1(
        &mut self,
        msg: <SignerInitialState as SignerState>::Message,
    ) -> Result<(usize, PubNonce)> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (next, pubnonce) = Self::step1_inner(
            std::mem::replace(&mut self.state, SignerStateValue::Replaced),
            msg,
        )
        .inspect_err(|e| {
            self.state = SignerStateValue::Failed(e.clone());
        })?;

        self.state = next;

        Ok(pubnonce)
    }

    fn step1_inner(
        state: SignerStateValue,
        msg: <SignerInitialState as SignerState>::Message,
    ) -> Result<(SignerStateValue, (usize, PubNonce))> {
        match state {
            SignerStateValue::Initial(state) => {
                let (next, pubnonce) = state.next(msg)?;

                let next_state = SignerStateValue::Step1(next.ok_or_else(|| {
                    SignError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pubnonce))
            }
            _ => Err(SignError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Completes the session for this signer.
    ///
    /// Takes the `(id, pubnonce)` list relayed by the coordinator together
    /// with the message and the tweaks, and produces the
    /// [`PartialSignature`] (paired with this participant's id) to send back.
    /// The secret nonce is consumed here. Returning an error moves the signer
    /// to the failed state.
    pub fn finalize(
        &mut self,
        msg: <SignerStep1State as SignerState>::Message,
    ) -> Result<(usize, PartialSignature)> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let psig = Self::finalize_inner(
            std::mem::replace(&mut self.state, SignerStateValue::Replaced),
            msg,
        )
        .inspect_err(|e| {
            self.state = SignerStateValue::Failed(e.clone());
        })?;

        self.state = SignerStateValue::Successful;

        Ok(psig)
    }

    fn finalize_inner(
        state: SignerStateValue,
        msg: <SignerStep1State as SignerState>::Message,
    ) -> Result<(usize, PartialSignature)> {
        match state {
            SignerStateValue::Step1(state) => {
                let (_, psig) = state.next(msg)?;
                Ok(psig)
            }
            _ => Err(SignError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Returns `true` if a step returned an error and the signer can no
    /// longer be advanced.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, SignerStateValue::Failed(_))
    }

    /// Returns `Some(SignError)` if current state
    /// is `SignerStateValue::Failed` and None otherwise.
    pub fn failure(&self) -> Option<&SignError> {
        match &self.state {
            SignerStateValue::Failed(e) => Some(e),
            _ => None,
        }
    }

    /// Returns `true` once [`finalize`](Signer::finalize) has succeeded.
    pub fn is_successful(&self) -> bool {
        matches!(self.state, SignerStateValue::Successful)
    }

    /// Returns `true` while the signer is still mid-session (neither failed
    /// nor successful) and can accept the next step.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            SignerStateValue::Initial(_) | SignerStateValue::Step1(_) | SignerStateValue::Replaced
        )
    }

    fn only_active(&self) -> Result<()> {
        if !self.is_active() {
            return Err(SignError::Runtime(
                "can not apply message to the terminal state".into(),
            ));
        }

        Ok(())
    }
}

/// Driver for the coordinator across one signing session.
///
/// The coordinator relays the signers' nonces with [`Coordinator::step1`]
/// and combines their partial signatures with [`Coordinator::step2`]. Like
/// [`Signer`], it is a linear state machine: steps run once, in order, and an
/// error moves it to a terminal failed state. The coordinator only ever
/// handles public data.
#[derive(Clone)]
pub struct Coordinator {
    state: CoordinatorStateValue,
}

#[derive(Clone, PartialEq, Eq)]
enum CoordinatorStateValue {
    Initial(CoordinatorInitialState),
    Step1(CoordinatorStep1State),
    Failed(SignError),
    Successful,
    Replaced, // An intermediate state between transitions
}

impl Coordinator {
    /// Creates a coordinator for one session from the coordinator's DKG
    /// output.
    pub fn new(output: &CoordinatorDKGOutput) -> Self {
        Self {
            state: CoordinatorStateValue::Initial(CoordinatorInitialState::new(output)),
        }
    }

    /// Runs the coordinator's first round.
    ///
    /// Validates the signing subset and the `(id, pubnonce)` pairs collected
    /// from it, and returns the list to relay to every signer. On error the
    /// coordinator moves to the failed state.
    pub fn step1(
        &mut self,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<Vec<(usize, PubNonce)>> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let (next, pubnonces) = Self::step1_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|e| {
            self.state = CoordinatorStateValue::Failed(e.clone());
        })?;

        self.state = next;

        Ok(pubnonces)
    }

    fn step1_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorInitialState as CoordinatorState>::Message,
    ) -> Result<(CoordinatorStateValue, Vec<(usize, PubNonce)>)> {
        match state {
            CoordinatorStateValue::Initial(state) => {
                let (next, pubnonces) = state.next(msg)?;

                let next_state = CoordinatorStateValue::Step1(next.ok_or_else(|| {
                    SignError::Runtime("invalid next state after applying message".into())
                })?);

                Ok((next_state, pubnonces))
            }
            _ => Err(SignError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Completes the session on the coordinator side.
    ///
    /// Takes the signers' `(id, psig)` pairs together with the message and
    /// the tweaks, verifies every partial signature (a bad one is reported as
    /// [`SignError::InvalidContribution`] naming the participant), combines
    /// them and returns the final BIP340 [`SchnorrSignature`], checked under
    /// the tweaked threshold key. On error the coordinator moves to the
    /// failed state.
    pub fn step2(
        &mut self,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<SchnorrSignature> {
        // Call on the terminal state shouldn't change it
        self.only_active()?;

        let sig = Self::step2_inner(
            std::mem::replace(&mut self.state, CoordinatorStateValue::Replaced),
            msg,
        )
        .inspect_err(|e| {
            self.state = CoordinatorStateValue::Failed(e.clone());
        })?;

        self.state = CoordinatorStateValue::Successful;

        Ok(sig)
    }

    fn step2_inner(
        state: CoordinatorStateValue,
        msg: <CoordinatorStep1State as CoordinatorState>::Message,
    ) -> Result<SchnorrSignature> {
        match state {
            CoordinatorStateValue::Step1(state) => {
                let (_, sig) = state.next(msg)?;
                Ok(sig)
            }
            _ => Err(SignError::Runtime(
                "can not apply message to the given state".into(),
            )),
        }
    }

    /// Returns `true` if a step returned an error and the coordinator can no
    /// longer be advanced.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Failed(_))
    }

    /// Returns `Some(SignError)` if current state
    /// is `CoordinatorStateValue::Failed` and None otherwise.
    pub fn failure(&self) -> Option<&SignError> {
        match &self.state {
            CoordinatorStateValue::Failed(e) => Some(e),
            _ => None,
        }
    }

    /// Returns `true` once [`step2`](Coordinator::step2) has succeeded.
    pub fn is_successful(&self) -> bool {
        matches!(self.state, CoordinatorStateValue::Successful)
    }

    /// Returns `true` while the coordinator is still mid-session (neither
    /// failed nor successful) and can accept the next step.
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
            return Err(SignError::Runtime(
                "can not apply message to the terminal state".into(),
            ));
        }

        Ok(())
    }
}
