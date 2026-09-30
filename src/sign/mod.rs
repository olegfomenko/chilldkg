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
//! (see [`SignerState`] and [`CoordinatorState`]):
//!
//! 1. Every signer starts a [`SignerInitialState`] from its DKG output and
//!    steps it with the message, the tweaks and fresh randomness, obtaining
//!    the [`PubNonce`] to send to the coordinator. The coordinator starts a
//!    [`CoordinatorInitialState`] from its DKG output, the message and the
//!    tweaks, steps it with the collected `(id, pubnonce)` pairs and relays
//!    the resulting list.
//! 2. Every signer steps its [`SignerStep1State`] with that list, obtaining
//!    its [`PartialSignature`]. The coordinator steps its
//!    [`CoordinatorStep1State`] with the `(id, psig)` pairs: each one is
//!    verified (a bad one is reported as [`SignError::InvalidContribution`]
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
