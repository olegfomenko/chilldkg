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
//! 1. Every signer generates a nonce pair with [`sample_nonce`] and sends the
//!    [`PubNonce`] to the coordinator, keeping the [`SecNonce`].
//! 2. The coordinator relays the collected `(id, pubnonce)` pairs. Every signer calls
//!    [`Signer::sign`] with the message, the tweaks, its secret nonce and that
//!    list, returning its [`PartialSignature`]. The coordinator calls
//!    [`Verifier::verify_and_aggregate`], which checks every partial signature
//!    (blaming the faulty signer) and combines them into the final BIP340
//!    signature.
//!
//! [`Signer`] and [`Verifier`] hold only the long-lived DKG key material
//! (both are `From` a DKG output) and are reused across signing sessions.
//! Both run the session-level checks of the reference's `validate_signers_ctx`
//! on every call: the signing subset has between `t` and `n` distinct,
//! in-range members whose shares interpolate to the threshold key.
//!
//! ## Nonce reuse
//!
//! Reusing a secret nonce leaks the secret share. [`SecNonce`] is therefore
//! neither `Clone` nor `Copy`, and [`Signer::sign`] takes it by value: a
//! nonce can only ever be used once, and the compiler enforces it. The nonce
//! is wiped from memory as soon as it has been used.
//!
//! Note that a ChillDKG threshold key already commits to an unspendable
//! Taproot script path, as BIP445 requires of key generation.

mod nonce;
mod signer;
mod tweak;
mod verifier;

pub use nonce::{PubNonce, SecNonce, aggr_pubnonces, sample_nonce};
pub use signer::{PartialSignature, Signer};
pub use tweak::Tweak;
pub use verifier::Verifier;
