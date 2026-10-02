#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::tweak::Tweak;
use crate::sign::errors::{Result, SignError};
use crate::sign::msg::{PartialSignature, PubNonce};
use crate::sign::party::nonce::sample_nonce_internal;
use crate::sign::party::sign::partial_sign;
use crate::sign::party::{SignerInitialState, SignerState, SignerStep1State};
use crate::sign::signing_pubkey;
use zeroize::Zeroizing;

impl SignerState for SignerInitialState {
    /// The message and the tweaks, if already known, and 32 bytes of fresh
    /// randomness.
    type Message = (Option<Vec<u8>>, Option<Vec<Tweak>>, [u8; 32]);
    type Next = SignerStep1State;
    /// The public nonce to send to the coordinator.
    type Output = (usize, PubNonce);

    /// Round 1: derives a nonce pair bound to the secret share and the public
    /// share, and to the tweaked threshold key and the message when those are
    /// already known. Whatever is fixed here must be repeated unchanged at
    /// round 2.
    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (msg, tweaks, random) = msg;

        chill_dkg_ensure!(
            self.idx < self.pubshares.len(),
            SignError::Value("The signer's id is out of range.".into()),
        );

        let threshold_pk = tweaks.as_deref().map_or_else(
            || Ok(self.threshold_pubkey),
            |tweaks| signing_pubkey(&self.threshold_pubkey, tweaks),
        )?;

        let (pubnonce, secnonce) = sample_nonce_internal(
            Zeroizing::new(random),
            Some(&self.secshare),
            Some(&self.pubshare()),
            Some(&threshold_pk),
            msg.as_deref(),
            None,
        )?;

        let next = SignerStep1State {
            idx: self.idx,
            t: self.t,
            secshare: self.secshare,
            pubshares: self.pubshares.clone(),
            threshold_pubkey: self.threshold_pubkey,
            msg,
            tweaks,
            secnonce,
        };

        Ok((Some(next), (self.idx, pubnonce)))
    }
}

impl SignerState for SignerStep1State {
    /// The public nonces of every signer (this one included) paired with
    /// their participant ids, the message and the tweaks.
    type Message = (Vec<(usize, PubNonce)>, Vec<u8>, Vec<Tweak>);
    type Next = Self;
    /// The partial signature, paired with this participant's id.
    type Output = (usize, PartialSignature);

    /// Round 2: checks the message and tweaks against what the nonce was
    /// bound to, then produces the partial signature (see
    /// [`partial_sign`]). Consumes the secret nonce.
    fn next(self, msg: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let (pubnonces, msg, tweaks) = msg;
        // The nonce may have been bound to a message and tweaks at round 1;
        // signing anything else with it is refused.
        chill_dkg_ensure!(
            self.msg.as_ref().is_none_or(|bound| *bound == msg),
            SignError::Value(
                "The message differs from the one the nonce was generated for.".into()
            ),
        );
        chill_dkg_ensure!(
            self.tweaks.as_ref().is_none_or(|bound| *bound == tweaks),
            SignError::Value("The tweaks differ from the ones the nonce was generated for.".into()),
        );

        let s = partial_sign(
            self.idx,
            self.t,
            &self.secshare,
            &self.pubshares,
            &self.threshold_pubkey,
            &self.secnonce,
            &pubnonces,
            &msg,
            &tweaks,
        )?;

        // `self` (with the secret nonce) is dropped and wiped here.
        Ok((None, (self.idx, s)))
    }
}
