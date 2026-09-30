#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::compress_point_bip340;
use crate::crypto::schnorr::{SchnorrSignature, bip340_challenge};
use crate::crypto::tweak::TweakContext;
use crate::sign::coordinator::verify::{
    aggr_pubnonces, combine, signing_nonce, validate_signers, verify,
};
use crate::sign::coordinator::{CoordinatorInitialState, CoordinatorState, CoordinatorStep1State};
use crate::sign::errors::{Result, SignError};
use crate::sign::msg::{PartialSignature, PubNonce};
use crate::sign::partial_verify;
use std::collections::BTreeMap;

impl CoordinatorState for CoordinatorInitialState {
    /// The public nonces collected from the chosen signers.
    type Message = Vec<(usize, PubNonce)>;
    type Next = CoordinatorStep1State;
    /// The same list, to relay to every signer.
    type Output = Vec<(usize, PubNonce)>;

    /// Round 1: validates the signing subset and its nonces before anything
    /// is relayed.
    fn next(self, pubnonces: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let ids: Vec<usize> = pubnonces.iter().map(|(id, _)| *id).collect();
        validate_signers(self.t, &self.pubshares, &self.threshold_pubkey, &ids)?;

        for (id, pubnonce) in &pubnonces {
            chill_dkg_ensure!(
                !pubnonce.is_identity(),
                SignError::InvalidContribution {
                    participant: *id,
                    message: "invalid pubnonce".into(),
                },
            );
        }

        let next = CoordinatorStep1State {
            t: self.t,
            pubshares: self.pubshares,
            threshold_pubkey: self.threshold_pubkey,
            msg: self.msg,
            tweaks: self.tweaks,
            pubnonces: pubnonces.clone().into_iter().collect(),
        };

        Ok((Some(next), pubnonces))
    }
}

impl CoordinatorState for CoordinatorStep1State {
    /// The partial signatures, paired with their participant ids.
    type Message = Vec<(usize, PartialSignature)>;
    type Next = Self;
    /// The final BIP340 signature.
    type Output = SchnorrSignature;

    /// Round 2: verifies every partial signature against its signer's nonce
    /// and public share (an invalid one is reported as
    /// [`SignError::InvalidContribution`] naming the participant), combines
    /// them and checks the result verifies under the tweaked threshold key.
    fn next(self, psigs: Self::Message) -> Result<(Option<Self::Next>, Self::Output)> {
        let psigs: BTreeMap<usize, PartialSignature> = psigs.into_iter().collect();
        chill_dkg_ensure!(
            self.pubnonces.keys().eq(psigs.keys()),
            SignError::Value("invalid list of signer ids".into())
        );

        let input: BTreeMap<usize, (PubNonce, PartialSignature)> = self
            .pubnonces
            .into_iter()
            .zip(psigs)
            .map(|((id, nonce), (_, psig))| (id, (nonce, psig)))
            .collect();

        let ids: Vec<usize> = input.keys().cloned().collect();

        let tweak_ctx = TweakContext::new(self.threshold_pubkey).apply_all(&self.tweaks)?;
        let (b, R) = signing_nonce(
            &ids,
            aggr_pubnonces(input.values().map(|(pubnonce, _)| pubnonce)),
            &tweak_ctx,
            &self.msg,
        );
        let e = bip340_challenge(
            &compress_point_bip340(&R),
            &tweak_ctx.xonly_pubkey(),
            &self.msg,
        )?;

        for (id, (pubnonce, psig)) in &input {
            partial_verify(
                psig,
                *id,
                pubnonce,
                &self.pubshares[*id],
                &ids,
                &tweak_ctx,
                b,
                &R,
                e,
            )?;
        }

        let sig = combine(input.values().map(|(_, psig)| psig), &tweak_ctx, &R, e);
        verify(&self.threshold_pubkey, sig, &self.msg, &self.tweaks)
            .map_err(|_| SignError::Runtime("aggregated signature does not verify".into()))?;

        Ok((None, sig))
    }
}
