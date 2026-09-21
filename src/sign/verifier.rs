#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{X_ONLY_POINT_BYTES_SIZE, compress_point_bip340, has_even_y};
use crate::crypto::schnorr::{
    SCHNORR_SIG_BYTES_SIZE, SchnorrSignature, SchnorrVerifier, bip340_challenge,
};
use crate::errors::{ChillDkgError, Result};
use crate::msg::{CoordinatorDKGOutput, DKGOutput};
use crate::sign::lagrange::{interpolate_pubkey, lagrange};
use crate::sign::nonce::{PubNonce, aggr_pubnonces, get_pub_nonce};
use crate::sign::signer::{PartialSignature, signing_nonce};
use crate::sign::tweak::{Tweak, TweakContext};
use itertools::Itertools;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// The public side of a signing session: the DKG key material needed to check
/// partial signatures and combine them. Held by the coordinator, or by anyone
/// who wants to verify a signer's contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verifier {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Untweaked threshold public key of the DKG.
    pub thresh_pk: ProjectivePoint,

    /// Public shares of all `n` participants, indexed by participant id.
    ///
    /// Math: `Y_0, ..., Y_{n-1}`.
    pub pubshares: Vec<ProjectivePoint>,
}

impl From<&DKGOutput> for Verifier {
    fn from(output: &DKGOutput) -> Self {
        Self {
            t: output.t,
            thresh_pk: output.threshold_pubkey,
            pubshares: output.pubshares.clone(),
        }
    }
}

impl From<&CoordinatorDKGOutput> for Verifier {
    fn from(output: &CoordinatorDKGOutput) -> Self {
        Self {
            t: output.t,
            thresh_pk: output.threshold_pubkey,
            pubshares: output.pubshares.clone(),
        }
    }
}

impl Verifier {
    /// The key a signature produced with `tweaks` verifies under (BIP340
    /// x-only semantics).
    pub fn signing_pubkey(&self, tweaks: &[Tweak]) -> Result<ProjectivePoint> {
        Ok(TweakContext::new(self.thresh_pk).apply_all(tweaks)?.q)
    }

    /// Verifies a final signature over `msg` as a plain BIP340 signature under
    /// the threshold key tweaked by `tweaks` (x-only semantics).
    pub fn verify(&self, sig: SchnorrSignature, msg: &[u8], tweaks: &[Tweak]) -> Result<()> {
        struct Bip340<'a> {
            msg: &'a [u8],
            Q: ProjectivePoint,
        }

        impl SchnorrVerifier for Bip340<'_> {
            fn message(&self) -> &[u8] {
                self.msg
            }

            fn pub_key(&self) -> ProjectivePoint {
                self.Q
            }
        }

        Bip340 {
            msg,
            Q: self.signing_pubkey(tweaks)?,
        }
        .verify(sig)
    }

    /// Verifies every partial signature and combines them into the final
    /// BIP340 signature under the tweaked threshold key.
    ///
    /// `psigs` pairs each signer's participant id with its partial signature
    /// and its public nonce. An invalid partial
    /// signature is reported as [`ChillDkgError::FaultyParticipant`] naming
    /// that signer's participant id.
    pub fn verify_and_aggregate(
        &self,
        psigs: &[(usize, PubNonce, PartialSignature)],
        msg: &[u8],
        tweaks: &[Tweak],
    ) -> Result<SchnorrSignature> {
        let ids: Vec<usize> = psigs.iter().map(|(i, _, _)| *i).collect();
        validate_signers(self.t, &self.pubshares, &self.thresh_pk, &ids)?;

        let tweak_ctx = TweakContext::new(self.thresh_pk).apply_all(tweaks)?;
        let (b, R) = signing_nonce(
            &ids,
            aggr_pubnonces(psigs.iter().map(|(_, pubnonce, _)| pubnonce)),
            &tweak_ctx,
            msg,
        );
        let e = bip340_challenge(&compress_point_bip340(&R), &tweak_ctx.xonly_pubkey(), msg)?;

        for (id, pubnonce, psig) in psigs {
            Self::partial_sig_verify_internal(
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

        Ok(Self::combine(
            psigs.iter().map(|(_, _, psig)| psig),
            &tweak_ctx,
            &R,
            e,
        ))
    }

    /// Verifies one signer's partial signature against the public nonces of
    /// the whole session. An invalid signature or an identity nonce is
    /// reported as [`ChillDkgError::FaultyParticipant`]; malformed session
    /// inputs as [`ChillDkgError::Value`].
    ///
    /// Mirrors the reference `partial_sig_verify`.
    pub fn partial_verify(
        &self,
        psig: &PartialSignature,
        id: usize,
        pubnonces: &[(usize, PubNonce)],
        msg: &[u8],
        tweaks: &[Tweak],
    ) -> Result<()> {
        let ids: Vec<usize> = pubnonces.iter().map(|(id, _)| *id).collect();
        validate_signers(self.t, &self.pubshares, &self.thresh_pk, &ids)?;

        let pubnonce = get_pub_nonce(pubnonces.iter().map(|(id, pubnonce)| (*id, pubnonce)), id)
            .ok_or_else(|| {
                ChillDkgError::Value(
                    "The signer's id must be present in the participant identifier list.".into(),
                )
            })?;

        let tweak_ctx = TweakContext::new(self.thresh_pk).apply_all(tweaks)?;
        let (b, R) = signing_nonce(
            &ids,
            aggr_pubnonces(pubnonces.iter().map(|(_, pubnonce)| pubnonce)),
            &tweak_ctx,
            msg,
        );

        let e = bip340_challenge(&compress_point_bip340(&R), &tweak_ctx.xonly_pubkey(), msg)?;

        Self::partial_sig_verify_internal(
            psig,
            id,
            pubnonce,
            &self.pubshares[id],
            &ids,
            &tweak_ctx,
            b,
            &R,
            e,
        )
    }

    /// Combines partial signatures into a BIP340 signature under the tweaked
    /// threshold key **without verifying them**, given only the signing subset
    /// and the aggregate nonce `(R_1, R_2)` — for a coordinator that never
    /// held the individual public nonces. Prefer
    /// [`Verifier::verify_and_aggregate`] when they are available.
    ///
    /// Mirrors the reference `partial_sig_agg`.
    ///
    /// Math: `s = sum_i s_i + e * g * tacc`; signature is `R_x || s`.
    pub fn aggregate(
        &self,
        ids: &[usize],
        psigs: &[PartialSignature],
        aggnonce: (ProjectivePoint, ProjectivePoint),
        msg: &[u8],
        tweaks: &[Tweak],
    ) -> Result<SchnorrSignature> {
        chill_dkg_ensure!(
            psigs.len() == ids.len(),
            ChillDkgError::Value("The psigs and ids arrays must have the same length.".into()),
        );

        validate_signers(self.t, &self.pubshares, &self.thresh_pk, ids)?;

        let tweak_ctx = TweakContext::new(self.thresh_pk).apply_all(tweaks)?;
        let (_, R) = signing_nonce(ids, aggnonce, &tweak_ctx, msg);
        let e = bip340_challenge(&compress_point_bip340(&R), &tweak_ctx.xonly_pubkey(), msg)?;

        Ok(Self::combine(psigs, &tweak_ctx, &R, e))
    }

    /// Math: `s_i * G == R_i' + (e * a_i * g * gacc) * Y_i`, where
    /// `R_i' = R_{i,1} + b * R_{i,2}`, negated if `R` has an odd `y`.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn partial_sig_verify_internal(
        psig: &PartialSignature,
        my_id: usize,
        pubnonce: &PubNonce,
        pubshare: &ProjectivePoint,
        ids: &[usize],
        tweak_ctx: &TweakContext,
        b: Scalar,
        R: &ProjectivePoint,
        e: Scalar,
    ) -> Result<()> {
        chill_dkg_ensure!(
            !bool::from(pubnonce.R1.is_identity()),
            ChillDkgError::FaultyParticipant {
                participant: my_id,
                message: "Participant provided identity R1 nonce".into()
            },
        );

        chill_dkg_ensure!(
            !bool::from(pubnonce.R2.is_identity()),
            ChillDkgError::FaultyParticipant {
                participant: my_id,
                message: "Participant provided identity R2 nonce".into()
            },
        );

        let Re_s_ = pubnonce.R1 + pubnonce.R2 * b;
        let Re_s = if has_even_y(R) { Re_s_ } else { -Re_s_ };

        // Fails if my_id is not among the signers.
        let Ok(a) = lagrange(ids, my_id) else {
            return Err(ChillDkgError::Value(
                "Participants is not among the signers.".into(),
            ));
        };
        let g_ = tweak_ctx.g() * tweak_ctx.gacc;

        chill_dkg_ensure!(
            ProjectivePoint::GENERATOR * psig == Re_s + pubshare * &(e * a * g_),
            ChillDkgError::FaultyParticipant {
                participant: my_id,
                message: "invalid partial signature".into(),
            },
        );

        Ok(())
    }

    /// Math: `s = sum_i s_i + e * g * tacc`; signature is `R_x || s`.
    pub(crate) fn combine<'a>(
        psigs: impl IntoIterator<Item = &'a PartialSignature>,
        tweak_ctx: &TweakContext,
        R: &ProjectivePoint,
        e: Scalar,
    ) -> SchnorrSignature {
        let mut s = Scalar::ZERO;
        for psig in psigs {
            s += psig;
        }
        s += e * tweak_ctx.g() * tweak_ctx.tacc;

        let mut sig = [0u8; SCHNORR_SIG_BYTES_SIZE];
        sig[..X_ONLY_POINT_BYTES_SIZE].copy_from_slice(&compress_point_bip340(R));
        sig[X_ONLY_POINT_BYTES_SIZE..].copy_from_slice(&s.to_bytes());
        sig
    }
}

/// Checks that `ids` is a valid signing subset for this key material:
/// `t <= |ids| <= n`, every id is in range, no duplicates, no identity
/// public share, and the subset's public shares interpolate to the
/// threshold key.
pub fn validate_signers(
    t: usize,
    pubshares: &[ProjectivePoint],
    threshold_pubkey: &ProjectivePoint,
    ids: &[usize],
) -> Result<()> {
    let n = pubshares.len();
    chill_dkg_ensure!(
        t >= 1 && t <= n,
        ChillDkgError::Value("The threshold must be 1 <= t <= n.".into()),
    );
    chill_dkg_ensure!(
        t <= ids.len() && ids.len() <= n,
        ChillDkgError::Value("The number of signers must be between t and n.".into()),
    );
    for (idx, &id) in ids.iter().enumerate() {
        chill_dkg_ensure!(
            id < n,
            ChillDkgError::Value(
                format!("The participant identifier at index {idx} is out of range.").into()
            ),
        );
        chill_dkg_ensure!(
            !bool::from(pubshares[id].is_identity()),
            ChillDkgError::Value(format!("Invalid pubshare at index {idx}.").into()),
        );
    }

    chill_dkg_ensure!(
        ids.iter().all_unique(),
        ChillDkgError::Value("The participant identifier list contains duplicate elements.".into()),
    );

    let pubshares: Vec<ProjectivePoint> = ids.iter().map(|&id| pubshares[id]).collect();
    chill_dkg_ensure!(
        &interpolate_pubkey(ids, &pubshares)? == (threshold_pubkey),
        ChillDkgError::Value("The provided key material is incorrect.".into()),
    );
    Ok(())
}
