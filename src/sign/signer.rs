#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{compress_default, compress_point_bip340, reduce_scalar_from_bytes};
use crate::crypto::schnorr::bip340_challenge;
use crate::crypto::tagged_hash;
use crate::crypto::tags::TAG_FROST_NONCECOEF;
use crate::errors::{ChillDkgError, Result};
use crate::msg::DKGOutput;
use crate::sign::lagrange::lagrange;
use crate::sign::nonce::{SecNonce, aggr_pubnonces};
use crate::sign::tweak::{Tweak, TweakContext};
use crate::sign::verifier::validate_signers;
use crate::sign::{PubNonce, Verifier};
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A signer's partial signature.
///
/// Math: `s_i`.
pub type PartialSignature = Scalar;

/// One participant's long-lived signing identity: its DKG index, secret share
/// and the threshold key. Built once from the DKG output and reused for every
/// signing session; everything specific to one signing (message, tweaks,
/// nonces) is passed to [`Signer::sign`].
///
/// The secret share is wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Signer {
    /// Participant index.
    ///
    /// Math: `i`.
    pub my_id: usize,

    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Final participant public shares.
    ///
    /// Math: `Y_i`.
    pub pubshares: Vec<ProjectivePoint>,

    /// Untweaked threshold public key of the DKG.
    pub threshold_pubkey: ProjectivePoint,

    /// Math: `u_i`.
    secshare: Scalar,
}

impl From<&DKGOutput> for Signer {
    fn from(output: &DKGOutput) -> Self {
        Self::new(
            output.idx,
            output.t,
            &output.secshare,
            &output.pubshares,
            output.threshold_pubkey,
        )
    }
}

impl Signer {
    pub fn new(
        my_id: usize,
        t: usize,
        secshare: &Scalar,
        pubshares: &[ProjectivePoint],
        threshold_pubkey: ProjectivePoint,
    ) -> Self {
        Self {
            my_id,
            t,
            threshold_pubkey,
            pubshares: pubshares.to_vec(),
            secshare: *secshare,
        }
    }

    /// The signer's public share.
    ///
    /// Math: `Y_i = u_i * G`.
    pub fn pubshare(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.secshare
    }

    /// Produces a partial signature over `msg` under the threshold key tweaked
    /// by `tweaks`, using the secret nonce generated for this session and the
    /// public nonces of every signer (this one included). Consumes the secret
    /// nonce, so it cannot be reused.
    ///
    /// Runs the session-level checks of the reference's `validate_signers_ctx`
    /// first: at least `t` and at most `n` distinct, in-range participants
    /// sign and their public shares interpolate to `threshold_pubkey`.
    ///
    /// Math: `k_j = -k_j` if `R` has an odd `y`; `d = g * gacc * u_i`;
    /// `s_i = k_1 + b * k_2 + e * a_i * d`.
    pub fn sign(
        &self,
        msg: &[u8],
        tweaks: &[Tweak],
        secnonce: SecNonce,
        pubnonces: &[(usize, PubNonce)],
    ) -> Result<PartialSignature> {
        chill_dkg_ensure!(
            !bool::from(secnonce.k1.is_zero()),
            ChillDkgError::Value("first secnonce value is out of range.".into()),
        );
        chill_dkg_ensure!(
            !bool::from(secnonce.k2.is_zero()),
            ChillDkgError::Value("second secnonce value is out of range.".into()),
        );
        chill_dkg_ensure!(
            !bool::from(self.secshare.is_zero()),
            ChillDkgError::Value("The signer's secret share value is out of range.".into()),
        );

        let ids: Vec<usize> = pubnonces.iter().map(|(i, _)| *i).collect();
        validate_signers(self.t, &self.pubshares, &self.threshold_pubkey, &ids)?;

        let tweak_ctx = TweakContext::new(self.threshold_pubkey).apply_all(tweaks)?;
        let (b, R) = signing_nonce(
            &ids,
            aggr_pubnonces(pubnonces.iter().map(|(_, pubnonce)| pubnonce)),
            &tweak_ctx,
            msg,
        );

        let e = bip340_challenge(&compress_point_bip340(&R), &tweak_ctx.xonly_pubkey(), msg)?;

        // Fails if my_id is not among the signers (so my_id < n from here on).
        let a = lagrange(&ids, self.my_id)?;

        // The share we hold must be the one the group knows us by.
        let pubshare = self.pubshare();
        chill_dkg_ensure!(
            pubshare == self.pubshares[self.my_id],
            ChillDkgError::Value(
                "The signer's pubshare must be included in the list of pubshares.".into()
            ),
        );

        // Public nonce of the un-negated secret nonce, used for the self-check below.
        let pubnonce = secnonce.pubnonce();
        let k = secnonce.even_y_nonce(&R);
        // The nonce is consumed: wipe it now so it cannot be reused.
        drop(secnonce);

        let d = Zeroizing::new((tweak_ctx.g() * tweak_ctx.gacc) * self.secshare);
        let b_k2 = Zeroizing::new(b * k.k2);
        let e_a_d = Zeroizing::new((e * a) * d.as_ref());
        let s = k.k1 + b_k2.as_ref() + e_a_d.as_ref();

        // The result of signing must pass partial signature verification.
        Verifier::partial_sig_verify_internal(
            &s, self.my_id, &pubnonce, &pubshare, &ids, &tweak_ctx, b, &R, e,
        )?;

        Ok(s)
    }
}

/// Nonce coefficient and final nonce of the session, from the signing subset
/// (in any order; committed to as a set) and the aggregate nonce.
///
/// Math: `b = H_noncecoef(ser_ids || aggnonce || Q_x || msg)` where ser_ids is
/// the sorted ids as 4-byte big-endian integers (a set, per ROAST) and aggnonce
/// is `R_1 || R_2` compressed with the identity as 33 zero bytes;
/// `R = R_1 + b * R_2`, or `G` if that is the identity.
pub fn signing_nonce(
    ids: &[usize],
    aggnonce: (ProjectivePoint, ProjectivePoint),
    tweak_ctx: &TweakContext,
    msg: &[u8],
) -> (Scalar, ProjectivePoint) {
    let mut sorted_ids = ids.to_vec();
    sorted_ids.sort_unstable();
    let ser_ids: Vec<u8> = sorted_ids
        .iter()
        .flat_map(|&id| (id as u32).to_be_bytes())
        .collect();
    let (R1, R2) = aggnonce;

    let b = reduce_scalar_from_bytes(tagged_hash(
        TAG_FROST_NONCECOEF,
        [
            ser_ids.as_slice(),
            &compress_default(&R1),
            &compress_default(&R2),
            &tweak_ctx.xonly_pubkey(),
            msg,
        ]
        .concat(),
    ));

    let R_ = R1 + R2 * b;
    let R = if bool::from(R_.is_identity()) {
        ProjectivePoint::GENERATOR
    } else {
        R_
    };

    (b, R)
}
