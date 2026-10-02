#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

//! Verification and aggregation of FROST3 contributions: the checks anyone
//! can run with only the public key material, and the shared math the
//! signer and coordinator state machines are built on.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    X_ONLY_POINT_BYTES_SIZE, compress_default, compress_point_bip340, has_even_y,
    reduce_scalar_from_bytes,
};
use crate::crypto::lagrange::{interpolate_pubkey, lagrange};
use crate::crypto::schnorr::{
    SCHNORR_SIG_BYTES_SIZE, SchnorrSignature, SchnorrVerifier, bip340_challenge,
};
use crate::crypto::tagged_hash;
use crate::crypto::tags::TAG_FROST_NONCECOEF;
use crate::crypto::tweak::{Tweak, TweakContext};
use crate::sign::errors::{Result, SignError};
use crate::sign::msg::{PartialSignature, PubNonce};
use itertools::Itertools;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// Checks that `ids` is a valid signing subset for the key material:
/// `t <= |ids| <= n`, every id is in range, no duplicates, no identity
/// public share, and the subset's public shares interpolate to the
/// threshold key.
///
/// Mirrors the reference `validate_signers_ctx`.
pub fn validate_signers(
    t: usize,
    pubshares: &[ProjectivePoint],
    threshold_pubkey: &ProjectivePoint,
    ids: &[usize],
) -> Result<()> {
    let n = pubshares.len();
    chill_dkg_ensure!(
        t >= 1 && t <= n,
        SignError::Value("The threshold must be 1 <= t <= n.".into()),
    );
    chill_dkg_ensure!(
        t <= ids.len() && ids.len() <= n,
        SignError::Value("The number of signers must be between t and n.".into()),
    );
    for (idx, &id) in ids.iter().enumerate() {
        chill_dkg_ensure!(
            id < n,
            SignError::Value(
                format!("The participant identifier at index {idx} is out of range.").into()
            ),
        );
        chill_dkg_ensure!(
            !bool::from(pubshares[id].is_identity()),
            SignError::Value(format!("Invalid pubshare at index {idx}.").into()),
        );
    }

    chill_dkg_ensure!(
        ids.iter().all_unique(),
        SignError::Value("The participant identifier list contains duplicate elements.".into()),
    );

    let pubshares: Vec<ProjectivePoint> = ids.iter().map(|&id| pubshares[id]).collect();
    chill_dkg_ensure!(
        &interpolate_pubkey(ids, &pubshares)? == threshold_pubkey,
        SignError::Value("The provided key material is incorrect.".into()),
    );
    Ok(())
}

/// The key a signature produced with `tweaks` verifies under (BIP340 x-only
/// semantics).
pub fn signing_pubkey(
    threshold_pubkey: &ProjectivePoint,
    tweaks: &[Tweak],
) -> Result<ProjectivePoint> {
    Ok(TweakContext::new(*threshold_pubkey).apply_all(tweaks)?.q)
}

/// Verifies a final signature over `msg` as a plain BIP340 signature under
/// the threshold key tweaked by `tweaks`.
pub fn verify(
    threshold_pubkey: &ProjectivePoint,
    sig: SchnorrSignature,
    msg: &[u8],
    tweaks: &[Tweak],
) -> Result<()> {
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
        Q: signing_pubkey(threshold_pubkey, tweaks)?,
    }
    .verify(sig)?;
    Ok(())
}

/// Nonce coefficient and final nonce of the session, from the signing subset
/// (in any order; committed to as a set) and the aggregate nonce.
///
/// Math: `b = H_noncecoef(ser_ids || aggnonce || Q_x || msg)` where ser_ids is
/// the sorted ids as 4-byte big-endian integers (a set, per ROAST) and aggnonce
/// is `R_1 || R_2` compressed with the identity as 33 zero bytes;
/// `R = R_1 + b * R_2`, or `G` if that is the identity. Fails if `b` is zero, which
/// cannot occur except with negligible probability (the reference asserts it).
pub fn signing_nonce(
    ids: &[usize],
    aggnonce: (ProjectivePoint, ProjectivePoint),
    tweak_ctx: &TweakContext,
    msg: &[u8],
) -> Result<(Scalar, ProjectivePoint)> {
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

    chill_dkg_ensure!(
        !bool::from(b.is_zero()),
        SignError::Runtime("nonce coefficient is zero".into()),
    );

    let R_ = R1 + R2 * b;
    let R = if bool::from(R_.is_identity()) {
        ProjectivePoint::GENERATOR
    } else {
        R_
    };

    Ok((b, R))
}

/// The session's BIP340 challenge.
///
/// Math: `e = H_challenge(R_x || Q_x || msg)`. Fails if `e` is zero, which
/// cannot occur except with negligible probability (the reference asserts it).
pub fn challenge(R: &ProjectivePoint, tweak_ctx: &TweakContext, msg: &[u8]) -> Result<Scalar> {
    let e = bip340_challenge(&compress_point_bip340(R), &tweak_ctx.xonly_pubkey(), msg)?;
    chill_dkg_ensure!(
        !bool::from(e.is_zero()),
        SignError::Runtime("challenge is zero".into()),
    );

    Ok(e)
}

/// Math: `s_i * G == R_i' + (e * a_i * g * gacc) * Y_i`, where
/// `R_i' = R_{i,1} + b * R_{i,2}`, negated if `R` has an odd `y`.
#[expect(clippy::too_many_arguments)]
pub fn partial_verify(
    psig: &PartialSignature,
    id: usize,
    pubnonce: &PubNonce,
    pubshare: &ProjectivePoint,
    ids: &[usize],
    tweak_ctx: &TweakContext,
    b: Scalar,
    R: &ProjectivePoint,
    e: Scalar,
) -> Result<()> {
    chill_dkg_ensure!(
        !pubnonce.is_identity(),
        SignError::InvalidContribution {
            participant: id,
            message: "invalid pubnonce".into(),
        },
    );

    let Re_s_ = pubnonce.R1 + pubnonce.R2 * b;
    let Re_s = if has_even_y(R) { Re_s_ } else { -Re_s_ };

    // Fails if id is not among the signers.
    let a = lagrange(ids, id)?;
    let g_ = tweak_ctx.g() * tweak_ctx.gacc;

    chill_dkg_ensure!(
        ProjectivePoint::GENERATOR * psig == Re_s + pubshare * &(e * a * g_),
        SignError::InvalidContribution {
            participant: id,
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

/// Combines the signers' public nonces.
///
/// Math: `R_j = sum_i R_{i,j}` for `j = 1, 2`.
pub fn aggr_pubnonces<'a>(
    iter: impl Iterator<Item = &'a PubNonce>,
) -> (ProjectivePoint, ProjectivePoint) {
    let mut R1 = ProjectivePoint::IDENTITY;
    let mut R2 = ProjectivePoint::IDENTITY;
    iter.for_each(|pubnonce| {
        R1 += pubnonce.R1;
        R2 += pubnonce.R2;
    });

    (R1, R2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ec::{decompress_default, parse_scalar_from_bytes};

    fn point(hex: &str) -> ProjectivePoint {
        decompress_default(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    fn scalar(hex: &str) -> Scalar {
        parse_scalar_from_bytes(hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    /// The `sig_agg` reference vectors: combining partial signatures given
    /// only the aggregate nonce (the reference `partial_sig_agg`).
    #[test]
    fn combine_matches_sig_agg_vectors() {
        let threshold_pubkey =
            point("03B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237");
        let msg = hex::decode("599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869")
            .unwrap();

        // (ids, aggregate nonce as R1 || R2, tweaks, psigs, expected signature)
        for (ids, aggnonce, tweaks, psigs, expected) in [
            // Minimum threshold subset of signers (t=2 of n=3), no tweaks
            (
                vec![0, 1],
                "02ABA4374155062E973007AC12D2CB1BCB70A76ACF3CFCE6F9E2160CF5D7DD4CCB03EB324CCEF66810F01197F28E63B97B50D7F6503940709E8DDD0313144D039568",
                vec![],
                vec![
                    "911E1C3821D5C4314C32BF7B312C39B7D9A2C54FB3EF1E3349395299A781ED93",
                    "6F6E24B9ADD50F74B329F27A6EC30250A89938AD8C9CBE0235BD8EB8EAEA9EE2",
                ],
                "5527965735029EAD5BBF977E71E06B601589E22E241F11DD68F420E75FE4AC63008C40F1CFAAD3A5FF5CB1F59FEF3C09C78D211691433BF9BF2482C5C2364B34",
            ),
            // Signer order does not affect the aggregate signature: partial signatures are summed, so this matches the first valid case
            (
                vec![1, 0],
                "02ABA4374155062E973007AC12D2CB1BCB70A76ACF3CFCE6F9E2160CF5D7DD4CCB03EB324CCEF66810F01197F28E63B97B50D7F6503940709E8DDD0313144D039568",
                vec![],
                vec![
                    "6F6E24B9ADD50F74B329F27A6EC30250A89938AD8C9CBE0235BD8EB8EAEA9EE2",
                    "911E1C3821D5C4314C32BF7B312C39B7D9A2C54FB3EF1E3349395299A781ED93",
                ],
                "5527965735029EAD5BBF977E71E06B601589E22E241F11DD68F420E75FE4AC63008C40F1CFAAD3A5FF5CB1F59FEF3C09C78D211691433BF9BF2482C5C2364B34",
            ),
            // Aggregation with three tweaks applied (one x-only, two plain)
            (
                vec![0, 1],
                "02ABA4374155062E973007AC12D2CB1BCB70A76ACF3CFCE6F9E2160CF5D7DD4CCB03EB324CCEF66810F01197F28E63B97B50D7F6503940709E8DDD0313144D039568",
                vec![
                    (
                        "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
                        true,
                    ),
                    (
                        "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
                        false,
                    ),
                    (
                        "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
                        false,
                    ),
                ],
                vec![
                    "BFFDAC5F3CB017F2DEF06D1D7703A50875CF18D4F9CFCFE1FD0261D1250655A8",
                    "1792D36FD56EBA5A303C7F7E367B3EB48D6F631258FF396C36F4AA7D268039FA",
                ],
                "6D5558EB783A023F2A09BDE65D3E9DB79928702D4143BCFD69C2074C9A143F5108D818ADC9BD3AA2B9DC669B66AD9EF420FDBF97558DB65D9528C27FBEB3308E",
            ),
            // All n=3 signers participate, no tweaks
            (
                vec![0, 1, 2],
                "021F4A843C6740C0F36AF26DF2D3DBBD5DF5A79037579F4C979B2FE0B047FE2A88035DE91B1E9BFC222DCF83A8D2C7C468EB3B2F104661F6358257E7A90EA9BA7B92",
                vec![],
                vec![
                    "96CCC80C315D5F61DA34B6FF7FB86CFB642FD1410089B7B6CE205C50C22891CF",
                    "33E5776846D493D422F995B676A73ACE7897345081DC569B2FE3BC0940F72DD6",
                    "B907873BD954272E5B3E97DAC1CC93D6DF1BF8161A69D2C548B3C1D405CF1C2C",
                ],
                "12FADDB3E8C8A8B95E6C36E5B33CB657A840A2EC1DDABCC19D05E99FD71F637583B9C6B051861A64586CE490B82C3BA2013420C0ED8740DB86E57BA138B89A90",
            ),
        ] {
            let tweaks: Vec<Tweak> = tweaks
                .iter()
                .map(|&(hex, is_xonly)| Tweak {
                    value: hex::decode(hex).unwrap().try_into().unwrap(),
                    is_xonly,
                })
                .collect();
            let psigs: Vec<PartialSignature> = psigs.iter().map(|hex| scalar(hex)).collect();

            let tweak_ctx = TweakContext::new(threshold_pubkey)
                .apply_all(&tweaks)
                .unwrap();
            let (_, R) = signing_nonce(
                &ids,
                (point(&aggnonce[..66]), point(&aggnonce[66..])),
                &tweak_ctx,
                &msg,
            )
            .unwrap();
            let e = challenge(&R, &tweak_ctx, &msg).unwrap();

            let sig = combine(psigs.iter(), &tweak_ctx, &R, e);
            assert_eq!(hex::encode_upper(sig), expected);
            verify(&threshold_pubkey, sig, &msg, &tweaks).unwrap();
        }
    }
}
