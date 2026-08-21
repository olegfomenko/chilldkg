#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::curve::{
    ByteArray, Curve, CurvePoint, CurveScalar, PointBytes, ScalarBytes, XOnlyBytes,
};
use crate::crypto::ec::{compress_scalar_bip340, parse_scalar_from_bytes, reduce_scalar_from_hash};
use crate::crypto::pop::SchnorrSignature;
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tags::{
    TAG_BIP340_AUX, TAG_BIP340_CHALLENGE, TAG_BIP340_NONCE, TAG_CERTEQ_MESSAGE,
};
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::{ChillDkgError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Certificate-of-equality transcript.
///
/// This data contains the public transcript received by a participant during
/// the DKG protocol execution. Its serialized form is signed to create the
/// certificate of equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertEQTranscript<C: Curve> {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Aggregate VSS commitment before Taproot tweaking.
    ///
    /// Math: `C_k = sum_i C_{i,k}` for `k = 0, ..., t - 1`.
    pub sum_commitment: Vec<C::Point>,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<C::Point>,

    /// Ordered public encryption nonces.
    ///
    /// Math: `R_i`.
    pub pubnonces: Vec<C::Point>,

    /// Aggregated encrypted secret shares.
    ///
    /// Math: `hat_u_i`.
    pub enc_secshares: Vec<C::Scalar>,
}

impl<C: Curve> CertEQTranscript<C> {
    pub fn new(
        t: usize,
        sum_commitment: Vec<C::Point>,
        host_pubkeys: Vec<C::Point>,
        pubnonces: Vec<C::Point>,
        enc_secshares: Vec<C::Scalar>,
    ) -> Self {
        Self {
            t,
            sum_commitment,
            host_pubkeys,
            pubnonces,
            enc_secshares,
        }
    }

    pub fn n(&self) -> usize {
        self.host_pubkeys.len()
    }
}

impl<C: Curve> From<&CertEQTranscript<C>> for Vec<u8> {
    fn from(transcript: &CertEQTranscript<C>) -> Self {
        let mut bytes = Vec::with_capacity(
            4 + <C::Point as CurvePoint>::BYTES_SIZE
                * (transcript.sum_commitment.len()
                    + transcript.host_pubkeys.len()
                    + transcript.pubnonces.len())
                + <C::Scalar as CurveScalar>::BYTES_SIZE * transcript.enc_secshares.len(),
        );

        bytes.extend_from_slice(&(transcript.t as u32).to_be_bytes());
        for C_k in &transcript.sum_commitment {
            bytes.extend_from_slice(C_k.to_bytes().as_ref());
        }
        for P_i in &transcript.host_pubkeys {
            bytes.extend_from_slice(P_i.to_bytes().as_ref());
        }
        for R_i in &transcript.pubnonces {
            bytes.extend_from_slice(R_i.to_bytes().as_ref());
        }
        for enc_secshare in &transcript.enc_secshares {
            bytes.extend_from_slice(enc_secshare.to_bytes().as_ref());
        }

        bytes
    }
}

impl<C: Curve> TryFrom<(&[u8], usize)> for CertEQTranscript<C> {
    type Error = ChillDkgError;

    fn try_from((bytes, n): (&[u8], usize)) -> std::result::Result<Self, Self::Error> {
        let point_size = <C::Point as CurvePoint>::BYTES_SIZE;
        let scalar_size = <C::Scalar as CurveScalar>::BYTES_SIZE;

        chill_dkg_ensure!(
            bytes.len() >= 4,
            ChillDkgError::RuntimeError("invalid CertEq transcript length".to_owned()),
        );

        let t = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
        chill_dkg_ensure!(
            bytes.len() == 4 + point_size * t + (point_size * 2 + scalar_size) * n,
            ChillDkgError::RuntimeError("invalid CertEq transcript length".to_owned()),
        );

        let mut offset = 4;

        let mut sum_commitment: Vec<C::Point> = Vec::with_capacity(t);
        let mut host_pubkeys: Vec<C::Point> = Vec::with_capacity(n);
        let mut pubnonces: Vec<C::Point> = Vec::with_capacity(n);
        let mut enc_secshares: Vec<C::Scalar> = Vec::with_capacity(n);

        let take_point = |offset: &mut usize| -> Option<C::Point> {
            let encoded = PointBytes::<C>::from_slice(&bytes[*offset..*offset + point_size])?;
            *offset += point_size;
            C::Point::from_bytes(&encoded)
        };

        for _ in 0..t {
            sum_commitment.push(take_point(&mut offset).ok_or_else(|| {
                ChillDkgError::RuntimeError("invalid commitment point".to_owned())
            })?);
        }

        for i in 0..n {
            host_pubkeys.push(
                take_point(&mut offset)
                    .ok_or(ChillDkgError::InvalidHostPubkeyError { participant: i })?,
            );
        }

        for _ in 0..n {
            pubnonces.push(take_point(&mut offset).ok_or_else(|| {
                ChillDkgError::RuntimeError("invalid public nonce point".to_owned())
            })?);
        }

        for _ in 0..n {
            let scalar_bytes = ScalarBytes::<C>::from_slice(&bytes[offset..offset + scalar_size])
                .ok_or_else(|| {
                ChillDkgError::RuntimeError("invalid encrypted secret share".to_owned())
            })?;
            offset += scalar_size;
            enc_secshares.push(parse_scalar_from_bytes::<C>(&scalar_bytes)?);
        }

        Ok(Self {
            t,
            sum_commitment,
            host_pubkeys,
            pubnonces,
            enc_secshares,
        })
    }
}

pub fn verify_certeq_certificate<C: Curve>(
    transcript: &CertEQTranscript<C>,
    cert: &[SchnorrSignature<C>],
) -> Result<()> {
    let host_pubkeys = &transcript.host_pubkeys;

    chill_dkg_ensure!(
        cert.len() == host_pubkeys.len(),
        ChillDkgError::FaultyCoordinatorError("invalid certificate length".to_owned(),),
    );

    for i in 0..host_pubkeys.len() {
        if let Err(err) = CertEQVerifier::new(host_pubkeys[i], transcript, i).verify(cert[i]) {
            return Err(ChillDkgError::FaultyParticipantOrCoordinatorError {
                participant: i,
                message: format!(
                    "Participant has provided an invalid signature for the certificate, error = {:?}",
                    err
                ),
            });
        }
    }

    Ok(())
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CertEQSigner<C: Curve> {
    hostkey: C::Scalar,
    message: Vec<u8>,
    aux_rand: [u8; 32],
}

impl<C: Curve> CertEQSigner<C> {
    pub fn new(
        hostkey: &C::Scalar,
        transcript: &CertEQTranscript<C>,
        idx: usize,
        aux_rand: [u8; 32],
    ) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQSigner {
            hostkey: *hostkey,
            message,
            aux_rand,
        }
    }
}

impl<C: Curve> SchnorrSigner<C> for CertEQSigner<C> {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn secret_key(&self) -> SecretScalar<C> {
        Zeroizing::new(self.hostkey)
    }

    fn x_only_nonce(
        &self,
        P_x: &XOnlyBytes<C>,
        d: &C::Scalar,
    ) -> Result<(XOnlyBytes<C>, SecretScalar<C>)> {
        let aux_hash = tagged_hash::<C>(TAG_BIP340_AUX, self.aux_rand);

        let mut t: Zeroizing<ScalarBytes<C>> = Zeroizing::new(d.to_bytes());
        for (t_i, aux_i) in t.as_mut().iter_mut().zip(aux_hash.as_ref()) {
            *t_i ^= aux_i;
        }

        let mut nonce_preimage = Zeroizing::new(Vec::with_capacity(
            <C::Scalar as CurveScalar>::BYTES_SIZE
                + <C::Point as CurvePoint>::X_ONLY_BYTES_SIZE
                + self.message().len(),
        ));
        nonce_preimage.extend_from_slice(t.as_ref());
        nonce_preimage.extend_from_slice(P_x.as_ref());
        nonce_preimage.extend_from_slice(self.message());

        let preimage_hash = Zeroizing::new(tagged_hash::<C>(TAG_BIP340_NONCE, &nonce_preimage));
        let k0 = reduce_scalar_from_hash::<C>(&preimage_hash);

        chill_dkg_ensure!(
            !k0.is_zero(),
            ChillDkgError::RuntimeError("CertEq signing failed: BIP340: nonce is zero".to_owned()),
        );

        Ok(compress_scalar_bip340::<C>(&k0))
    }

    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar> {
        get_certeq_challenge::<C>(R, P, self.message())
    }
}

pub struct CertEQVerifier<C: Curve> {
    host_pubkey: C::Point,
    message: Vec<u8>,
}

impl<C: Curve> CertEQVerifier<C> {
    pub fn new(host_pubkey: C::Point, transcript: &CertEQTranscript<C>, idx: usize) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQVerifier {
            host_pubkey,
            message,
        }
    }
}

impl<C: Curve> SchnorrVerifier<C> for CertEQVerifier<C> {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn pub_key(&self) -> C::Point {
        self.host_pubkey
    }

    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar> {
        get_certeq_challenge::<C>(R, P, self.message())
    }
}

fn get_certeq_challenge<C: Curve>(
    R: &XOnlyBytes<C>,
    P: &XOnlyBytes<C>,
    message: &[u8],
) -> Result<C::Scalar> {
    let mut challenge_preimage =
        Vec::with_capacity(<C::Point as CurvePoint>::X_ONLY_BYTES_SIZE * 2 + message.len());
    challenge_preimage.extend_from_slice(R.as_ref());
    challenge_preimage.extend_from_slice(P.as_ref());
    challenge_preimage.extend_from_slice(message);

    Ok(C::hash_to_scalar(&tagged_hash::<C>(
        TAG_BIP340_CHALLENGE,
        challenge_preimage,
    )))
}

fn get_certeq_message<C: Curve>(transcript: &CertEQTranscript<C>, idx: usize) -> Vec<u8> {
    //   ("BIP DKG/certeq message" || zero padding to 33 bytes)
    //   || uint32_be(idx)
    //   || transcript

    const CERTEQ_MSG_PADDING_SIZE: usize = 33;

    let transcript: Vec<u8> = transcript.into();
    let tag = TAG_CERTEQ_MESSAGE.as_bytes();
    let mut message = Vec::with_capacity(CERTEQ_MSG_PADDING_SIZE + 4 + transcript.len());

    message.extend_from_slice(tag);
    message.resize(CERTEQ_MSG_PADDING_SIZE, 0);
    message.extend_from_slice(&(idx as u32).to_be_bytes());
    message.extend_from_slice(&transcript);

    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::Secp256k1;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn certeq_transcript_serialization_roundtrips() -> Result<()> {
        let G = ProjectivePoint::GENERATOR;
        let transcript = CertEQTranscript::<Secp256k1>::new(
            2,
            vec![G * Scalar::from(3u64), G * Scalar::from(4u64)],
            vec![
                G * Scalar::from(5u64),
                G * Scalar::from(6u64),
                G * Scalar::from(7u64),
            ],
            vec![
                G * Scalar::from(8u64),
                G * Scalar::from(9u64),
                G * Scalar::from(10u64),
            ],
            vec![
                Scalar::from(11u64),
                Scalar::from(12u64),
                Scalar::from(13u64),
            ],
        );

        let serialized: Vec<u8> = (&transcript).into();
        let transcript1 = CertEQTranscript::try_from((serialized.as_slice(), 3usize))?;

        assert_eq!(transcript1, transcript);

        Ok(())
    }
}
