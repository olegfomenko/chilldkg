#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::ec::{
    BIP340XOnlyPubKey, COMPRESSED_POINT_BYTES_SIZE, CompressedPubKey, EC_SCALAR_BYTES_SIZE,
    compress_default, compress_scalar_bip340, decompress_default,
};
use crate::crypto::pop::SchnorrSignature;
use crate::crypto::schnorr::{SchnorrSigner, SchnorrVerifier};
use crate::crypto::tags::{
    TAG_BIP340_AUX, TAG_BIP340_CHALLENGE, TAG_BIP340_NONCE, TAG_CERTEQ_MESSAGE,
};
use crate::crypto::{scalar_from_bytes, tagged_hash};
use crate::errors::ChillDkgError;
use anyhow::{Context, Result, ensure};
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};

/// Certificate-of-equality transcript.
///
/// This data contains the public transcript received by a participant during
/// the DKG protocol execution. Its serialized form is signed to create the
/// certificate of equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertEQTranscript {
    /// DKG threshold.
    ///
    /// Math: `t`.
    pub t: usize,

    /// Aggregate VSS commitment before Taproot tweaking.
    ///
    /// Math: `C_k = sum_i C_{i,k}` for `k = 0, ..., t - 1`.
    pub sum_commitment: Vec<ProjectivePoint>,

    /// Ordered participant host public keys.
    ///
    /// Math: `P_i` is the host public key of participant `i`.
    pub host_pubkeys: Vec<ProjectivePoint>,

    /// Ordered public encryption nonces.
    ///
    /// Math: `R_i`.
    pub pubnonces: Vec<ProjectivePoint>,

    /// Aggregated encrypted secret shares.
    ///
    /// Math: `hat_u_i`.
    pub enc_secshares: Vec<Scalar>,
}

impl CertEQTranscript {
    pub fn new(
        t: usize,
        sum_commitment: Vec<ProjectivePoint>,
        host_pubkeys: Vec<ProjectivePoint>,
        pubnonces: Vec<ProjectivePoint>,
        enc_secshares: Vec<Scalar>,
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

impl From<&CertEQTranscript> for Vec<u8> {
    fn from(transcript: &CertEQTranscript) -> Self {
        let mut bytes = Vec::with_capacity(
            4 + COMPRESSED_POINT_BYTES_SIZE
                * (transcript.sum_commitment.len()
                    + transcript.host_pubkeys.len()
                    + transcript.pubnonces.len())
                + EC_SCALAR_BYTES_SIZE * transcript.enc_secshares.len(),
        );

        bytes.extend_from_slice(&(transcript.t as u32).to_be_bytes());
        for C_k in &transcript.sum_commitment {
            bytes.extend_from_slice(&compress_default(C_k));
        }
        for P_i in &transcript.host_pubkeys {
            bytes.extend_from_slice(&compress_default(P_i));
        }
        for R_i in &transcript.pubnonces {
            bytes.extend_from_slice(&compress_default(R_i));
        }
        for enc_secshare in &transcript.enc_secshares {
            let scalar_bytes: [u8; EC_SCALAR_BYTES_SIZE] = enc_secshare.to_bytes().into();
            bytes.extend_from_slice(&scalar_bytes);
        }

        bytes
    }
}

impl TryFrom<(&[u8], usize)> for CertEQTranscript {
    type Error = anyhow::Error;

    fn try_from((bytes, n): (&[u8], usize)) -> Result<Self, Self::Error> {
        ensure!(bytes.len() >= 4, "invalid CertEq transcript length");

        let t = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
        ensure!(
            bytes.len()
                == 4 + COMPRESSED_POINT_BYTES_SIZE * t
                    + (COMPRESSED_POINT_BYTES_SIZE
                        + COMPRESSED_POINT_BYTES_SIZE
                        + EC_SCALAR_BYTES_SIZE)
                        * n,
            "invalid CertEq transcript length"
        );

        let mut offset = 4;

        let mut sum_commitment: Vec<ProjectivePoint> = Vec::with_capacity(t);
        let mut host_pubkeys: Vec<ProjectivePoint> = Vec::with_capacity(n);
        let mut pubnonces: Vec<ProjectivePoint> = Vec::with_capacity(n);
        let mut enc_secshares: Vec<Scalar> = Vec::with_capacity(n);

        for _ in 0..t {
            let compressed: &CompressedPubKey =
                (&bytes[offset..offset + COMPRESSED_POINT_BYTES_SIZE]).try_into()?;
            offset += COMPRESSED_POINT_BYTES_SIZE;
            sum_commitment
                .push(decompress_default(compressed).context("invalid commitment point")?);
        }

        for i in 0..n {
            let compressed: &CompressedPubKey =
                (&bytes[offset..offset + COMPRESSED_POINT_BYTES_SIZE]).try_into()?;
            offset += COMPRESSED_POINT_BYTES_SIZE;
            host_pubkeys.push(
                decompress_default(compressed)
                    .ok_or(ChillDkgError::InvalidHostPubkeyError { participant: i })?,
            );
        }

        for _ in 0..n {
            let compressed: &CompressedPubKey =
                (&bytes[offset..offset + COMPRESSED_POINT_BYTES_SIZE]).try_into()?;
            offset += COMPRESSED_POINT_BYTES_SIZE;
            pubnonces.push(decompress_default(compressed).context("invalid public nonce point")?);
        }

        for _ in 0..n {
            let bytes: [u8; EC_SCALAR_BYTES_SIZE] =
                (&bytes[offset..offset + EC_SCALAR_BYTES_SIZE]).try_into()?;
            offset += EC_SCALAR_BYTES_SIZE;
            enc_secshares.push(scalar_from_bytes(bytes).context("invalid enc share scalar")?);
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

pub fn verify_certeq_certificate(
    transcript: &CertEQTranscript,
    cert: &[SchnorrSignature],
) -> Result<()> {
    let host_pubkeys = &transcript.host_pubkeys;

    chill_dkg_ensure!(
        cert.len() == host_pubkeys.len(),
        ChillDkgError::FaultyCoordinatorError("invalid certificate length".to_owned(),),
    );

    for i in 0..host_pubkeys.len() {
        if let Err(err) = CertEQVerifier::new(host_pubkeys[i], transcript, i).verify(cert[i]) {
            return Err(
                ChillDkgError::FaultyParticipantOrCoordinatorError {
                    participant: i,
                    message: format!(
                        "Participant has provided an invalid signature for the certificate, error = {:?}",
                        err
                    ),
                }
                .into());
        }
    }

    Ok(())
}

pub struct CertEQSigner {
    hostkey: Scalar,
    message: Vec<u8>,
    aux_rand: [u8; 32],
}

impl CertEQSigner {
    pub fn new(
        hostkey: Scalar,
        transcript: &CertEQTranscript,
        idx: usize,
        aux_rand: [u8; 32],
    ) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQSigner {
            hostkey,
            message,
            aux_rand,
        }
    }
}

impl SchnorrSigner for CertEQSigner {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn secret_key(&self) -> Scalar {
        self.hostkey
    }

    fn x_only_nonce(&self) -> Result<(BIP340XOnlyPubKey, Scalar)> {
        let (p_x, d) = self.x_only_key();
        let aux_hash = tagged_hash(TAG_BIP340_AUX, self.aux_rand);

        let mut t: [u8; EC_SCALAR_BYTES_SIZE] = d.to_bytes().into();
        for i in 0..EC_SCALAR_BYTES_SIZE {
            t[i] ^= aux_hash[i];
        }

        let mut nonce_preimage =
            Vec::with_capacity(EC_SCALAR_BYTES_SIZE * 2 + self.message().len());
        nonce_preimage.extend_from_slice(&t);
        nonce_preimage.extend_from_slice(&p_x);
        nonce_preimage.extend_from_slice(self.message());

        let k0 = Scalar::reduce(U256::from_be_slice(&tagged_hash(
            TAG_BIP340_NONCE,
            nonce_preimage,
        )));

        ensure!(
            !bool::from(k0.is_zero()),
            "CertEq signing failed: BIP340: nonce is zero"
        );

        Ok(compress_scalar_bip340(&k0))
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_certeq_challenge(R, P, self.message())
    }
}

pub struct CertEQVerifier {
    host_pubkey: ProjectivePoint,
    message: Vec<u8>,
}

impl CertEQVerifier {
    pub fn new(host_pubkey: ProjectivePoint, transcript: &CertEQTranscript, idx: usize) -> Self {
        let message = get_certeq_message(transcript, idx);
        CertEQVerifier {
            host_pubkey,
            message,
        }
    }
}

impl SchnorrVerifier for CertEQVerifier {
    fn message(&self) -> &[u8] {
        self.message.as_slice()
    }

    fn pub_key(&self) -> ProjectivePoint {
        self.host_pubkey
    }

    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar> {
        get_certeq_challenge(R, P, self.message())
    }
}

fn get_certeq_challenge(
    R: &BIP340XOnlyPubKey,
    P: &BIP340XOnlyPubKey,
    message: &[u8],
) -> Result<Scalar> {
    let mut challenge_preimage = Vec::with_capacity(EC_SCALAR_BYTES_SIZE * 2 + message.len());
    challenge_preimage.extend_from_slice(R);
    challenge_preimage.extend_from_slice(P);
    challenge_preimage.extend_from_slice(message);

    Ok(Scalar::reduce(U256::from_be_slice(&tagged_hash(
        TAG_BIP340_CHALLENGE,
        challenge_preimage,
    ))))
}

fn get_certeq_message(transcript: &CertEQTranscript, idx: usize) -> Vec<u8> {
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

    #[test]
    fn certeq_transcript_serialization_roundtrips() -> Result<()> {
        let G = ProjectivePoint::GENERATOR;
        let transcript = CertEQTranscript::new(
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
