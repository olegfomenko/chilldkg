#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::SecretScalar;
use crate::crypto::curve::{ByteArray, Curve, CurvePoint, CurveScalar, ScalarBytes, XOnlyBytes};
use crate::crypto::ec::{compress_scalar_bip340, even_y_point, parse_scalar_from_bytes};
use crate::errors::{ChillDkgError, Result};

/// A BIP340 Schnorr signature.
///
/// Math: `sigma = (R_x, s)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchnorrSignature<C: Curve> {
    /// X-only encoding of the public nonce.
    ///
    /// Math: `R_x`.
    pub pubnonce: XOnlyBytes<C>,

    /// Canonical encoding of the response scalar.
    ///
    /// Math: `s = k + e*d mod n`.
    pub response: ScalarBytes<C>,
}

impl<C: Curve> SchnorrSignature<C> {
    /// Size of the serialized signature.
    pub const BYTES_SIZE: usize =
        <C::Point as CurvePoint>::X_ONLY_BYTES_SIZE + <C::Scalar as CurveScalar>::BYTES_SIZE;

    /// Serializes the signature as `R_x || bytes(s)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::BYTES_SIZE);
        bytes.extend_from_slice(self.pubnonce.as_ref());
        bytes.extend_from_slice(self.response.as_ref());
        bytes
    }

    /// Parses a signature serialized as `R_x || bytes(s)`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        chill_dkg_ensure!(
            bytes.len() == Self::BYTES_SIZE,
            ChillDkgError::MsgParseError("invalid Schnorr signature length".to_owned()),
        );

        let (pubnonce, response) = bytes.split_at(<C::Point as CurvePoint>::X_ONLY_BYTES_SIZE);

        Ok(Self {
            pubnonce: XOnlyBytes::<C>::from_slice(pubnonce)
                .ok_or_else(|| ChillDkgError::MsgParseError("invalid public nonce".to_owned()))?,
            response: ScalarBytes::<C>::from_slice(response)
                .ok_or_else(|| ChillDkgError::MsgParseError("invalid response".to_owned()))?,
        })
    }
}

pub trait SchnorrSigner<C: Curve> {
    fn message(&self) -> &[u8];
    fn secret_key(&self) -> SecretScalar<C>;
    fn x_only_key(&self) -> (XOnlyBytes<C>, SecretScalar<C>) {
        compress_scalar_bip340::<C>(&self.secret_key())
    }
    /// x_only_nonce computes nonce value and its commitment which can differ for different
    /// Schnorr instances. It accepts P_x and d -- a results of x_only_key. It obviously can
    /// call x_only_key by itself adding one more call and increasing the overall execution time.
    fn x_only_nonce(
        &self,
        P_x: &XOnlyBytes<C>,
        d: &C::Scalar,
    ) -> Result<(XOnlyBytes<C>, SecretScalar<C>)>;
    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar>;
    fn sign(&self) -> Result<SchnorrSignature<C>> {
        chill_dkg_ensure!(
            !self.secret_key().is_zero(),
            ChillDkgError::RuntimeError("Schnorr signing failed: secret key is zero".to_owned()),
        );

        let (P_x, d) = self.x_only_key();
        let (R_x, k) = self.x_only_nonce(&P_x, &d)?;
        let e = self.challenge(&R_x, &P_x)?;
        let s = *k + e * *d;

        Ok(SchnorrSignature {
            pubnonce: R_x,
            response: s.to_bytes(),
        })
    }
}

pub trait SchnorrVerifier<C: Curve> {
    fn message(&self) -> &[u8];

    fn pub_key(&self) -> C::Point;

    fn x_only_pubkey(&self) -> (C::Point, XOnlyBytes<C>) {
        (
            even_y_point::<C>(&self.pub_key()),
            self.pub_key().to_x_only_bytes(),
        )
    }
    fn challenge(&self, R: &XOnlyBytes<C>, P: &XOnlyBytes<C>) -> Result<C::Scalar>;
    fn verify(&self, sig: SchnorrSignature<C>) -> Result<()> {
        chill_dkg_ensure!(
            !self.pub_key().is_identity(),
            ChillDkgError::RuntimeError(
                "Schnorr verification failed: public key is identity".to_owned()
            ),
        );

        let s = parse_scalar_from_bytes::<C>(&sig.response).map_err(|_| {
            ChillDkgError::RuntimeError(
                "Schnorr verification failed: invalid response scalar".to_owned(),
            )
        })?;

        let (P, p_x) = self.x_only_pubkey();
        let e = self.challenge(&sig.pubnonce, &p_x)?;

        let R = C::Point::GENERATOR * s - P * e;
        chill_dkg_ensure!(
            !R.is_identity(),
            ChillDkgError::RuntimeError(
                "Schnorr verification failed: nonce is identity".to_owned()
            ),
        );
        chill_dkg_ensure!(
            !R.has_odd_y(),
            ChillDkgError::RuntimeError("Schnorr verification failed: nonce has odd Y".to_owned()),
        );

        if R.to_x_only_bytes() != sig.pubnonce {
            return Err(ChillDkgError::RuntimeError(
                "Schnorr verification failed: invalid signature".to_owned(),
            ));
        }

        Ok(())
    }
}
