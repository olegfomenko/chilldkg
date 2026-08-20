#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::crypto::SecretScalar;
use crate::crypto::ec::{
    BIP340XOnlyPubKey, EC_SCALAR_BYTES_SIZE, X_ONLY_POINT_BYTES_SIZE, compress_point_bip340,
    compress_scalar_bip340, even_y_point, parse_scalar_from_bytes,
};
use crate::errors::{ChillDkgError, Result};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{ProjectivePoint, Scalar};

// 64
pub const SCHNORR_SIG_BYTES_SIZE: usize = X_ONLY_POINT_BYTES_SIZE + EC_SCALAR_BYTES_SIZE;
pub type SchnorrSignature = [u8; SCHNORR_SIG_BYTES_SIZE];

pub trait SchnorrSigner {
    fn message(&self) -> &[u8];
    fn secret_key(&self) -> SecretScalar;
    fn x_only_key(&self) -> (BIP340XOnlyPubKey, SecretScalar) {
        compress_scalar_bip340(&self.secret_key())
    }
    /// x_only_nonce computes nonce value and its commitment which can differ for different
    /// Schnorr instances. It accepts P_x and d -- a results of x_only_key. It obviously can
    /// call x_only_key by itself adding one more call and increasing the overall execution time.
    fn x_only_nonce(
        &self,
        P_x: &BIP340XOnlyPubKey,
        d: &Scalar,
    ) -> Result<(BIP340XOnlyPubKey, SecretScalar)>;
    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar>;
    fn sign(&self) -> Result<SchnorrSignature> {
        chill_dkg_ensure!(
            !bool::from(self.secret_key().is_zero()),
            ChillDkgError::Runtime("Schnorr signing failed: secret key is zero".into()),
        );

        let (P_x, d) = self.x_only_key();
        let (R_x, k) = self.x_only_nonce(&P_x, &d)?;
        let e = self.challenge(&R_x, &P_x)?;
        let s: [u8; EC_SCALAR_BYTES_SIZE] = (k.as_ref() + e * d.as_ref()).to_bytes().into();
        let mut sig = [0u8; SCHNORR_SIG_BYTES_SIZE];
        sig[..X_ONLY_POINT_BYTES_SIZE].copy_from_slice(&R_x);
        sig[X_ONLY_POINT_BYTES_SIZE..].copy_from_slice(&s);
        Ok(sig)
    }
}

pub trait SchnorrVerifier {
    fn message(&self) -> &[u8];

    fn pub_key(&self) -> ProjectivePoint;

    fn x_only_pubkey(&self) -> (ProjectivePoint, BIP340XOnlyPubKey) {
        (
            even_y_point(&self.pub_key()),
            compress_point_bip340(&self.pub_key()),
        )
    }
    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar>;
    fn verify(&self, sig: SchnorrSignature) -> Result<()> {
        chill_dkg_ensure!(
            !bool::from(self.pub_key().is_identity()),
            ChillDkgError::Runtime("Schnorr verification failed: public key is identity".into()),
        );

        let r_x: BIP340XOnlyPubKey = sig[..X_ONLY_POINT_BYTES_SIZE].try_into()?;
        let s: Scalar = parse_scalar_from_bytes(sig[X_ONLY_POINT_BYTES_SIZE..].try_into()?)
            .map_err(|_| {
                ChillDkgError::Runtime(
                    "Schnorr verification failed: invalid response scalar".into(),
                )
            })?;

        let (P, p_x) = self.x_only_pubkey();
        let e = self.challenge(&r_x, &p_x)?;

        let R = ProjectivePoint::GENERATOR * s - P * e;
        chill_dkg_ensure!(
            !bool::from(R.is_identity()),
            ChillDkgError::Runtime("Schnorr verification failed: nonce is identity".into()),
        );

        let R = R.to_affine();
        chill_dkg_ensure!(
            !bool::from(R.y_is_odd()),
            ChillDkgError::Runtime("Schnorr verification failed: nonce has odd Y".into()),
        );

        let computed_r_x: [u8; X_ONLY_POINT_BYTES_SIZE] = R.x().into();
        if computed_r_x != r_x {
            return Err(ChillDkgError::Runtime(
                "Schnorr verification failed: invalid signature".into(),
            ));
        }

        Ok(())
    }
}
