#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::crypto::ec::{
    BIP340XOnlyPubKey, compress_point_bip340, compress_scalar_bip340, even_y_point,
};
use crate::crypto::scalar_from_bytes;
use anyhow::{Context, Result, bail, ensure};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{ProjectivePoint, Scalar};

pub type SchnorrSignature = [u8; 64];

pub trait SchnorrSigner {
    fn message(&self) -> &[u8];
    fn secret_key(&self) -> Scalar;
    fn x_only_key(&self) -> (BIP340XOnlyPubKey, Scalar) {
        compress_scalar_bip340(&self.secret_key())
    }
    fn x_only_nonce(&self) -> Result<(BIP340XOnlyPubKey, Scalar)>;
    fn challenge(&self, R: &BIP340XOnlyPubKey, P: &BIP340XOnlyPubKey) -> Result<Scalar>;
    fn sign(&self) -> Result<SchnorrSignature> {
        ensure!(
            !bool::from(self.secret_key().is_zero()),
            "Schnorr signing failed: secret key is zero"
        );

        let (P_x, d) = self.x_only_key();
        let (R_x, k) = self.x_only_nonce()?;
        let e = self.challenge(&R_x, &P_x)?;
        let s: [u8; 32] = (k + e * d).to_bytes().into();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&R_x);
        sig[32..].copy_from_slice(&s);
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
        ensure!(
            !bool::from(self.pub_key().is_identity()),
            "Schnorr verification failed: public key is identity"
        );

        let mut r_x = [0u8; 32];
        r_x.copy_from_slice(&sig[..32]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..]);

        let s = scalar_from_bytes(s_bytes)
            .context("Schnorr verification failed: invalid response scalar")?;

        let (P, p_x) = self.x_only_pubkey();
        let e = self.challenge(&r_x, &p_x)?;

        let R = ProjectivePoint::GENERATOR * s - P * e;
        ensure!(
            !bool::from(R.is_identity()),
            "Schnorr verification failed: nonce is identity"
        );

        let R = R.to_affine();
        ensure!(
            !bool::from(R.y_is_odd()),
            "Schnorr verification failed: nonce has odd Y"
        );

        let computed_r_x: [u8; 32] = R.x().into();
        if computed_r_x != r_x {
            bail!("Schnorr verification failed: invalid signature");
        }

        Ok(())
    }
}
