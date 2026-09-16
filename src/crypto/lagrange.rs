//! Lagrange interpolation over participant identifiers.
//!
//! Shares are evaluations of a polynomial at `id + 1` (see [`crate::crypto::poly`]),
//! so the interpolating value for a signer combines the shares of a signing
//! subset back into the value at zero, i.e. the threshold secret.

#![allow(non_snake_case)] // Uppercase identifiers denote curve points.

use crate::chill_dkg_ensure;
use crate::errors::{ChillDkgError, Result};
use itertools::Itertools;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};

/// Computes the Lagrange coefficient of `my_id` with respect to the signing
/// subset `ids`.
///
/// Math: `lambda_i = prod_{j != i} (j + 1) / prod_{j != i} (j - i)` over `j in ids`.
///
/// Returns an error if `my_id` is not in `ids` or `ids` contains duplicates,
/// since the denominator is zero in either case.
pub fn lagrange(ids: &[usize], my_id: usize) -> Result<Scalar> {
    chill_dkg_ensure!(
        ids.contains(&my_id),
        ChillDkgError::Value(
            "The signer's id must be present in the participant identifier list.".into()
        ),
    );

    chill_dkg_ensure!(
        ids.iter().all_unique(),
        ChillDkgError::Value("The participant identifier list contains duplicate elements.".into()),
    );

    let my = Scalar::from(my_id as u64);
    let mut num = Scalar::ONE;
    let mut deno = Scalar::ONE;

    for &curr_id in ids {
        if curr_id == my_id {
            continue;
        }

        let curr = Scalar::from(curr_id as u64);
        num *= curr + Scalar::ONE;
        deno *= curr - my;
    }

    // `deno` is a product of non-zero differences of distinct ids, so it is
    // invertible; the check above makes this unreachable.
    let deno_inv = Option::<Scalar>::from(deno.invert())
        .ok_or_else(|| ChillDkgError::Runtime("Lagrange denominator is zero".into()))?;

    Ok(num * deno_inv)
}

/// Reconstructs the threshold public key from the public shares of a signing
/// subset.
///
/// Math: `Q = sum_i lambda_i * X_i` for `(i, X_i)` in `zip(ids, pubshares)`.
pub fn interpolate_pubkey(ids: &[usize], pubshares: &[ProjectivePoint]) -> Result<ProjectivePoint> {
    chill_dkg_ensure!(
        ids.len() == pubshares.len(),
        ChillDkgError::Value("The pubshares and ids arrays must have the same length.".into()),
    );

    let Q = pubshares
        .iter()
        .zip(ids.iter())
        .map(|(X_i, i)| Ok(X_i * &lagrange(ids, *i)?))
        .sum::<Result<ProjectivePoint>>()?;

    // Q is not the point at infinity except with negligible probability.
    chill_dkg_ensure!(
        !bool::from(Q.is_identity()),
        ChillDkgError::Runtime("interpolated public key is the identity point".into()),
    );

    Ok(Q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poly::Polynomial;

    #[test]
    fn interpolation_recovers_polynomial_at_zero() {
        // f(x) with 3 coefficients: threshold 3. Any 3 shares reconstruct f(0).
        let poly = Polynomial::new(&[7u8; 32], 3).unwrap();
        let shares = poly.eval_shares(5);
        let secret = poly.coeff(0).unwrap();

        for ids in [[0usize, 1, 2], [0, 2, 4], [1, 3, 4]] {
            let mut acc = Scalar::ZERO;
            for &id in &ids {
                acc += lagrange(&ids, id).unwrap() * shares[id];
            }
            assert_eq!(acc, *secret, "subset {ids:?} must reconstruct the secret");
        }
    }

    #[test]
    fn interpolate_pubkey_matches_commitment_to_secret() {
        let poly = Polynomial::new(&[9u8; 32], 2).unwrap();
        let shares = poly.eval_shares(4);
        let expected = ProjectivePoint::GENERATOR * *poly.coeff(0).unwrap();

        let ids = [1usize, 3];
        let pubshares: Vec<_> = ids
            .iter()
            .map(|&i| ProjectivePoint::GENERATOR * shares[i])
            .collect();
        assert_eq!(interpolate_pubkey(&ids, &pubshares).unwrap(), expected);
    }

    #[test]
    fn rejects_missing_id_and_duplicates() {
        assert!(lagrange(&[0, 1], 2).is_err());
        assert!(lagrange(&[0, 1, 1], 0).is_err());
    }
}
