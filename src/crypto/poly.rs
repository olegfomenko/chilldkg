use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, Hash};
use crate::crypto::ec::parse_scalar_from_hash;
use crate::crypto::tags::TAG_VSS_COEFFS;
use crate::crypto::{SecretScalar, tagged_hash};
use crate::errors::Result;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial<C: Curve> {
    coefficients: Vec<C::Scalar>,
}

impl<C: Curve> Polynomial<C> {
    pub fn new(seed: &Hash<C>, t: usize) -> Result<Self> {
        let mut poly = Self {
            coefficients: Vec::with_capacity(t),
        };

        let seed = seed.as_ref();
        let mut preimage = Zeroizing::new(Vec::with_capacity(seed.len() + 4));
        preimage.extend_from_slice(seed);
        preimage.resize(seed.len() + 4, 0);

        for i in 0..t {
            preimage[seed.len()..].copy_from_slice(&(i as u32).to_be_bytes());
            let preimage_hash = Zeroizing::new(tagged_hash::<C>(TAG_VSS_COEFFS, &preimage));
            poly.coefficients
                .push(parse_scalar_from_hash::<C>(&preimage_hash)?);
        }

        Ok(poly)
    }

    fn eval(&self, x: C::Scalar) -> C::Scalar {
        self.coefficients
            .iter()
            .rev()
            .fold(C::Scalar::ZERO, |acc, coefficient| acc * x + *coefficient)
    }

    pub fn eval_shares(&self, n: u64) -> Zeroizing<Vec<C::Scalar>> {
        Zeroizing::new(
            (0u64..n)
                .map(|i| self.eval(C::Scalar::from_u64(i + 1)))
                .collect(),
        )
    }

    pub fn coeff(&self, i: usize) -> Option<SecretScalar<C>> {
        self.coefficients.get(i).map(|c| Zeroizing::new(*c))
    }

    pub fn commit(&self) -> Vec<C::Point> {
        self.coefficients
            .iter()
            .map(|c| C::Point::GENERATOR * *c)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::Secp256k1;
    use k256::{ProjectivePoint, Scalar};

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn polynomial(coefficients: Vec<Scalar>) -> Polynomial<Secp256k1> {
        Polynomial { coefficients }
    }

    #[test]
    fn returns_coefficients_by_index() {
        let polynomial = polynomial(vec![scalar(3), scalar(5), scalar(8)]);

        assert_eq!(polynomial.coeff(0), Some(Zeroizing::new(scalar(3))));
        assert_eq!(polynomial.coeff(1), Some(Zeroizing::new(scalar(5))));
        assert_eq!(polynomial.coeff(2), Some(Zeroizing::new(scalar(8))));
        assert_eq!(polynomial.coeff(3), None);
    }

    #[test]
    fn evaluates_empty_polynomial_as_zero() {
        let polynomial = polynomial(vec![]);

        assert_eq!(polynomial.eval(scalar(7)), Scalar::ZERO);
    }

    #[test]
    fn evaluates_constant_polynomial() {
        let polynomial = polynomial(vec![scalar(42)]);

        assert_eq!(polynomial.eval(scalar(9)), scalar(42));
    }

    #[test]
    fn evaluates_polynomial_at_scalar() {
        let polynomial = polynomial(vec![scalar(3), scalar(2), scalar(5)]);

        assert_eq!(polynomial.eval(scalar(4)), scalar(91));
    }

    #[test]
    fn evaluates_shares_at_one_based_indices() {
        let polynomial = polynomial(vec![scalar(3), scalar(2), scalar(5)]);

        assert_eq!(
            *polynomial.eval_shares(4),
            vec![scalar(10), scalar(27), scalar(54), scalar(91)]
        );
    }

    #[test]
    fn evaluates_zero_shares_as_empty_list() {
        let polynomial = polynomial(vec![scalar(3), scalar(2), scalar(5)]);

        assert_eq!(*polynomial.eval_shares(0), Vec::<Scalar>::new());
    }

    #[test]
    fn commits_coefficients_to_generator_multiples() {
        let polynomial = polynomial(vec![scalar(3), scalar(5), scalar(8)]);

        assert_eq!(
            polynomial.commit(),
            vec![
                ProjectivePoint::GENERATOR * scalar(3),
                ProjectivePoint::GENERATOR * scalar(5),
                ProjectivePoint::GENERATOR * scalar(8),
            ]
        );
    }

    #[test]
    fn commits_empty_polynomial_as_empty_list() {
        let polynomial = polynomial(vec![]);

        assert_eq!(polynomial.commit(), Vec::<ProjectivePoint>::new());
    }
}
