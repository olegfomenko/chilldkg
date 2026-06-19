use crate::crypto::tagged_hash;
use crate::crypto::tags::TAG_VSS_COEFFS;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{Scalar, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn new(seed: &[u8; 32], t: usize) -> Self {
        let mut coefficients = Vec::with_capacity(t);

        for i in 0..t {
            let mut preimage = Vec::with_capacity(32 + 4);
            preimage.extend_from_slice(seed);
            preimage.extend_from_slice(&(i as u32).to_be_bytes());

            coefficients.push(Scalar::reduce(U256::from_be_slice(&tagged_hash(
                TAG_VSS_COEFFS,
                preimage,
            ))));
        }

        Self { coefficients }
    }

    pub fn eval(&self, x: Scalar) -> Scalar {
        self.coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, coefficient| acc * x + coefficient)
    }

    pub fn coeff(&self, i: usize) -> Option<&Scalar> {
        self.coefficients.get(i)
    }
}

impl<'a> IntoIterator for &'a Polynomial {
    type Item = &'a Scalar;
    type IntoIter = std::slice::Iter<'a, Scalar>;

    fn into_iter(self) -> Self::IntoIter {
        self.coefficients.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    #[test]
    fn returns_coefficients_by_index() {
        let polynomial = Polynomial {
            coefficients: vec![scalar(3), scalar(5), scalar(8)],
        };

        assert_eq!(polynomial.coeff(0), Some(&scalar(3)));
        assert_eq!(polynomial.coeff(1), Some(&scalar(5)));
        assert_eq!(polynomial.coeff(2), Some(&scalar(8)));
        assert_eq!(polynomial.coeff(3), None);
    }

    #[test]
    fn evaluates_empty_polynomial_as_zero() {
        let polynomial = Polynomial {
            coefficients: vec![],
        };

        assert_eq!(polynomial.eval(scalar(7)), Scalar::ZERO);
    }

    #[test]
    fn evaluates_constant_polynomial() {
        let polynomial = Polynomial {
            coefficients: vec![scalar(42)],
        };

        assert_eq!(polynomial.eval(scalar(9)), scalar(42));
    }

    #[test]
    fn evaluates_polynomial_at_scalar() {
        let polynomial = Polynomial {
            coefficients: vec![scalar(3), scalar(2), scalar(5)],
        };

        assert_eq!(polynomial.eval(scalar(4)), scalar(91));
    }
}
