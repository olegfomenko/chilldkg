use k256::Scalar;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::rand_core::CryptoRngCore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    pub fn random(rng: &mut impl CryptoRngCore, degree: usize) -> Self {
        let coefficients = (0..=degree).map(|_| Scalar::random(&mut *rng)).collect();

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

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    #[test]
    fn returns_coefficients_by_index() {
        let polynomial = Polynomial::new(vec![scalar(3), scalar(5), scalar(8)]);

        assert_eq!(polynomial.coeff(0), Some(&scalar(3)));
        assert_eq!(polynomial.coeff(1), Some(&scalar(5)));
        assert_eq!(polynomial.coeff(2), Some(&scalar(8)));
        assert_eq!(polynomial.coeff(3), None);
    }

    #[test]
    fn evaluates_empty_polynomial_as_zero() {
        let polynomial = Polynomial::new(vec![]);

        assert_eq!(polynomial.eval(scalar(7)), Scalar::ZERO);
    }

    #[test]
    fn evaluates_constant_polynomial() {
        let polynomial = Polynomial::new(vec![scalar(42)]);

        assert_eq!(polynomial.eval(scalar(9)), scalar(42));
    }

    #[test]
    fn evaluates_polynomial_at_scalar() {
        let polynomial = Polynomial::new(vec![scalar(3), scalar(2), scalar(5)]);

        assert_eq!(polynomial.eval(scalar(4)), scalar(91));
    }
}
