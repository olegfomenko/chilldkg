pub mod certeq;
pub mod ec;
pub mod enc;
pub mod pop;
pub mod tags;

use anyhow::{Context, Result};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use sha2::{Digest, Sha256};

pub type TaggedHash = [u8; 32];

pub fn tagged_hash(tag: impl AsRef<[u8]>, x: impl AsRef<[u8]>) -> TaggedHash {
    let tag_hash = Sha256::digest(tag.as_ref());

    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(x.as_ref());
    hash.finalize().into()
}

pub fn scalar_from_bytes(x: [u8; 32]) -> Result<Scalar> {
    let res = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(x)))
        .context("failed to convert 32 byte array into field element")?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_tagged_hash() {
        let tag = b"chilldkg/test";
        let x = b"message";
        let tag_hash = Sha256::digest(tag);

        let mut expected = Sha256::new();
        expected.update(tag_hash);
        expected.update(tag_hash);
        expected.update(x);

        assert_eq!(tagged_hash(tag, x), <[u8; 32]>::from(expected.finalize()));
    }
}
