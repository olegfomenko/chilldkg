pub mod certeq;
pub mod ec;
pub mod enc;
pub mod poly;
pub mod pop;
pub mod schnorr;
pub mod tags;

use k256::Scalar;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A secret scalar that wipes its memory on drop.
/// Note: `*secret` yields a plain `Copy` of the value — deref with intent.
pub type SecretScalar = Zeroizing<Scalar>;

pub type TaggedHash = [u8; 32];

pub fn tagged_hash(tag: impl AsRef<[u8]>, x: impl AsRef<[u8]>) -> TaggedHash {
    let tag_hash = Sha256::digest(tag.as_ref());

    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(x.as_ref());
    hash.finalize().into()
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
