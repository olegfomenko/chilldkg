pub mod certeq;
pub mod curve;
pub mod ec;
pub mod enc;
pub mod poly;
pub mod pop;
pub mod schnorr;
pub mod secp256k1;
pub mod tags;

use sha2::Digest;
use zeroize::Zeroizing;

use crate::crypto::curve::{Curve, Hash};

/// A secret scalar that wipes its memory on drop.
/// Note: `*secret` yields a plain `Copy` of the value — deref with intent.
pub type SecretScalar<C> = Zeroizing<<C as Curve>::Scalar>;

/// Hashes `x` with the hasher of the curve `C`.
pub fn hash<C: Curve>(x: impl AsRef<[u8]>) -> Hash<C> {
    C::Hasher::digest(x.as_ref()).into()
}

/// BIP340 tagged hash computed with the hasher of the curve `C`.
pub fn tagged_hash<C: Curve>(tag: impl AsRef<[u8]>, x: impl AsRef<[u8]>) -> Hash<C> {
    let tag_hash = C::Hasher::digest(tag.as_ref());

    let mut hasher = C::Hasher::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(x.as_ref());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::Secp256k1;
    use sha2::Sha256;

    #[test]
    fn computes_tagged_hash() {
        let tag = b"chilldkg/test";
        let x = b"message";
        let tag_hash = Sha256::digest(tag);

        let mut expected = Sha256::new();
        expected.update(tag_hash);
        expected.update(tag_hash);
        expected.update(x);

        assert_eq!(
            tagged_hash::<Secp256k1>(tag, x),
            <[u8; 32]>::from(expected.finalize())
        );
    }
}
