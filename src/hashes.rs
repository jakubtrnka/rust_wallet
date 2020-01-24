use ripemd160;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    output.copy_from_slice(Sha256::digest(&Sha256::digest(data)[..]).as_slice());
    output
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut output = [0; 20];
    output.copy_from_slice(Ripemd160::digest(&Sha256::digest(data)[..]).as_slice());
    output
}

#[cfg(test)]
mod test {
    use crate::hashes::{hash160, sha256d};

    #[test]
    fn test_hash160() {
        assert_eq!(
            hash160(&[64, 64, 64, 64, 64, 64, 64, 64, 64, 64]),
            [
                0x71, 0x63, 0xf0, 0x05, 0x39, 0xb4, 0xd7, 0x85, 0x1a, 0x7a, 0xb5, 0xd1, 0xcf, 0xdb,
                0xe7, 0x95, 0x7c, 0xef, 0x38, 0x68u8,
            ]
        );
    }

    #[test]
    fn test_sha256d() {
        assert_eq!(
            sha256d(&[64, 64, 64, 64, 64, 64, 64, 64, 64, 64]),
            [
                0xc2, 0xbb, 0x6c, 0x41, 0x6a, 0xda, 0xac, 0xd7, 0xeb, 0xfb, 0x02, 0xf8, 0x95, 0x74,
                0x01, 0xa1, 0xc1, 0xfa, 0x7c, 0x5b, 0x67, 0x3d, 0x02, 0x62, 0x43, 0xce, 0x73, 0x8c,
                0x14, 0x74, 0x80, 0x07u8
            ]
        );
    }
}
