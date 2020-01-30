use crate::base58::bytes_to_base58;
use crate::hashes::{hash160, sha256d};

use super::copy_to_offset;

pub enum AddressFormat {
    LegacyMainnet,
    LegacyTestnet,
}

impl AddressFormat {
    pub fn from_public_key(&self, pub_key: &[u8; 33]) -> String {
        let mut output_array = [0u8; 25];

        let pub_key_hash = hash160(pub_key);
        match self {
            AddressFormat::LegacyMainnet => {}
            AddressFormat::LegacyTestnet => {
                output_array[0] = 0x6f;
            }
        }
        copy_to_offset(&mut output_array, 1, &pub_key_hash);
        let checksum = sha256d(&mut output_array[0..21]);
        copy_to_offset(&mut output_array, 21, &checksum[0..4]);
        bytes_to_base58(&mut output_array)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pub_key_to_address() {
        let legacy_mainnet = AddressFormat::LegacyMainnet.from_public_key(&[
            0x03, 0x57, 0xd6, 0x47, 0x92, 0xe1, 0xbd, 0xa1, 0x16, 0xf7, 0x66, 0xb2, 0x4b, 0x61,
            0xfa, 0x78, 0xe9, 0xef, 0x8d, 0xb6, 0x11, 0x84, 0xb2, 0x77, 0x0a, 0xae, 0x1b, 0xda,
            0x0f, 0x19, 0x19, 0xe1, 0xb6,
        ]);
        assert_eq!(
            legacy_mainnet,
            String::from("1XEGXTfjsJ27h9Z4WvXrP7jVjs8riF8Li")
        );
    }
}
