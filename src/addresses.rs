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

    pub fn from_private_key(&self, priv_key: &[u8; 32]) -> String {
        let mut output_array = [0u8; 38];
        match self {
            AddressFormat::LegacyTestnet => { unimplemented!() }
            AddressFormat::LegacyMainnet => {
                output_array[0] = 0x80;
            }
        }
        copy_to_offset(&mut output_array, 1, priv_key);
        output_array[33] = 1;  // for compressed pub key
        let checksum = sha256d(&mut output_array[0..34]);
        copy_to_offset(&mut output_array, 34, &checksum[0..4]);
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
    
    #[test]
    fn priv_key_to_wif() {
        let raw_private = [
            0xf4, 0x6c, 0x68, 0x88, 0xb8, 0x46, 0xd7, 0x1f, 0x11, 0x19, 0x33, 0x66, 0xc9, 0x22,
            0x9b, 0x7f, 0xdf, 0x99, 0xf8, 0xfd, 0xed, 0xee, 0xe6, 0x36, 0x9c, 0x83, 0xfa, 0xb2,
            0x58, 0xff, 0xd2, 0x57
        ];
        assert_eq!(
            AddressFormat::LegacyMainnet.from_private_key(&raw_private),
            String::from("L5QqZr8wuvDMPfadrZHrrJ96rqiFQaCvq5giC6FN2owmfWPvhVSB")
        );

    }
}
