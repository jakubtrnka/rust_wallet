use crate::base58::bytes_to_base58;
use crate::hashes::{hash160, sha256d};

use super::copy_to_offset;

use crate::bitcoin_keys::BitcoinKey;

pub struct LegacyAddress(pub String, pub Option<String>);

pub trait Wif {
    fn addr(&self) -> String;
    fn secret(&self) -> Option<String>;
}

impl LegacyAddress {
    pub fn new_addr_key_pair(key: &BitcoinKey) -> Self {
        let mut tmp = [0u8; 38];

        let pub_key_hash = hash160(&key.serialize_public());
        copy_to_offset(&mut tmp, 1, &pub_key_hash);
        let checksum = sha256d(&tmp[0..21]);
        copy_to_offset(&mut tmp, 21, &checksum[0..4]);
        let output_address = bytes_to_base58(&tmp[0..25]);
        let output_priv_key_wif = if let Ok(priv_key) = key.serialize_private() {
            tmp[0] = 0x80;
            copy_to_offset(&mut tmp, 1, &priv_key);
            tmp[33] = 1; // for compressed pub key
            let checksum = sha256d(&tmp[0..34]);
            copy_to_offset(&mut tmp, 34, &checksum[0..4]);
            Some(bytes_to_base58(&tmp))
        } else {
            None
        };
        Self(output_address, output_priv_key_wif)
    }
}
impl Wif for LegacyAddress {
    fn addr(&self) -> String {
        self.0.clone()
    }
    fn secret(&self) -> Option<String> {
        self.1.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pub_key_to_address() {
        let legacy_mainnet = LegacyAddress::new_addr_key_pair(
            &BitcoinKey::new_public(&[
                0x03, 0x57, 0xd6, 0x47, 0x92, 0xe1, 0xbd, 0xa1, 0x16, 0xf7, 0x66, 0xb2, 0x4b, 0x61,
                0xfa, 0x78, 0xe9, 0xef, 0x8d, 0xb6, 0x11, 0x84, 0xb2, 0x77, 0x0a, 0xae, 0x1b, 0xda,
                0x0f, 0x19, 0x19, 0xe1, 0xb6,
            ])
            .unwrap(),
        );
        assert_eq!(
            legacy_mainnet.addr(),
            String::from("1XEGXTfjsJ27h9Z4WvXrP7jVjs8riF8Li")
        );
        assert_eq!(legacy_mainnet.secret(), None,);
    }

    #[test]
    fn priv_key_to_wif_1() {
        let raw_private = BitcoinKey::new_private(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ])
        .unwrap();
        let wif = LegacyAddress::new_addr_key_pair(&raw_private);
        assert_eq!(
            wif.addr(),
            String::from("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        );
        assert_eq!(
            wif.secret().unwrap(),
            String::from("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        );
    }

    #[test]
    fn priv_key_to_wif_2() {
        let raw_private = BitcoinKey::new_private(&[
            0xf4, 0x6c, 0x68, 0x88, 0xb8, 0x46, 0xd7, 0x1f, 0x11, 0x19, 0x33, 0x66, 0xc9, 0x22,
            0x9b, 0x7f, 0xdf, 0x99, 0xf8, 0xfd, 0xed, 0xee, 0xe6, 0x36, 0x9c, 0x83, 0xfa, 0xb2,
            0x58, 0xff, 0xd2, 0x57,
        ])
        .unwrap();
        let wif = LegacyAddress::new_addr_key_pair(&raw_private);
        assert_eq!(
            wif.addr(),
            String::from("1ZKVFRnWgnMBXsoqpt773GugWkraC8xZo")
        );
        assert_eq!(
            wif.secret().unwrap(),
            String::from("L5QqZr8wuvDMPfadrZHrrJ96rqiFQaCvq5giC6FN2owmfWPvhVSB")
        );
    }
}
