use crate::coding::{bytes_to_base58, Bech32};
use crate::hashes::{hash160, sha256d};

use super::copy_to_offset;

use crate::bitcoin_keys::KeyPair;

pub trait Wif {
    fn from_key_pair(key_pair: &KeyPair) -> Self;
    fn address(&self) -> String;
    fn secret(&self) -> Option<String>;
}

pub struct P2WPKHAddress(Bech32, Option<String>);

impl Wif for P2WPKHAddress {
    fn from_key_pair(key_pair: &KeyPair) -> Self {
        let mut address_data = [0_u8; 21];
        let witness_program = hash160(&key_pair.get_public().serialize_public());
        copy_to_offset(&mut address_data, 1, &witness_program);

        let data = key_pair.get_private().map(|private_key| {
            let mut tmp = [0_u8; 38];
            let priv_key = private_key
                .serialize_private()
                .expect("BUG: private key serialization error");
            tmp[0] = 0x80;
            copy_to_offset(&mut tmp, 1, &priv_key);
            tmp[33] = 11; // for compressed pub key
            let checksum = sha256d(&tmp[0..34]);
            copy_to_offset(&mut tmp, 34, &checksum[0..4]);
            bytes_to_base58(&tmp)
        });

        Self(Bech32::new("bc", &address_data), data)
    }

    fn address(&self) -> String {
        match self.0.to_string() {
            Ok(addr) => addr,
            Err(e) => panic!("BUG: Bech32 address encoding failed: {:?}", e),
        }
    }

    fn secret(&self) -> Option<String> {
        self.1.clone()
    }
}

pub struct P2PKHAddress(String, Option<String>);

impl Wif for P2PKHAddress {
    fn from_key_pair(key_pair: &KeyPair) -> Self {
        let mut tmp = [0u8; 38];

        let key = key_pair.get_public();

        let pub_key_hash = hash160(&key.serialize_public());
        copy_to_offset(&mut tmp, 1, &pub_key_hash);
        let checksum = sha256d(&tmp[0..21]);
        copy_to_offset(&mut tmp, 21, &checksum[0..4]);
        let output_address = bytes_to_base58(&tmp[0..25]);

        let output_priv_key_wif = key_pair.get_private().map(|private_key| {
            let priv_key = private_key
                .serialize_private()
                .expect("BUG: private key serialization error");
            tmp[0] = 0x80;
            copy_to_offset(&mut tmp, 1, &priv_key);
            tmp[33] = 1; // for compressed pub key
            let checksum = sha256d(&tmp[0..34]);
            copy_to_offset(&mut tmp, 34, &checksum[0..4]);
            bytes_to_base58(&tmp)
        });
        Self(output_address, output_priv_key_wif)
    }

    fn address(&self) -> String {
        self.0.clone()
    }
    fn secret(&self) -> Option<String> {
        self.1.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bitcoin_keys::BitcoinKey;

    #[test]
    #[ignore]
    fn test_p2wpkh() {
        let wif_private_key = "L3YT5g8SyEsvkHC389oKibF6HpujJuQyepSYwu2VVJX25h6Er5s2";
        let bech32_address = "bc1qfu7h094mx8p5suvxqekym0qsgpvq3tatv72gv6";
    }

    #[test]
    fn pub_key_to_address() {
        let legacy_mainnet = P2PKHAddress::from_key_pair(
            &BitcoinKey::new_public(&[
                0x03, 0x57, 0xd6, 0x47, 0x92, 0xe1, 0xbd, 0xa1, 0x16, 0xf7, 0x66, 0xb2, 0x4b, 0x61,
                0xfa, 0x78, 0xe9, 0xef, 0x8d, 0xb6, 0x11, 0x84, 0xb2, 0x77, 0x0a, 0xae, 0x1b, 0xda,
                0x0f, 0x19, 0x19, 0xe1, 0xb6,
            ])
            .unwrap()
            .into(),
        );
        assert_eq!(
            legacy_mainnet.address(),
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
        let wif = P2PKHAddress::from_key_pair(&raw_private.into());
        assert_eq!(
            wif.address(),
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
        let wif = P2PKHAddress::from_key_pair(&raw_private.into());
        assert_eq!(
            wif.address(),
            String::from("1ZKVFRnWgnMBXsoqpt773GugWkraC8xZo")
        );
        assert_eq!(
            wif.secret().unwrap(),
            String::from("L5QqZr8wuvDMPfadrZHrrJ96rqiFQaCvq5giC6FN2owmfWPvhVSB")
        );
    }
}
