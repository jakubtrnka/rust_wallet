use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use std::error::Error;

const MAINNET_PRIVATE_MAGIC: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const MAINNET_PUBLIC_MAGIC: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TESTNET_PRIVATE_MAGIC: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const TESTNET_PUBLIC_MAGIC: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

fn copy_to_offset(target: &mut [u8], mut offset: usize, source: &[u8]) {
    for element in source {
        if let Some(x) = target.get_mut(offset) {
            *x = *element;
            offset += 1;
        } else {
            break;
        }
    }
}

fn ckd(
    k_par: &KeyBytes,
    c_par: &[u8; 32],
    index: u32,
) -> Result<(KeyBytes, [u8; 32]), Box<dyn Error>> {
    let mut mac = Hmac::<Sha512>::new_varkey(c_par).unwrap();
    if index >= 0x8000_0000 {
        mac.input(&k_par.as_33_bytes());
    } else {
        mac.input(&k_par.as_public_bytes());
    }
    mac.input(&index.to_be_bytes());
    let result = mac.result().code();
    let mut i_l = [0u8; 32];
    let mut i_r = [0u8; 32];
    i_l.copy_from_slice(&result[0..32]);
    i_r.copy_from_slice(&result[32..]);

    let child_key = KeyBytes::Private(i_l).ec_or_scalar_add(k_par)?;
    Ok((child_key, i_r))
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum KeyType {
    MainnetPrivate,
    MainnetPublic,
    TestnetPrivate,
    TestnetPublic,
}

#[derive(Clone)]
enum KeyBytes {
    Public([u8; 33]),
    Private([u8; 32]),
}

impl KeyBytes {
    fn as_public_bytes(&self) -> [u8; 33] {
        match self {
            Self::Public(x) => *x,
            Self::Private(x) => {
                let ctx = Secp256k1::new();
                PublicKey::from_secret_key(&ctx, &SecretKey::from_slice(x).unwrap()).serialize()
            }
        }
    }

    fn as_public(&self) -> Self {
        Self::Public(self.as_public_bytes())
    }

    fn ec_or_scalar_add(&self, other: &Self) -> Result<Self, Box<dyn Error>> {
        let ctx = Secp256k1::new();
        let add_op = |priv_tmp: &[u8; 32], pub_tmp: &[u8; 33]| {
            let lhs_point = PublicKey::from_slice(pub_tmp)?;
            let pub_rhs_pub = PublicKey::from_secret_key(&ctx, &SecretKey::from_slice(priv_tmp)?);
            Ok(Self::Public(lhs_point.combine(&pub_rhs_pub)?.serialize()))
        };
        match (self, other) {
            (Self::Public(pub_lhs), Self::Public(pub_rhs)) => {
                let lhs_point = PublicKey::from_slice(pub_lhs)?;
                let rhs_point = PublicKey::from_slice(pub_rhs)?;
                let output = lhs_point.combine(&rhs_point)?;
                Ok(Self::Public(output.serialize()))
            }
            (Self::Private(priv_lhs), Self::Private(priv_rhs)) => {
                let mut lhs_num = SecretKey::from_slice(priv_lhs)?;
                lhs_num.add_assign(priv_rhs)?;
                let mut combined = [0u8; 32];
                combined.copy_from_slice(&lhs_num[..]);
                Ok(Self::Private(combined))
            }
            (Self::Public(pub_tmp), Self::Private(priv_tmp)) => add_op(priv_tmp, pub_tmp),
            (Self::Private(priv_tmp), Self::Public(pub_tmp)) => add_op(priv_tmp, pub_tmp),
        }
    }

    fn as_33_bytes(&self) -> [u8; 33] {
        match self {
            Self::Private(private_key) => {
                let mut output = [0; 33];
                copy_to_offset(&mut output, 1, private_key);
                output
            }
            Self::Public(public_key) => {
                *public_key
            }
        }
    }

    fn public_identifier(&self) -> [u8; 20] {
        crate::hashes::hash160(&self.as_public_bytes())
    }
}

#[derive(Clone)]
pub struct RawExtendedKey {
    key_type: KeyType,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: [u8; 4],
    chain_code: [u8; 32],
    main_key: KeyBytes,
}

impl RawExtendedKey {
    pub fn serialize(&self) -> [u8; 82] {
        let mut output: [u8; 82] = [0; 82];
        let network_key_magic = match self.key_type {
            KeyType::MainnetPrivate => MAINNET_PRIVATE_MAGIC,
            KeyType::MainnetPublic => MAINNET_PUBLIC_MAGIC,
            KeyType::TestnetPrivate => TESTNET_PRIVATE_MAGIC,
            KeyType::TestnetPublic => TESTNET_PUBLIC_MAGIC,
        };
        copy_to_offset(&mut output, 0, &network_key_magic);
        copy_to_offset(&mut output, 4, &[self.depth]);
        copy_to_offset(&mut output, 5, &self.parent_fingerprint);
        copy_to_offset(&mut output, 9, &self.child_number);
        copy_to_offset(&mut output, 13, &self.chain_code);
        copy_to_offset(&mut output, 45, &self.main_key.as_33_bytes());
        let checksum = crate::hashes::sha256d(&output[0..78]);
        copy_to_offset(&mut output, 78, &checksum[0..4]);
        output
    }

    pub fn ext_pub(mut self) -> Self {
        self.key_type = KeyType::MainnetPublic;
        self.main_key = self.main_key.as_public();
        self
    }

    fn raw_tree_expander(&self, path: &[u32]) -> RawExtendedKey {
        fn recursion(
            k_par: &KeyBytes,
            c_par: &[u8; 32],
            derivation_path: &[u32],
        ) -> (KeyBytes, [u8; 32], [u8; 20]) {
            let (k_child, c_child) = ckd(k_par, c_par, derivation_path[0]).unwrap();
            if derivation_path.len() == 1 {
                (k_child, c_child, k_par.public_identifier())
            } else {
                recursion(&k_child, &c_child, &derivation_path[1..])
            }
        }

        if path.is_empty() {
            self.clone()
        } else {
            let result = recursion(&self.main_key, &self.chain_code, path);
            let mut par_fpr = [0u8; 4];
            par_fpr.copy_from_slice(&result.2[0..4]);
            RawExtendedKey {
                key_type: self.key_type.clone(),
                depth: self.depth + path.len() as u8,
                parent_fingerprint: par_fpr,
                child_number: path.last().unwrap().to_be_bytes(),
                chain_code: result.1,
                main_key: result.0,
            }
        }
    }

    pub fn secret_from_enthropy(enthropy: &[u8], path: &[u32]) -> Self {
        let mut mac = Hmac::<Sha512>::new_varkey(b"Bitcoin seed").unwrap();
        mac.input(enthropy);
        let result = mac.result().code();
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&result[..32]);
        let mut master_chain_code = [0u8; 32];
        master_chain_code.copy_from_slice(&result[32..]);
        let master_raw_ext_key = RawExtendedKey {
            key_type: KeyType::MainnetPrivate,
            depth: 0,
            parent_fingerprint: [0, 0, 0, 0],
            child_number: [0, 0, 0, 0],
            chain_code: master_chain_code,
            main_key: KeyBytes::Private(master_key),
        };
        master_raw_ext_key.raw_tree_expander(path)
    }

    pub fn public_from_enthropy(enthropy: &[u8], path: &[u32]) -> Self {
        Self::secret_from_enthropy(enthropy, path).ext_pub()
    }

}

pub fn secret_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> [u8; 82] {
    RawExtendedKey::secret_from_enthropy(enthropy, path).serialize()
}

pub fn public_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> [u8; 82] {
    RawExtendedKey::public_from_enthropy(enthropy, path).serialize()
}

#[cfg(test)]
mod test {

    const SEED: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn test_ext_keys_from_seed_0() {
        let private_key = crate::bip32::secret_ext_key_from_enthropy(&SEED, &[]);
        let public_key = crate::bip32::public_ext_key_from_enthropy(&SEED, &[]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsef\
            D265TMg7usUDFdp6W1EGMcet8"
        );
        assert_eq!(
            xpriv,
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMR\
            NNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn test_ext_keys_from_seed_1() {
        let public_key = crate::bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000]);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bg\
            wQ9xv5ski8PX9rL2dZXvgGDnw"
        );
        let private_key = crate::bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11\
            eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
    }

    #[test]
    fn test_ext_keys_from_seed_2() {
        let public_key = crate::bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1]);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq52\
            7Hqck2AxYysAA7xmALppuCkwQ"
        );
        let private_key = crate::bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8M\
            SY3H2EU4pWcQDnRnrVA1xe8fs"
        );
    }

    #[test]
    fn test_ext_keys_from_seed_3() {
        let public_key = crate::bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002]);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7\
            epu4trkrX7x7DogT5Uv6fcLW5"
        );
        let private_key = crate::bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiN\
            MjANTtpgP4mLTj34bhnZX7UiM"
        );
    }

    #[test]
    fn test_ext_keys_from_seed_4() {
        let public_key = crate::bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2]);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR\
            62cfN7fe5JnJ7dh8zL4fiyLHV"
        );
        let private_key = crate::bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsun\
            u5Mm3wDvUAKRHSC34sJ7in334"
        );
    }

    #[test]
    fn test_ext_keys_from_seed_5() {
        let public_key =
            crate::bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2, 10_0000_0000]);
        let xpub = crate::base58::bytes_to_base58(&public_key);
        assert_eq!(
            xpub,
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yG\
            asTvXEYBVPamhGW6cFJodrTHy"
        );
        let private_key =
            crate::bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2, 10_0000_0000]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSr\
            uoUihUZREPSL39UNdE3BBDu76"
        );
    }
}
