use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

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
        if let KeyBytes::Private(_) = k_par {
            mac.input(&k_par.as_33_bytes());
        } else {
            return Err(Box::new(secp256k1::Error::InvalidSecretKey));
        }
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

#[derive(Debug)]
pub struct ExtKeyParseError(pub &'static str);

impl Error for ExtKeyParseError {}
impl Display for ExtKeyParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self.0)
    }
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
            Self::Public(public_key) => *public_key,
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
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, ExtKeyParseError> {
        if bytes.len() != 82 {
            return Err(ExtKeyParseError("Bad key length"));
        }
        let depth = bytes[4];
        let parent_fingerprint: [u8; 4] = bytes[5..9].try_into().unwrap();
        let child_number: [u8; 4] = bytes[9..13].try_into().unwrap();
        let chain_code: [u8; 32] = bytes[13..45].try_into().unwrap();
        let sha256d_checksum = crate::hashes::sha256d(&bytes[0..78]);
        if sha256d_checksum[0..4] != bytes[78..82] {
            return Err(ExtKeyParseError("Bad checksum"));
        }
        let (key_type, main_key) = match bytes[0..4].try_into().unwrap() {
            MAINNET_PRIVATE_MAGIC => (
                KeyType::MainnetPrivate,
                KeyBytes::Private(bytes[46..78].try_into().unwrap()),
            ),
            TESTNET_PRIVATE_MAGIC => (
                KeyType::TestnetPrivate,
                KeyBytes::Private(bytes[46..78].try_into().unwrap()),
            ),
            MAINNET_PUBLIC_MAGIC => {
                let mut pub_bytes = [0u8; 33];
                pub_bytes.copy_from_slice(&bytes[45..78]);
                (KeyType::MainnetPublic, KeyBytes::Public(pub_bytes))
            }
            TESTNET_PUBLIC_MAGIC => {
                let mut pub_bytes = [0u8; 33];
                pub_bytes.copy_from_slice(&bytes[45..78]);
                (KeyType::TestnetPublic, KeyBytes::Public(pub_bytes))
            }
            _ => return Err(ExtKeyParseError("Invalid key")),
        };
        Ok(Self {
            key_type,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            main_key,
        })
    }

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
        match self.key_type {
            KeyType::MainnetPrivate => {
                self.key_type = KeyType::MainnetPublic;
                self.main_key = self.main_key.as_public();
                self
            }
            KeyType::TestnetPrivate => {
                self.key_type = KeyType::TestnetPublic;
                self.main_key = self.main_key.as_public();
                self
            }
            _ => self,
        }
    }

    fn raw_tree_expander(&self, path: &[u32]) -> Self {
        // TODO: handle failures for hardened keys as Result<Self, Box<dyn Error>>
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

    pub fn child_key_pair(&self, index: u32) -> ([u8; 33], Option<[u8; 32]>) {
        let child_no = self.raw_tree_expander(&[index]);
        match child_no.main_key {
            KeyBytes::Private(priv_key) => (child_no.main_key.as_public_bytes(), Some(priv_key)),
            KeyBytes::Public(pub_key) => (pub_key, None),
        }
    }
}

pub fn secret_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> [u8; 82] {
    RawExtendedKey::secret_from_enthropy(enthropy, path).serialize()
}

pub fn public_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> [u8; 82] {
    RawExtendedKey::public_from_enthropy(enthropy, path).serialize()
}

#[cfg(test)]
mod test;
