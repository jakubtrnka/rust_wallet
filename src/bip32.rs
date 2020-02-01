use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

use super::copy_to_offset;
use crate::bip32::BIP32Error::KeyDerivationError;

const MAINNET_PRIVATE_MAGIC: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const MAINNET_PUBLIC_MAGIC: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TESTNET_PRIVATE_MAGIC: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const TESTNET_PUBLIC_MAGIC: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

#[derive(Debug)]
pub enum BIP32Error {
    ExtendedKeyParseError(&'static str),
    KeyDerivationError(&'static str),
    Secp256k1Error,
}

impl Error for BIP32Error {}
impl Display for BIP32Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self.to_string().as_str())
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum NetworkType {
    Mainnet,
    Testnet,
}

#[derive(Clone)]
pub enum BitcoinKey {
    Public(secp256k1::PublicKey),
    Private(secp256k1::SecretKey),
}

impl BitcoinKey {
    fn new_public(key: &[u8]) -> Result<Self, BIP32Error> {
        let public_key = PublicKey::from_slice(key)
            .map_err(|_e| KeyDerivationError("invalid public key bytes"))?;
        Ok(Self::Public(public_key))
    }

    fn new_private(key: &[u8]) -> Result<Self, BIP32Error> {
        let secret = SecretKey::from_slice(key)
            .map_err(|_e| KeyDerivationError("invalid private key bytes"))?;
        Ok(Self::Private(secret))
    }

    fn serialize_public(&self) -> [u8; 33] {
        match self.as_public() {
            Self::Public(x) => x.serialize(),
            Self::Private(_) => unreachable!(),
        }
    }

    fn serialize_private(&self) -> Result<[u8; 32], BIP32Error> {
        match self {
            Self::Public(_) => Err(KeyDerivationError("Cannot derive private key from public")),
            Self::Private(x) => Ok(x[..].try_into().unwrap()),
        }
    }

    fn as_public(&self) -> Self {
        match self {
            Self::Public(_) => self.clone(),
            Self::Private(x_prv) => {
                let ctx = Secp256k1::new();
                Self::Public(PublicKey::from_secret_key(&ctx, x_prv))
            }
        }
    }

    fn ec_or_scalar_add(&self, other: &Self) -> Result<Self, secp256k1::Error> {
        let ctx = Secp256k1::new();
        let add_op = |priv_tmp: &SecretKey, pub_tmp: &PublicKey| {
            Ok(Self::Public(
                pub_tmp.combine(&PublicKey::from_secret_key(&ctx, priv_tmp))?,
            ))
        };
        match (self, other) {
            (Self::Public(pub_lhs), Self::Public(pub_rhs)) => {
                let output = pub_lhs.combine(pub_rhs)?;
                Ok(Self::Public(output))
            }
            (Self::Private(priv_lhs), Self::Private(priv_rhs)) => {
                let mut output = *priv_lhs;
                output.add_assign(&priv_rhs[..])?;
                Ok(Self::Private(output))
            }
            (Self::Public(pub_tmp), Self::Private(priv_tmp)) => add_op(priv_tmp, pub_tmp),
            (Self::Private(priv_tmp), Self::Public(pub_tmp)) => add_op(priv_tmp, pub_tmp),
        }
    }

    fn ckd(&self, c_par: &[u8; 32], index: u32) -> Result<(Self, [u8; 32]), BIP32Error> {
        let mut mac = Hmac::<Sha512>::new_varkey(c_par).unwrap();
        if index >= 0x8000_0000 {
            mac.input(&[0]);
            mac.input(&self.serialize_private()?);
        } else {
            mac.input(&self.serialize_public());
        }
        mac.input(&index.to_be_bytes());
        let result = mac.result().code();
        let i_r = result[32..].try_into().unwrap();

        let child_key = Self::new_private(&result[0..32])?
            .ec_or_scalar_add(self)
            .map_err(|_| BIP32Error::Secp256k1Error)?;
        Ok((child_key, i_r))
    }
}

#[derive(Clone)]
pub struct Bip32ExtendedKey {
    key_type: NetworkType,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: [u8; 4],
    chain_code: [u8; 32],
    main_key: BitcoinKey,
}

impl Bip32ExtendedKey {
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, BIP32Error> {
        if bytes.len() != 82 {
            return Err(BIP32Error::ExtendedKeyParseError("Bad key length"));
        }
        let depth = bytes[4];
        let parent_fingerprint: [u8; 4] = bytes[5..9].try_into().unwrap();
        let child_number: [u8; 4] = bytes[9..13].try_into().unwrap();
        let chain_code: [u8; 32] = bytes[13..45].try_into().unwrap();
        let sha256d_checksum = crate::hashes::sha256d(&bytes[0..78]);
        if sha256d_checksum[0..4] != bytes[78..82] {
            return Err(BIP32Error::ExtendedKeyParseError("Bad checksum"));
        }
        let (key_type, main_key) = match bytes[0..4].try_into().unwrap() {
            MAINNET_PRIVATE_MAGIC => (
                NetworkType::Mainnet,
                BitcoinKey::new_private(&bytes[46..78])?,
            ),
            TESTNET_PRIVATE_MAGIC => (
                NetworkType::Testnet,
                BitcoinKey::new_private(&bytes[46..78])?,
            ),
            MAINNET_PUBLIC_MAGIC => {
                let mut pub_bytes = [0u8; 33];
                pub_bytes.copy_from_slice(&bytes[45..78]);
                (NetworkType::Mainnet, BitcoinKey::new_public(&pub_bytes)?)
            }
            TESTNET_PUBLIC_MAGIC => {
                let mut pub_bytes = [0u8; 33];
                pub_bytes.copy_from_slice(&bytes[45..78]);
                (NetworkType::Testnet, BitcoinKey::new_public(&pub_bytes)?)
            }
            _ => return Err(BIP32Error::ExtendedKeyParseError("Invalid key")),
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
        match (&self.key_type, &self.main_key) {
            (NetworkType::Mainnet, BitcoinKey::Private(_)) => {
                copy_to_offset(&mut output, 0, &MAINNET_PRIVATE_MAGIC);
                copy_to_offset(&mut output, 46, &self.main_key.serialize_private().unwrap());
            }
            (NetworkType::Mainnet, BitcoinKey::Public(_)) => {
                copy_to_offset(&mut output, 0, &MAINNET_PUBLIC_MAGIC);
                copy_to_offset(&mut output, 45, &self.main_key.serialize_public());
            }
            (NetworkType::Testnet, BitcoinKey::Private(_)) => {
                copy_to_offset(&mut output, 0, &TESTNET_PRIVATE_MAGIC);
                copy_to_offset(&mut output, 46, &self.main_key.serialize_private().unwrap());
            }
            (NetworkType::Testnet, BitcoinKey::Public(_)) => {
                copy_to_offset(&mut output, 0, &TESTNET_PUBLIC_MAGIC);
                copy_to_offset(&mut output, 45, &self.main_key.serialize_public());
            }
        };
        copy_to_offset(&mut output, 4, &[self.depth]);
        copy_to_offset(&mut output, 5, &self.parent_fingerprint);
        copy_to_offset(&mut output, 9, &self.child_number);
        copy_to_offset(&mut output, 13, &self.chain_code);
        let checksum = crate::hashes::sha256d(&output[0..78]);
        copy_to_offset(&mut output, 78, &checksum[0..4]);
        output
    }

    pub fn ext_pub(mut self) -> Self {
        self.main_key = self.main_key.as_public();
        self
    }

    pub fn expand(&self, path: &[u32]) -> Result<Self, BIP32Error> {
        fn recursion(
            k_par: &BitcoinKey,
            c_par: &[u8; 32],
            derivation_path: &[u32],
        ) -> Result<(BitcoinKey, [u8; 32], [u8; 20]), BIP32Error> {
            let (k_child, c_child) = k_par.ckd(c_par, derivation_path[0])?;
            if derivation_path.len() == 1 {
                Ok((
                    k_child,
                    c_child,
                    crate::hashes::hash160(&k_par.serialize_public()),
                ))
            } else {
                recursion(&k_child, &c_child, &derivation_path[1..])
            }
        }

        if path.is_empty() {
            Ok(self.clone())
        } else {
            let result = recursion(&self.main_key, &self.chain_code, path)?;
            let mut par_fpr = [0u8; 4];
            par_fpr.copy_from_slice(&result.2[0..4]);
            Ok(Bip32ExtendedKey {
                key_type: self.key_type.clone(),
                depth: self.depth + path.len() as u8,
                parent_fingerprint: par_fpr,
                child_number: path.last().unwrap().to_be_bytes(),
                chain_code: result.1,
                main_key: result.0,
            })
        }
    }

    pub fn secret_from_enthropy(enthropy: &[u8], path: &[u32]) -> Result<Self, BIP32Error> {
        let mut mac = Hmac::<Sha512>::new_varkey(b"Bitcoin seed").unwrap();
        mac.input(enthropy);
        let result = mac.result().code();
        let master_raw_ext_key = Bip32ExtendedKey {
            key_type: NetworkType::Mainnet,
            depth: 0,
            parent_fingerprint: [0, 0, 0, 0],
            child_number: [0, 0, 0, 0],
            chain_code: result[32..].try_into().unwrap(),
            main_key: BitcoinKey::new_private(&result[..32])?,
        };
        master_raw_ext_key.expand(path)
    }

    pub fn public_from_enthropy(enthropy: &[u8], path: &[u32]) -> Result<Self, BIP32Error> {
        Self::secret_from_enthropy(enthropy, path).map(|ext_priv_key| ext_priv_key.ext_pub())
    }

    pub fn child_key_pair(
        &self,
        index: u32,
    ) -> Result<(BitcoinKey, Option<BitcoinKey>), BIP32Error> {
        let child_no = self.expand(&[index])?;
        match child_no.main_key {
            BitcoinKey::Private(_) => Ok((child_no.main_key.as_public(), Some(child_no.main_key))),
            BitcoinKey::Public(_) => Ok((child_no.main_key, None)),
        }
    }
}

pub fn secret_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> Result<[u8; 82], BIP32Error> {
    Bip32ExtendedKey::secret_from_enthropy(enthropy, path).map(|ext_key| ext_key.serialize())
}

pub fn public_ext_key_from_enthropy(enthropy: &[u8], path: &[u32]) -> Result<[u8; 82], BIP32Error> {
    Bip32ExtendedKey::public_from_enthropy(enthropy, path).map(|ext_key| ext_key.serialize())
}

#[cfg(test)]
mod test;
