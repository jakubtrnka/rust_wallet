use std::convert::TryInto;
use std::error::Error;

use crate::bitcoin_keys::KeyError::{InvalidPublicBytes, UnsupportedOperation};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub enum BitcoinKey {
    Public(secp256k1::PublicKey),
    Private(secp256k1::SecretKey),
}

#[derive(Debug)]
pub enum KeyError {
    InvalidPublicBytes,
    InvalidPrivateBytes,
    UnsupportedOperation,
}
impl Error for KeyError {}
impl Display for KeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        //        write!(f, "{:?}", self)
        f.write_str(self.to_string().as_str())
    }
}

impl BitcoinKey {
    pub fn new_public(key: &[u8]) -> Result<Self, KeyError> {
        let public_key = PublicKey::from_slice(key).map_err(|_e| InvalidPublicBytes)?;
        Ok(Self::Public(public_key))
    }

    pub fn new_private(key: &[u8]) -> Result<Self, KeyError> {
        let secret = SecretKey::from_slice(key).map_err(|_e| InvalidPublicBytes)?;
        Ok(Self::Private(secret))
    }

    pub fn serialize_public(&self) -> [u8; 33] {
        match self.as_public() {
            Self::Public(x) => x.serialize(),
            Self::Private(_) => unreachable!(),
        }
    }

    pub fn serialize_private(&self) -> Result<[u8; 32], KeyError> {
        match self {
            Self::Public(_) => Err(UnsupportedOperation),
            Self::Private(x) => Ok(x[..].try_into().unwrap()),
        }
    }

    pub fn as_public(&self) -> Self {
        match self {
            Self::Public(_) => self.clone(),
            Self::Private(x_prv) => {
                let ctx = Secp256k1::new();
                Self::Public(PublicKey::from_secret_key(&ctx, x_prv))
            }
        }
    }

    pub fn ec_or_scalar_add(&self, other: &Self) -> Result<Self, secp256k1::Error> {
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
}
