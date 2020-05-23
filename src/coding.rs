mod base58;
mod bech32;

pub use base58::*;

pub use bech32::Bech32;

#[derive(PartialEq, Debug)]
pub enum CodingError {
    /// String does not contain the separator character
    MissingSeparator,
    /// The checksum does not match the rest of the data
    InvalidChecksum,
    /// The data or human-readable part is too long or too short
    InvalidLength,
    /// Some part of the string contains an invalid character
    InvalidChar,
    /// Some part of the data has an invalid value
    InvalidData,
    /// The whole string must be of one case
    MixedCase,
}

pub type Result<T> = std::result::Result<T, CodingError>;
