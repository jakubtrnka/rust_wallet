/// source: Reference implementation of BIP173
/// https://github.com/sipa/bech32/blob/4ec94646bebb3ee8932cb251ad80d98822872e87/ref/rust/src/bech32.rs
use super::{CodingError, Result};

/// Grouping structure for the human-readable part and the data part
/// of decoded Bech32 string.
#[derive(PartialEq, Debug, Clone)]
pub struct Bech32 {
    /// Human-readable part
    pub hrp: String,
    /// Data payload
    pub data: Vec<u8>,
}

// Human-readable part and data part separator
const SEP: char = '1';

// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
    'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

impl Bech32 {
    /// Encode as a string
    pub fn to_string(&self) -> Result<String> {
        if self.hrp.is_empty() {
            return Err(CodingError::InvalidLength);
        }
        let hrp_bytes: Vec<u8> = self.hrp.clone().into_bytes();
        let mut combined: Vec<u8> = self.data.clone();
        combined.extend_from_slice(&create_checksum(&hrp_bytes, &self.data));
        let mut encoded: String = format!("{}{}", self.hrp, SEP);
        for p in combined {
            if p >= 32 {
                return Err(CodingError::InvalidData);
            }
            encoded.push(CHARSET[p as usize]);
        }
        Ok(encoded)
    }

    /// Decode from a string
    pub fn from_string(s: &str) -> Result<Bech32> {
        // Ensure overall length is within bounds
        let len: usize = s.len();
        if len < 8 || len > 90 {
            return Err(CodingError::InvalidLength);
        }

        // Check for missing separator
        if s.find(SEP).is_none() {
            return Err(CodingError::MissingSeparator);
        }

        // Split at separator and check for two pieces
        let parts: Vec<&str> = s.rsplitn(2, SEP).collect();
        let raw_hrp = parts[1];
        let raw_data = parts[0];
        if raw_hrp.is_empty() || raw_data.len() < 6 {
            return Err(CodingError::InvalidLength);
        }

        let mut has_lower: bool = false;
        let mut has_upper: bool = false;
        let mut hrp_bytes: Vec<u8> = Vec::new();
        for b in raw_hrp.bytes() {
            // Valid subset of ASCII
            if b < 33 || b > 126 {
                return Err(CodingError::InvalidChar);
            }
            // Lowercase
            if b >= b'a' && b <= b'z' {
                has_lower = true;
            }
            // Uppercase
            let c = if b >= b'A' && b <= b'Z' {
                has_upper = true;
                // Convert to lowercase
                b + (b'a' - b'A')
            } else {
                b
            };
            hrp_bytes.push(c);
        }

        // Check data payload
        let mut data_bytes: Vec<u8> = Vec::new();
        for b in raw_data.bytes() {
            // Aphanumeric only
            if !((b >= b'0' && b <= b'9') || (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z')) {
                return Err(CodingError::InvalidChar);
            }
            // Excludes these characters: [1,b,i,o]
            if b == b'1' || b == b'b' || b == b'i' || b == b'o' {
                return Err(CodingError::InvalidChar);
            }
            // Lowercase
            if b >= b'a' && b <= b'z' {
                has_lower = true;
            }
            // Uppercase
            let c = if b >= b'A' && b <= b'Z' {
                has_upper = true;
                b + (b'a' - b'A')
            } else {
                b
            };
            data_bytes.push(CHARSET_REV[c as usize] as u8);
        }

        // Ensure no mixed case
        if has_lower && has_upper {
            return Err(CodingError::MixedCase);
        }

        // Ensure checksum
        if !verify_checksum(&hrp_bytes, &data_bytes) {
            return Err(CodingError::InvalidChecksum);
        }

        // Remove checksum from data payload
        let dbl: usize = data_bytes.len();
        data_bytes.truncate(dbl - 6);

        Ok(Bech32 {
            hrp: String::from_utf8(hrp_bytes).unwrap(),
            data: data_bytes,
        })
    }
}

fn create_checksum(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values: Vec<u8> = hrp_expand(hrp);
    values.extend_from_slice(data);
    // Pad with 6 zeros
    values.extend_from_slice(&[0u8; 6]);
    let plm: u32 = polymod(values) ^ 1;
    let mut checksum: Vec<u8> = Vec::new();
    for p in 0..6 {
        checksum.push((plm >> (5 * (5 - p)) & 0x1f) as u8);
    }
    checksum
}

fn verify_checksum(hrp: &[u8], data: &[u8]) -> bool {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    polymod(exp) == 1u32
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for b in hrp {
        v.push(*b >> 5);
    }
    v.push(0);
    for b in hrp {
        v.push(*b & 0x1f);
    }
    v
}

// Generator coefficients
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

fn polymod(values: Vec<u8>) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x01ff_ffff) << 5 ^ (v as u32);
        for (i, _) in GEN.iter().enumerate() {
            if (b >> i as u8) & 1 == 1 {
                chk ^= GEN[i]
            }
        }
    }
    chk
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bch_vectors() {
        let valid_code_1 = "A12UEL5L";
        let valid_code_2 = "a12uel5l";
        let valid_code_3 = concat!(
            "an83characterlonghumanreadablepartthatcontainsthenumber1andth",
            "eexcludedcharactersbio1tt5tgs"
        );
        let valid_code_4 = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
        let valid_code_5 = concat!(
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "qqqqqqqqqqqqqqqqqqqqqqqc8247j"
        );
        let valid_code_6 = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w";

        let invalid_code_1 = "abcdef1qqzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
        let invalid_code_2 = "abcdef1qPZRy9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
        let invalid_code_3 = concat!(
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce66mua7lmqqqxwwmua7lmqqqmua7lmqqqxw",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce66mua7lmqqqxwwmua7lmqqqmua7lmqqqxw",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce66mua7lmqqqxwwmua7lmqqqmua7lmqqqxw",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce66mua7lmqqqxwwmua7lmqqqmua7lmqqqxw",
        );
        let invalid_code_4 = "a12ul";
        let invalid_code_5 = "abcdef1qpzry9x8g#2tvdw0s3jn54khce6mua7lmqqqxw";

        assert_eq!(
            Bech32::from_string(invalid_code_1).unwrap_err(),
            CodingError::InvalidChecksum
        );
        assert_eq!(
            Bech32::from_string(invalid_code_2).unwrap_err(),
            CodingError::MixedCase
        );
        assert_eq!(
            Bech32::from_string(invalid_code_3).unwrap_err(),
            CodingError::InvalidLength
        );
        assert_eq!(
            Bech32::from_string(invalid_code_4).unwrap_err(),
            CodingError::InvalidLength
        );
        assert_eq!(
            Bech32::from_string(invalid_code_5).unwrap_err(),
            CodingError::InvalidChar
        );

        Bech32::from_string(valid_code_1).unwrap();
        Bech32::from_string(valid_code_2).unwrap();
        Bech32::from_string(valid_code_3).unwrap();
        Bech32::from_string(valid_code_4).unwrap();
        Bech32::from_string(valid_code_5).unwrap();
        Bech32::from_string(valid_code_6).unwrap();
    }
}
