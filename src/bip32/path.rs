use crate::bip32::BIP32Error;
use std::convert::TryFrom;
use std::slice::Iter;

#[derive(Debug)]
pub(crate) struct Bip32Path(Vec<u32>);

impl TryFrom<&str> for Bip32Path {
    type Error = BIP32Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim_start_matches("m/").trim_end_matches('/');
        fn index_to_number(idx: &str) -> Result<u32, BIP32Error> {
            if idx.ends_with('\'') {
                idx.trim_end_matches('\'')
                    .parse::<u32>()
                    .map(|i| i + 0x8000_0000)
            } else {
                idx.parse::<u32>()
            }
            .map_err(|e| BIP32Error::WrongBip32Path(e.to_string()))
        }
        let mut output = Vec::new();

        if !value.is_empty() {
            for idx in value.split('/') {
                output.push(index_to_number(idx)?)
            }
        }
        Ok(Self(output))
    }
}

impl Into<Vec<u32>> for Bip32Path {
    fn into(self) -> Vec<u32> {
        self.0
    }
}

impl Bip32Path {
    pub(crate) fn iter(&self) -> Iter<u32> {
        self.0.iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_bip32_path() {
        let p1: Vec<u32> = Bip32Path::try_from("m/1/144/12'/1").unwrap().into();
        let p2: Vec<u32> = Bip32Path::try_from("m/10'").unwrap().into();
        let p3: Vec<u32> = Bip32Path::try_from("m/10/").unwrap().into();
        let p4: Vec<u32> = Bip32Path::try_from("m/10").unwrap().into();
        let p5: Vec<u32> = Bip32Path::try_from("m/").unwrap().into();
        let p6: Vec<u32> = Bip32Path::try_from("m/10/12/").unwrap().into();
        let p7: Vec<u32> = Bip32Path::try_from("10/12").unwrap().into();
        let p8: Vec<u32> = Bip32Path::try_from("/").unwrap().into();
        let p9: Vec<u32> = Bip32Path::try_from("").unwrap().into();
        Bip32Path::try_from("invalid").unwrap_err();
        assert_eq!(p1, [1_u32, 144, (1_u32 << 31) + 12, 1]);
        assert_eq!(p2, [(1 << 31) + 10_u32]);
        assert_eq!(p3, [10_u32]);
        assert_eq!(p4, [10_u32]);
        assert_eq!(p5, []);
        assert_eq!(p6, [10, 12]);
        assert_eq!(p7, [10, 12]);
        assert_eq!(p8, []);
        assert_eq!(p9, []);

    }
}
