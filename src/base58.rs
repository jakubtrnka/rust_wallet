use std::iter::FromIterator;

const ABC: [char; 58] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
    'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e',
    'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z',
];

pub fn bytes_to_base58(bytes: &[u8]) -> String {
    let mut output = Vec::<u32>::with_capacity(bytes.len() * 2);
    for byte in bytes.iter() {
        let mut carry: u16 = *byte as u16;
        for digit in output.iter_mut() {
            *digit = *digit * 256 + carry as u32;
            carry = (*digit / 58) as u16;
            *digit %= 58;
        }
        while carry != 0 {
            output.push((carry % 58) as u32);
            carry /= 58;
        }
    }
    String::from_iter(output.iter().rev().map(|c| ABC[*c as usize]))
}

pub fn base58_to_bytes(code: &str) -> Result<Vec<u8>, &'static str> {
    if !code.is_ascii() {
        return Err("Non-ascii characters");
    }
    let digits = code
        .chars()
        .map(|c| ABC.iter().position(|i| *i == c))
        .collect::<Vec<Option<usize>>>();

    let mut output = Vec::<u32>::with_capacity(digits.len());
    for &opt_word in digits.iter() {
        match opt_word {
            None => return Err("Invalid character"),
            Some(word) => {
                let mut carry: u16 = word as u16;
                for digit in output.iter_mut() {
                    *digit = *digit * 58 + carry as u32;
                    carry = (*digit / 256) as u16;
                    *digit %= 256;
                }
                while carry != 0 {
                    output.push((carry % 256) as u32);
                    carry /= 256;
                }
            }
        }
    }
    Ok(output.iter().rev().map(|c| *c as u8).collect())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_base58_encoder() {
        assert_eq!(
            bytes_to_base58(&[
                0x04, 0x3c, 0x4c, 0x50, 0x99, 0x76, 0x9c, 0xf4, 0xe3, 0xc2, 0x28, 0x58, 0x95, 0x62,
                0x99, 0x60, 0xd8, 0xae, 0xdc, 0x86, 0x84, 0x03, 0x0b, 0x9d, 0x74, 0x6d, 0x10, 0x59,
                0x4c, 0x81, 0xb9, 0x98, 0x09, 0x71, 0x5f, 0x67, 0x5f, 0x10, 0xf9, 0x43, 0xb6, 0x12,
                0x1f, 0xef, 0x09, 0x13, 0xa5, 0x24, 0xee, 0xe3, 0xea, 0xe4, 0x27, 0xa7, 0xa4, 0x18,
                0xfb, 0xf5, 0x6a, 0x67, 0xa3, 0x42, 0x4a, 0x87,
            ]),
            String::from(
                "5usUX2PKUw7rbN238ggjxdD5HthFFFaJJpMLGBuo95KW6q5eNVpynaqX1PVFX2DAtPzrq\
                 DLstm8JicBS16mbMPC"
            )
        );
        assert_eq!(
            bytes_to_base58(&[0x05, 0x7f, 0x89, 0xe7, 0x7b]),
            String::from("cyju6S")
        );
    }

    #[test]
    fn test_base58_decoder() {
        assert_eq!(
            base58_to_bytes(&String::from(
                "61mNuLymU8nGjeLSgDsXAwT6WPwjPxfx1jK6469GdhHeU8ws1Ds6CrLGFJD\
                 hovxybzg9uDjAN8phJdX2m4YqhP9Q"
            )),
            Ok([
                0xfa, 0xbe, 0xac, 0x05, 0x0b, 0xb8, 0x70, 0x3c, 0xae, 0x3e, 0xd7, 0x76, 0xdf, 0x0e,
                0x4f, 0x8e, 0xf7, 0xb9, 0x7f, 0xe9, 0xb9, 0x14, 0xd7, 0xd2, 0x54, 0xa3, 0x6c, 0x9d,
                0xe3, 0x79, 0x02, 0x04, 0xda, 0x99, 0x1b, 0xda, 0x04, 0x00, 0xfe, 0x72, 0x92, 0x51,
                0x79, 0x4c, 0x9f, 0xb2, 0xbf, 0x10, 0x97, 0xf4, 0xcf, 0x61, 0xaa, 0x8d, 0xc8, 0x61,
                0x7f, 0xde, 0xef, 0xd6, 0xf5, 0xe5, 0xb0, 0x5fu8,
            ]
            .to_vec())
        );
    }
}
