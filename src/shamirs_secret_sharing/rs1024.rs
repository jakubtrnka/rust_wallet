pub fn rs1024_polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 10] = [
        0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
        0x21b1f890, 0x3f3f120,
    ];

    let mut chk = 1u32;

    for v in values.iter() {
        let b = chk >> 20;
        chk = ((chk & 0xfffff) << 10) ^ v;
        for (idx, &g) in GEN.iter().enumerate() {
            chk ^= match (b >> idx as u32) & 1 {
                0 => 0u32,
                _ => g,
            }
        }
    }
    chk
}

fn concat_data(cs: &str, data: &[u32]) -> Vec<u32> {
    let mut unicode_vals: Vec<u32> = cs.chars().map(|x| x as u32).collect();
    unicode_vals.extend_from_slice(&data);
    unicode_vals
}

pub fn rs1024_verify_checksum(cs: &str, data: &[u32]) -> bool {
    rs1024_polymod(concat_data(cs, &data).as_slice()) == 1
}

pub fn rs1024_create_checksum(cs: &str, data: &[u32]) -> Vec<u32> {
    let mut values_vec = concat_data(cs, &data);
    values_vec.extend_from_slice(&[0, 0, 0]);

    let polymod: u32 = rs1024_polymod(values_vec.as_slice()) ^ 1;
    (0..3)
        .map(|i| (polymod >> (10 * (2 - i))) & 1023_u32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rs1024_creation() {
        let rnd_bytes: [u32; 32] = [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ];
        let customization_string = String::from("some test string");
        let reference: Vec<u32> = vec![252, 310, 547];
        assert_eq!(
            rs1024_create_checksum(&customization_string, &rnd_bytes),
            reference
        );
    }

    #[test]
    fn test_rs1024_verification() {
        // rnd_bytes = sha256("seed2")
        let rnd_bytes: [u32; 32] = [
            53, 176, 250, 209, 103, 88, 181, 129, 36, 243, 159, 0, 210, 96, 97, 112, 69, 20, 190,
            78, 57, 193, 224, 59, 123, 35, 83, 74, 253, 96, 129, 227,
        ];
        let customization_string = String::from("some test2 string");
        let reference_checksum: [u32; 3] = [667, 459, 996];

        let mut data_with_checksum: Vec<u32> = Vec::from(&rnd_bytes[..]);
        data_with_checksum.extend_from_slice(&reference_checksum);
        assert!(rs1024_verify_checksum(
            &customization_string,
            data_with_checksum.as_slice()
        ));
    }
}
