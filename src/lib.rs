pub mod addresses;
pub mod bip32;
pub mod bitcoin_keys;
pub mod coding;
pub mod hashes;

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
