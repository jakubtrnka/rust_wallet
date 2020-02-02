pub mod addresses;
pub mod base58;
pub mod bip32;
pub mod bitcoin_keys;
pub mod hashes;

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum NetworkType {
    Mainnet,
    Testnet,
}

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
