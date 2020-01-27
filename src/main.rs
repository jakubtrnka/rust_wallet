use rust_wallet::bip32;

fn main() {
    let seed = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let private_key = bip32::secret_ext_key_from_enthropy(&seed, &[0x8000_0000]);
    let xpriv = rust_wallet::base58::bytes_to_base58(&private_key);
    println!("{}", &xpriv);
}
