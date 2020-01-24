use hmac::{Hmac, Mac};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;

const MAINNET_PRIVATE_MAGIC: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
const MAINNET_PUBLIC_MAGIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

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

pub fn ckd_priv(k_par: &[u8; 32], c_par: &[u8; 32], i: u32) -> ([u8; 32], [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_varkey(c_par).unwrap();
    let ctx = Secp256k1::new();
    if i >= 0x80000000 {
        mac.input(&[0u8]);
        mac.input(k_par);
    } else {
        let secr_key = SecretKey::from_slice(k_par).unwrap();
        let pub_key = PublicKey::from_secret_key(&ctx, &secr_key);
        mac.input(&pub_key.serialize());
    }
    mac.input(&i.to_be_bytes());
    let result = mac.result().code();
    let i_l = &result[0..32];
    let mut i_r = [0u8; 32];
    i_r.copy_from_slice(&result[32..]);

    let mut k_child_secr = SecretKey::from_slice(i_l).unwrap();
    k_child_secr.add_assign(k_par).unwrap();
    let mut k_child = [0u8; 32];
    k_child.copy_from_slice(&k_child_secr[..]);

    (k_child, i_r)
}

pub fn ckd_pub(kk_par: &[u8; 33], c_par: &[u8; 32], i: u32) -> ([u8; 33], [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_varkey(c_par).unwrap();
    let ctx = Secp256k1::new();
    if i >= 1 << 31 {
        panic!("not possible");
    } else {
        mac.input(kk_par);
    }
    mac.input(&i.to_be_bytes());
    let result = mac.result().code();
    let i_l = &result[0..32];
    let mut i_r = [0u8; 32];
    i_r.copy_from_slice(&result[32..]);

    let i_l_pub = PublicKey::from_secret_key(&ctx, &SecretKey::from_slice(i_l).unwrap());
    let kk_child = i_l_pub
        .combine(&PublicKey::from_slice(kk_par).unwrap())
        .unwrap()
        .serialize();
    (kk_child, i_r)
}

pub fn hd_wallet_public(enthropy: &[u8], path: &[u32]) -> [u8; 33] {
    unimplemented!()
}

pub fn hd_wallet_secret(enthropy: &[u8], path: &[u32]) -> [u8; 82] {
    fn recursion(
        k_par: [u8; 32],
        c_par: [u8; 32],
        key_index: &[u32],
    ) -> ([u8; 32], [u8; 32], [u8; 20]) {
        let (k_child, c_child) = ckd_priv(&k_par, &c_par, key_index[0]);
        if key_index.len() == 1 {
            let ctx = Secp256k1::new();
            let pub_k_par =
                PublicKey::from_secret_key(&ctx, &SecretKey::from_slice(&k_par).unwrap());
            (
                k_child,
                c_child,
                crate::hashes::hash160(&pub_k_par.serialize()),
            )
        } else {
            recursion(k_child, c_child, &key_index[1..])
        }
    }
    let mut mac = Hmac::<Sha512>::new_varkey(b"Bitcoin seed").unwrap();
    mac.input(enthropy);
    let result = mac.result().code();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    let mut chain_code0 = [0u8; 32];
    chain_code0.copy_from_slice(&result[32..]);
    let (private_key, chain_code, parent_id) = if path.len() == 0 {
        (
            key,
            chain_code0,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
    } else {
        recursion(key, chain_code0, path)
    };

    let mut output: [u8; 82] = [0; 82];
    copy_to_offset(&mut output, 0, &MAINNET_PRIVATE_MAGIC);
    copy_to_offset(&mut output, 4, &[path.len() as u8]);
    copy_to_offset(&mut output, 5, &parent_id[0..4]);
    copy_to_offset(&mut output, 9, &path.last().unwrap_or(&0).to_be_bytes());
    copy_to_offset(&mut output, 13, &chain_code);
    copy_to_offset(&mut output, 45, &[0]);
    copy_to_offset(&mut output, 46, &private_key);
    let checksum = crate::hashes::sha256d(&output[0..78]);
    copy_to_offset(&mut output, 78, &checksum[0..4]);
    output
}

#[cfg(test)]
mod test {

    const SEED: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn test_ext_priv0() {
        let private_key = crate::bip32::hd_wallet_secret(&SEED, &[]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMR\
            NNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn test_ext_priv1() {
        let private_key = crate::bip32::hd_wallet_secret(&SEED, &[0x80000000]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11\
            eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
    }

    #[test]
    fn test_ext_priv2() {
        let private_key = crate::bip32::hd_wallet_secret(&SEED, &[0x80000000, 1]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8M\
            SY3H2EU4pWcQDnRnrVA1xe8fs"
        );
    }

    #[test]
    fn test_ext_priv3() {
        let private_key = crate::bip32::hd_wallet_secret(&SEED, &[0x80000000, 1, 0x80000002]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiN\
            MjANTtpgP4mLTj34bhnZX7UiM"
        );
    }

    #[test]
    fn test_ext_priv4() {
        let private_key = crate::bip32::hd_wallet_secret(&SEED, &[0x80000000, 1, 0x80000002, 2]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsun\
            u5Mm3wDvUAKRHSC34sJ7in334"
        );
    }

    #[test]
    fn test_ext_priv5() {
        let private_key =
            crate::bip32::hd_wallet_secret(&SEED, &[0x80000000, 1, 0x80000002, 2, 1000000000]);
        let xpriv = crate::base58::bytes_to_base58(&private_key);
        assert_eq!(
            xpriv,
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSr\
            uoUihUZREPSL39UNdE3BBDu76"
        );
    }
}
