use hmac::{Hmac, Mac};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Sha256, Sha512};

pub fn ckd_priv(k_par: &[u8], c_par: &[u8], i: u32) -> (Box<[u8]>, Box<[u8]>) {
    let mut mac = Hmac::<Sha512>::new_varkey(c_par).unwrap();
    let ctx = Secp256k1::new();
    if i >= 1 << 31 {
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
    let i_r = &result[32..];

    let mut secr_key = SecretKey::from_slice(i_l).unwrap();
    secr_key.add_assign(k_par);

    (
        secr_key[..].to_owned().into_boxed_slice(),
        i_r.to_owned().into_boxed_slice(),
    )
}
