use hmac::{Hmac, Mac};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Sha256, Sha512};
use ripemd160;
use ripemd160::Ripemd160;

pub fn ckd_priv(k_par: &[u8; 32], c_par: &[u8; 32], i: u32) -> ([u8; 32], [u8; 32]) {
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

pub fn hd_wallet_secret(enthropy: &[u8], path: &[u32]) -> [u8; 45] {
    fn recursion(k_par: [u8; 32], c_par: [u8; 32], i: &[u32]) -> ([u8; 32], [u8; 32]) {
        let (k_child, c_child) = ckd_priv(&k_par, &c_par, i[0]);
        if i.len() == 1 {
            return (k_child, c_child);
        } else {
            return recursion(k_child, c_child, &i[1..]);
        }
    }
    let mut mac = Hmac::<Sha512>::new_varkey("Bitcoin seed".as_bytes()).unwrap();
    mac.input(enthropy);
    let result = mac.result().code();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&result[32..]);
    let (private_key, chain_code) = recursion(key, chain_code, path);
//    let mut serialized = Vec::<u8>::with_capacity(45);
//    serialized.append
    let x = [
        [0x04, 0x88, 0xAD, 0xE4],
        [path.len() as u8],
        []
    ];
    let mut output: [u8; 45] = [0; 45];
    let xx = Ripemd160::<ripemd160::Digest>::new();
    println!("{:?}", xx);
    output
}
