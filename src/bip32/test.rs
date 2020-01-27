use crate::{base58, bip32};
const SEED: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[test]
fn test_ext_keys_from_seed_0() {
    let private_key = bip32::secret_ext_key_from_enthropy(&SEED, &[]);
    let public_key = bip32::public_ext_key_from_enthropy(&SEED, &[]);
    let xpriv = base58::bytes_to_base58(&private_key);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsef\
         D265TMg7usUDFdp6W1EGMcet8"
    );
    assert_eq!(
        xpriv,
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMR\
         NNU3TGtRBeJgk33yuGBxrMPHi"
    );
}

#[test]
fn test_ext_keys_from_seed_1() {
    let public_key = bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000]);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bg\
         wQ9xv5ski8PX9rL2dZXvgGDnw"
    );
    let private_key = bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000]);
    let xpriv = base58::bytes_to_base58(&private_key);
    assert_eq!(
        xpriv,
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11\
         eZG7XnxHrnYeSvkzY7d2bhkJ7"
    );
}

#[test]
fn test_ext_keys_from_seed_2() {
    let public_key = bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1]);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq52\
         7Hqck2AxYysAA7xmALppuCkwQ"
    );
    let private_key = bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1]);
    let xpriv = base58::bytes_to_base58(&private_key);
    assert_eq!(
        xpriv,
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8M\
         SY3H2EU4pWcQDnRnrVA1xe8fs"
    );
}

#[test]
fn test_ext_keys_from_seed_3() {
    let public_key = bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002]);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4\
        trkrX7x7DogT5Uv6fcLW5"
    );
    let private_key = bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002]);
    let xpriv = base58::bytes_to_base58(&private_key);
    assert_eq!(
        xpriv,
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjAN\
        TtpgP4mLTj34bhnZX7UiM"
    );
}

#[test]
fn test_ext_keys_from_seed_4() {
    let public_key = bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2]);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cf\
        N7fe5JnJ7dh8zL4fiyLHV"
    );
    let private_key = bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2]);
    let xpriv = base58::bytes_to_base58(&private_key);
    assert_eq!(
        xpriv,
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm\
        3wDvUAKRHSC34sJ7in334"
    );
}

#[test]
fn test_ext_keys_from_seed_5() {
    let public_key =
        bip32::public_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2, 10_0000_0000]);
    let xpub = base58::bytes_to_base58(&public_key);
    assert_eq!(
        xpub,
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTv\
        XEYBVPamhGW6cFJodrTHy"
    );
    let private_key =
        bip32::secret_ext_key_from_enthropy(&SEED, &[0x8000_0000, 1, 0x8000_0002, 2, 10_0000_0000]);
    let xpriv = base58::bytes_to_base58(&private_key);
    assert_eq!(
        xpriv,
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUi\
        hUZREPSL39UNdE3BBDu76"
    );
}

#[test]
fn test_deserialization_serialization_1() {
    let pub_str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsf\
                   TFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
    let priv_str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCes\
                    nDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    let deserialized_priv_key = bip32::RawExtendedKey::parse_from_bytes(
        base58::base58_to_bytes(priv_str).unwrap().as_slice(),
    )
    .unwrap();
    assert_eq!(
        base58::bytes_to_base58(&deserialized_priv_key.ext_pub().serialize()),
        pub_str.to_owned()
    );
}

#[test]
#[should_panic]
fn test_bad_checksum_deserialization_1() {
    let pub_str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsf\
                   TFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnx";
    bip32::RawExtendedKey::parse_from_bytes(base58::base58_to_bytes(pub_str).unwrap().as_slice())
        .expect("Should fail");
}

#[test]
#[should_panic]
fn test_bad_checksum_deserialization_2() {
    let priv_str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCes\
                    nDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ8";
    bip32::RawExtendedKey::parse_from_bytes(base58::base58_to_bytes(priv_str).unwrap().as_slice())
        .expect("Should fail");
}
