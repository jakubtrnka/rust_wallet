pub(crate) trait BIP32Formatter {
    const PUBLIC_MAGIC: [u8; 4];
    const PRIVATE_MAGIC: [u8; 4];
}

pub(crate) struct MainnetP2PKHFormatter;
impl BIP32Formatter for MainnetP2PKHFormatter {
    const PUBLIC_MAGIC: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
    const PRIVATE_MAGIC: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
}

pub(crate) struct TestnetP2PKHFormatter;
impl BIP32Formatter for TestnetP2PKHFormatter {
    const PUBLIC_MAGIC: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
    const PRIVATE_MAGIC: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
}

pub(crate) struct MainnetBIP84Formatter;
impl BIP32Formatter for MainnetBIP84Formatter {
    const PUBLIC_MAGIC: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
    const PRIVATE_MAGIC: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
}
pub(crate) struct TestnetBIP84Formatter;
impl BIP32Formatter for TestnetBIP84Formatter {
    const PUBLIC_MAGIC: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];
    const PRIVATE_MAGIC: [u8; 4] = [0x04, 0x5f, 0x18, 0xbc];
}
