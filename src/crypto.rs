mod math;

use num::Unsigned;

pub trait Crypto<Item> {
    type SecretKey;
    type Cipher;
    type PublicKey;
    fn encrypto(&self, key: Self::SecretKey, item: Item) -> (Self::Cipher, Self::PublicKey);
    fn decrypto(&self, s_key: Self::SecretKey, p_key: Self::PublicKey, cipher: Self::Cipher) -> Item;
}

struct TLWE();
impl TLWE {
    const N:u32 = 635;
    const ALPHA:f32 = 1e-15;
    fn new() -> Self {TLWE()}
}
impl Crypto<math::Binary> for TLWE {
    type SecretKey = [math::Binary;TLWE::N as usize];
    type Cipher = math::Decimal<u32>;
    type PublicKey = [math::Decimal<u32>;TLWE::N as usize];

    fn encrypto(&self, key: Self::SecretKey, item: math::Binary) -> (Self::Cipher, Self::PublicKey) {
        todo!()
    }

    fn decrypto(&self, s_key: Self::SecretKey, p_key: Self::PublicKey, cipher: Self::Cipher) -> math::Binary {
        todo!()
    }
    
}




