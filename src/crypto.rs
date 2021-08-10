mod math;

pub trait Crypto<Item> {
    type SecretKey;
    type Cipher;
    type PublicKey;
    fn encrypto(&self, key: Self::SecretKey, item: Item) -> (Self::Cipher, Self::PublicKey);
    fn decrypto(&self, s_key: Self::SecretKey, p_key: Self::PublicKey, cipher: Self::Cipher) -> Item;
}




