
pub trait Encryptable<T: Crypto<Self>>
where
    Self: Sized,
{
}
pub trait Crypto<Item>{
    type SecretKey;
    type Representation;
    fn encrypto(&self, s_key: &Self::SecretKey, item: Item) -> Self::Representation;
    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Item;
}

pub struct Cryptor;
impl Cryptor {
    #[inline]
    pub fn encrypto<Item: Encryptable<Strategy>, Strategy: Crypto<Item>>(
        strategy: Strategy,
        s_key: &Strategy::SecretKey,
        item: Item,
    ) -> Strategy::Representation {
        strategy.encrypto(s_key, item)
    }
    #[inline]
    pub fn decrypto<Item: Encryptable<Strategy>, Strategy: Crypto<Item>>(
        strategy: Strategy,
        s_key: &Strategy::SecretKey,
        rep: Strategy::Representation,
    ) -> Item {
        strategy.decrypto(s_key, rep)
    }
}

pub trait Encrypted<Cipher, PublicKey>{
    fn cipher(&self) -> &Cipher;
    fn p_key(&self) -> &PublicKey;
    fn get_and_drop(self) -> (Cipher, PublicKey);
    fn get_ref(&self) -> (&Cipher, &PublicKey) {
        (self.cipher(), self.p_key())
    }
}
