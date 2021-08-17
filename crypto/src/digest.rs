use std::ops::{Add, Sub};

pub trait Encryptable<T: Crypto<Self>>
where
    Self: Sized,
{
}
pub trait Crypto<Item> {
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

#[derive(Debug, Clone)]
pub struct Encrypted<Cipher, PublicKey>(pub Cipher, pub PublicKey);
impl<S: Add<S>, T: Add<T>> Add for Encrypted<S, T> {
    type Output = Encrypted<<S as Add<S>>::Output, <T as Add<T>>::Output>;
    fn add(self, rhs: Self) -> Self::Output {
        let Encrypted(b, a) = self;
        let Encrypted(s, t) = rhs;
        Encrypted(b + s, a + t)
    }
}
impl<S: Sub<S>, T: Sub<T>> Sub for Encrypted<S, T> {
    type Output = Encrypted<<S as Sub<S>>::Output, <T as Sub<T>>::Output>;
    fn sub(self, rhs: Self) -> Self::Output {
        let Encrypted(b, a) = self;
        let Encrypted(s, t) = rhs;
        Encrypted(b - s, a - t)
    }
}
impl<Cipher, PublicKey> Encrypted<Cipher, PublicKey> {
    pub fn cipher(&self) -> &Cipher {
        &self.0
    }
    pub fn p_key(&self) -> &PublicKey {
        &self.1
    }
    pub fn get_ref(&self) -> (&Cipher, &PublicKey) {
        (&self.0, &self.1)
    }
    pub fn get_and_drop(self) -> (Cipher, PublicKey) {
        (self.0, self.1)
    }
}
