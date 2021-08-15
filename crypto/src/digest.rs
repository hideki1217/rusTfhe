use std::ops::Add;

pub struct Encrypted<Cipher, PublicKey>(pub Cipher,pub PublicKey);
impl<S: Add<S>, T: Add<T>> Add for Encrypted<S, T> {
    type Output = Encrypted<<S as Add<S>>::Output, <T as Add<T>>::Output>;
    fn add(self, rhs: Self) -> Self::Output {
        let Encrypted(b, a) = self;
        let Encrypted(s, t) = rhs;
        Encrypted(b + s, a + t)
    }
}
impl<Cipher, PublicKey> Encrypted<Cipher, PublicKey> {
    fn cipher(&self) -> &Cipher {
        &self.0
    }
    fn p_key(&self) -> &PublicKey {
        &self.1
    }
}
pub trait Crypto<Item> {
    type SecretKey;
    type Cipher;
    type PublicKey;
    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Item,
    ) -> Encrypted<Self::Cipher, Self::PublicKey>;
    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Item;
}