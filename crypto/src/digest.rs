use std::ops::Add;

#[derive(Debug,Clone)]
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
    pub fn cipher(&self) -> &Cipher {
        &self.0
    }
    pub fn p_key(&self) -> &PublicKey {
        &self.1
    }
    pub fn get_ref(&self) -> (&Cipher,&PublicKey) {
        (&self.0,&self.1)
    }
    pub fn get_and_drop(self) -> (Cipher,PublicKey) {
        (self.0,self.1)
    }
}
pub trait CryptoCore {
    type Representation;
}
pub trait Crypto<Item> :CryptoCore {
    type SecretKey;
    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Item,
    ) -> Self::Representation;
    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: Self::Representation
    ) -> Item;
}