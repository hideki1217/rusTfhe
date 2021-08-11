use self::math::{Binary, Random, Torus};
use num::{ToPrimitive, Zero};

mod math;

pub trait Crypto<Item> {
    type Representation;
    type SecretKey;
    type Cipher;
    type PublicKey;
    fn encode(&self, item: Item) -> Self::Representation;
    fn do_encrypto(
        &self,
        key: Self::SecretKey,
        rep: Self::Representation,
    ) -> (Self::Cipher, Self::PublicKey);
    fn do_decrypto(
        &self,
        s_key: Self::SecretKey,
        p_key: Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Self::Representation;
    fn decode(&self, rep: Self::Representation) -> Item;

    fn encrypto(&self, key: Self::SecretKey, item: Item) -> (Self::Cipher, Self::PublicKey) {
        self.do_encrypto(key, self.encode(item))
    }
    fn decrypto(
        &self,
        s_key: Self::SecretKey,
        p_key: Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Item {
        self.decode(self.do_decrypto(s_key, p_key, cipher))
    }
}

struct TLWE();
impl TLWE {
    const N: usize = 635;
    const ALPHA: f32 = 1e-15;
    fn new() -> Self {
        TLWE()
    }
}
impl Crypto<math::Binary> for TLWE {
    type Representation = Torus;
    type SecretKey = [Binary; TLWE::N];
    type Cipher = Torus;
    type PublicKey = [Torus; TLWE::N];

    fn encode(&self, item: Binary) -> Self::Representation {
        Torus::from_f32(match item {
            Binary::One => 1.0 / 8.0,
            Binary::Zero => -1.0 / 8.0,
        })
    }
    fn do_encrypto(
        &self,
        key: Self::SecretKey,
        rep: Self::Representation,
    ) -> (Self::Cipher, Self::PublicKey) {
        let mut unif = math::ModDistribution::uniform();
        let mut norm = math::ModDistribution::gaussian(TLWE::ALPHA);

        let a: [math::Torus; TLWE::N] = unif.genN();
        let m = rep;
        let e = norm.gen();
        let b = a
            .iter()
            .zip(key.iter())
            .map(|(&a, &b)| a * b.to::<u32>())
            .fold(math::Torus::zero(), |s, x| s + x)
            + e
            + m;
        (b, a)
    }

    fn do_decrypto(
        &self,
        s_key: Self::SecretKey,
        p_key: Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Self::Representation {
        let a_cross_s = p_key
            .iter()
            .zip(s_key.iter())
            .map(|(&a, &b)| a * b.to::<i32>())
            .fold(Torus::zero(), |s, x| s + x);
        let m_with_e = cipher - a_cross_s;

        m_with_e
    }
    fn decode(&self, rep: Self::Representation) -> math::Binary {
        let f = rep.to_f32().unwrap();
        if f < 0.5 {
            Binary::One
        } else {
            Binary::Zero
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlwe_test() {
        let mut b_uniform = math::BinaryDistribution::uniform();
        let tlwe = TLWE::new();

        let mut test = |item:Binary| {
            let s_key: [Binary; TLWE::N] = b_uniform.genN();
            let (cipher, p_key) = tlwe.encrypto(s_key, item);
            let res = tlwe.decrypto(s_key, p_key, cipher);
    
            assert!(res == item,"cipher={:?}\np_key={:?}", cipher, p_key);
        };

        for i in 0..100 { test(Binary::from(i%2)) }
    }
}
