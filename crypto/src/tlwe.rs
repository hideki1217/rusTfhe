use num::{ToPrimitive, Zero};

use math_utils::torus;

use super::digest::{Crypto, Encrypted};
use math_utils::{Binary, ModDistribution, Random, Torus};

pub struct TLWE<const N: usize>;
impl<const N: usize> TLWE<N> {
    const N: usize = 635;
    const ALPHA: f32 = 0.000030518; // 2-{-15}
    pub fn new() -> Self {
        TLWE
    }
    pub fn binary2torus(bin: Binary) -> Torus {
        torus!(match bin {
            Binary::One => 1.0 / 8.0,
            Binary::Zero => -1.0 / 8.0,
        })
    }
    pub fn torus2binary(torus: Torus) -> Binary {
        let f = torus.to_f32().unwrap();
        if f < 0.5 {
            Binary::One
        } else {
            Binary::Zero
        }
    }
}
impl<const N: usize> Default for TLWE<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Crypto<Binary> for TLWE<N> {
    type SecretKey = [Binary; N];
    type Cipher = Torus;
    type PublicKey = [Torus; N];

    fn encrypto(
        &self,
        key: &Self::SecretKey,
        item: Binary,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        self.encrypto(key, TLWE::<N>::binary2torus(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Binary {
        TLWE::<N>::torus2binary(self.decrypto(s_key, p_key, cipher))
    }
}
impl<const N: usize> Crypto<Torus> for TLWE<N> {
    type SecretKey = [Binary; N];
    type Cipher = Torus;
    type PublicKey = [Torus; N];

    fn encrypto(
        &self,
        key: &Self::SecretKey,
        item: Torus,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TLWE::<N>::ALPHA);

        let a: [Torus; N] = unif.gen_n();
        let m = item;
        let e = norm.gen();
        let b = a
            .iter()
            .zip(key.iter())
            .map(|(&a, &b)| a * b.to::<u32>())
            .fold(Torus::zero(), |s, x| s + x)
            + e
            + m;
        Encrypted(b, a)
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Torus {
        let a_cross_s = p_key
            .iter()
            .zip(s_key.iter())
            .map(|(&a, &b)| a * b.to::<i32>())
            .fold(Torus::zero(), |s, x| s + x);
        let m_with_e = cipher - a_cross_s;

        m_with_e
    }
}

#[cfg(test)]
mod tests {
    use math_utils::*;
    use super::*;

    #[test]
    fn tlwe_test() {
        let mut b_uniform = BinaryDistribution::uniform();
        let tlwe = TLWE::new();

        let mut test = |item: Binary| {
            let s_key: [Binary; TLWE::<0>::N] = b_uniform.gen_n();
            let Encrypted(cipher, p_key) = tlwe.encrypto(&s_key, item);
            let res: Binary = tlwe.decrypto(&s_key, &p_key, cipher);

            assert!(res == item, "cipher={:?}\np_key={:?}", cipher, p_key);
        };

        for i in 0..100 {
            test(Binary::from(i % 2))
        }
    }
}
