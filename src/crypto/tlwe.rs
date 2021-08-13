use num::{ToPrimitive, Zero};

use super::utils::math::{Binary, Random, Torus,ModDistribution};
use super::digest::{Crypto, Encrypted};

pub struct TLWE<const N: usize>;
impl<const N: usize> TLWE<N> {
    const N: usize = 635;
    const ALPHA: f32 = 1e-15;
    pub fn new() -> Self {
        TLWE
    }
}
impl<const N: usize> Default for TLWE<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Crypto<Binary> for TLWE<N> {
    type Representation = Torus;
    type SecretKey = [Binary; N];
    type Cipher = Torus;
    type PublicKey = [Torus; N];

    fn encode(&self, item: Binary) -> Self::Representation {
        Torus::from_f32(match item {
            Binary::One => 1.0 / 8.0,
            Binary::Zero => -1.0 / 8.0,
        })
    }
    fn do_encrypto(
        &self,
        key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TLWE::<N>::ALPHA);

        let a: [Torus; N] = unif.gen_n();
        let m = rep;
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

    fn do_decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
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
    fn decode(&self, rep: Self::Representation) -> Binary {
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
    use super::super::utils::*;

    #[test]
    fn tlwe_test() {
        let mut b_uniform = math::BinaryDistribution::uniform();
        let tlwe = TLWE::new();

        let mut test = |item: Binary| {
            let s_key: [Binary; TLWE::<0>::N] = b_uniform.gen_n();
            let Encrypted(cipher, p_key) = tlwe.encrypto(&s_key, item);
            let res = tlwe.decrypto(&s_key, &p_key, cipher);

            assert!(res == item, "cipher={:?}\np_key={:?}", cipher, p_key);
        };

        for i in 0..100 {
            test(Binary::from(i % 2))
        }
    }
}