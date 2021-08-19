use num::{ToPrimitive, Zero};

use super::digest::{Crypto, Encryptable, Encrypted};
use utils::math::{Binary, ModDistribution, Random, Torus};
use utils::{torus};

pub struct TLWE<const N: usize>;
macro_rules! tlwe_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TLWE<N>> for $t {}
    };
}
tlwe_encryptable!(Binary);
tlwe_encryptable!(Torus);

pub struct TLWERep<const N:usize>{
    cipher:Torus,
    p_key:[Torus; N],
}
impl<const N:usize> Encrypted<Torus,[Torus;N]> for TLWERep<N> {
    fn cipher(&self) -> &Torus {
        &self.cipher
    }
    fn p_key(&self) -> &[Torus;N] {
        &self.p_key
    }
    fn get_and_drop(self) -> (Torus, [Torus;N]) {
        (self.cipher,self.p_key)
    }
}
impl<const N:usize> TLWERep<N> {
    pub fn new(cipher:Torus,p_key:[Torus;N]) -> Self{
        TLWERep{cipher,p_key}
    }
}

pub struct TLWEHelper;
impl TLWEHelper {
    const N: usize = 635;
    const ALPHA: f32 = 1.0 / (2_u32.pow(15) as f32); // 2^{-15}
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
impl<const N: usize> TLWE<N> {}
impl<const N: usize> Crypto<Binary> for TLWE<N> {
    type SecretKey = [Binary; N];
    type Representation = TLWERep<N>;

    fn encrypto(&self, key: &Self::SecretKey, item: Binary) -> Self::Representation {
        self.encrypto(key, TLWEHelper::binary2torus(item))
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Binary {
        TLWEHelper::torus2binary(self.decrypto(s_key, rep))
    }
}
impl<const N: usize> Crypto<Torus> for TLWE<N> {
    type SecretKey = [Binary; N];
    type Representation = TLWERep<N>;

    fn encrypto(&self, key: &Self::SecretKey, item: Torus) -> Self::Representation {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TLWEHelper::ALPHA);

        let a: [Torus; N] = unif.gen_n();
        let m = item;
        let e = norm.gen();
        let b = a
            .iter()
            .zip(key.iter())
            .map(|(&a, &b)| a * b)
            .fold(Torus::zero(), |s, x| s + x)
            + e
            + m;
        TLWERep::new(b, a)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Torus {
        let (cipher, p_key) = rep.get_and_drop();
        let a_cross_s = p_key
            .iter()
            .zip(s_key.iter())
            .map(|(&a, &b)| a * b)
            .fold(Torus::zero(), |s, x| s + x);
        let m_with_e = cipher - a_cross_s;

        m_with_e
    }
}


#[cfg(test)]
mod tests {
    use crate::digest::Cryptor;

    use super::*;
    use utils::math::*;

    #[test]
    fn tlwe_test() {
        const N: usize = TLWEHelper::N;
        let mut b_uniform = BinaryDistribution::uniform();

        let mut test = |item: Binary| {
            let s_key: [Binary; N] = b_uniform.gen_n();
            let rep = Cryptor::encrypto(TLWE::<N>, &s_key, item);
            let res: Binary = Cryptor::decrypto(TLWE::<N>, &s_key, rep);

            assert!(res == item, "tlwe failed");
        };

        for i in 0..100 {
            test(Binary::from(i % 2))
        }
    }
}
