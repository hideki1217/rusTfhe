use super::digest::{Crypto, Encryptable, Encrypted};
use crate::tlwe::TLWERep;
use num::Zero;
use std::ops::{Add, Sub};
use utils::{
    math::{Binary, ModDistribution, Polynomial, Random, Torus32},
    mem, pol, torus,
};

pub struct TRLWE<const N: usize>;
macro_rules! trlwe_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TRLWE<N>> for $t {}
    };
}
trlwe_encryptable!(Polynomial<Torus32, N>);
trlwe_encryptable!(Polynomial<Binary, N>);

#[derive(Debug, Clone)]
pub struct TRLWERep<const N: usize> {
    cipher: Polynomial<Torus32, N>,
    p_key: Polynomial<Torus32, N>,
}
impl<const N: usize> Encrypted<Polynomial<Torus32, N>, Polynomial<Torus32, N>> for TRLWERep<N> {
    fn cipher(&self) -> &Polynomial<Torus32, N> {
        &self.cipher
    }
    fn p_key(&self) -> &Polynomial<Torus32, N> {
        &self.p_key
    }
    fn get_and_drop(self) -> (Polynomial<Torus32, N>, Polynomial<Torus32, N>) {
        (self.cipher, self.p_key)
    }
    fn get_mut_ref(&mut self) -> (&mut Polynomial<Torus32, N>, &mut Polynomial<Torus32, N>){
        (&mut self.cipher,&mut self.p_key)
    }
}
impl<const N: usize> TRLWERep<N> {
    pub fn new(cipher: Polynomial<Torus32, N>, p_key: Polynomial<Torus32, N>) -> Self {
        TRLWERep { cipher, p_key }
    }
    pub fn map<F: Fn(&Polynomial<Torus32, N>) -> Polynomial<Torus32, N>>(&self, f: F) -> Self {
        TRLWERep::new(f(self.cipher()), f(self.p_key()))
    }
    pub fn trivial_one(text: Polynomial<Torus32, N>) -> Self {
        TRLWERep::new(text, pol!([Torus32::zero(); N]))
    }
}
impl<const N: usize> Add for TRLWERep<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}
impl<const N: usize> Add<&TRLWERep<N>> for TRLWERep<N> {
    type Output = Self;
    fn add(self, rhs: &TRLWERep<N>) -> Self::Output {
        TRLWERep::new(self.cipher + rhs.cipher(), self.p_key + rhs.p_key())
    }
}
impl<const N: usize> Sub for TRLWERep<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}
impl<const N: usize> Sub<&TRLWERep<N>> for TRLWERep<N> {
    type Output = Self;
    fn sub(self, rhs: &TRLWERep<N>) -> Self::Output {
        TRLWERep::new(self.cipher - rhs.cipher(), self.p_key - rhs.p_key())
    }
}

pub struct TRLWEHelper;
impl TRLWEHelper {
    pub const N: usize = 2_usize.pow(10);
    pub const ALPHA: f32 = 1.0 / (2_u32.pow(25) as f32); // 2^{-25}
    pub fn binary_pol2torus_pol<const M: usize>(
        pol: Polynomial<Binary, M>,
    ) -> Polynomial<Torus32, M> {
        let l = mem::array_create_enumerate(|i| {
            torus!(match pol.coef_(i) {
                Binary::One => 1.0 / 8.0,
                Binary::Zero => -1.0 / 8.0,
            })
        });
        pol!(l)
    }
    pub fn torus_pol2binary_pol<const M: usize>(
        pol: Polynomial<Torus32, M>,
    ) -> Polynomial<Binary, M> {
        let l = mem::array_create_enumerate(|i| {
            let f: f32 = pol.coef_(i).into();
            if f < 0.5 {
                Binary::One
            } else {
                Binary::Zero
            }
        });
        pol!(l)
    }
}
impl<const N: usize> TRLWE<N> {}

impl<const N: usize> TRLWERep<N> {
    /**
    TRLWEのX^indexの部分だけ見ると、TLWEになっている。
    そこを取り出す。
    */
    pub fn sample_extract_index(&self, index: usize) -> TLWERep<N> {
        let (cipher, p_key) = self.get_ref();
        let a_ = mem::array_create_enumerate(|i| {
            if i <= index {
                p_key.coef_(index - i)
            } else {
                -p_key.coef_(N + index - i)
            }
        });
        let b_ = cipher.coef_(index);
        TLWERep::new(b_, a_)
    }
}
impl<const N: usize> Crypto<Polynomial<Torus32, N>> for TRLWE<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRLWERep<N>;

    fn encrypto(&self, key: &Self::SecretKey, rep: Polynomial<Torus32, N>) -> Self::Representation {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TRLWEHelper::ALPHA);

        let a = pol!(unif.gen_n::<N>());
        let e = pol!(norm.gen_n::<N>());

        let b = a.fft_cross(key) + rep + e;

        TRLWERep::new(b, a)
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Polynomial<Torus32, N> {
        let (cipher, p_key) = rep.get_and_drop();
        let m_with_e = cipher - p_key.fft_cross(&s_key);
        m_with_e
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRLWE<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRLWERep<N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> Self::Representation {
        self.encrypto(s_key, TRLWEHelper::binary_pol2torus_pol(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Polynomial<Binary, N> {
        TRLWEHelper::torus_pol2binary_pol(self.decrypto(s_key, rep))
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::Cryptor;
    use crate::tlwe::TLWE;

    use super::*;
    use utils::math::*;

    #[test]
    fn trlwe_sample_extract_index() {
        const N: usize = TRLWEHelper::N;

        let mut b_unif = BinaryDistribution::uniform();

        let mut test = |item: Polynomial<Binary, N>| {
            let s_key = pol!(b_unif.gen_n::<N>());
            let rep = Cryptor::encrypto(TRLWE, &s_key, item.clone());

            let res_trlwe: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, rep.clone());
            assert_eq!(res_trlwe, item, "Trlwe is Wrong,");
            for i in 0..N {
                let encrypted = rep.sample_extract_index(i);
                let res_tlwe: Binary = Cryptor::decrypto(TLWE::<N>, s_key.coefs(), encrypted);

                assert_eq!(
                    res_tlwe,
                    res_trlwe.coef_(i),
                    "Wrong culc. trlwe'res[{}] != tlwe's_sample_res",
                    i
                );
            }
        };

        let mut b_unif = BinaryDistribution::uniform();
        test(pol!(b_unif.gen_n::<N>()))
    }

    #[test]
    fn trlwe_test() {
        const N: usize = TRLWEHelper::N;
        let mut b_unif = BinaryDistribution::uniform();

        let mut test = |item: Polynomial<Binary, N>| {
            let s_key = pol!(b_unif.gen_n::<N>());
            let rep = Cryptor::encrypto(TRLWE, &s_key, item.clone());
            let res: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, rep);

            assert!(res == item, "trlwe failed");
        };

        let mut b_unif = BinaryDistribution::uniform();
        for _ in 0..20 {
            test(pol!(b_unif.gen_n::<N>()))
        }

        let s_key = pol!(b_unif.gen_n::<N>());
        let pol = pol!([torus!(0.5); N]);
        let rep = TRLWERep::trivial_one(pol);
        let res: Polynomial<Torus32, N> = Cryptor::decrypto(TRLWE, &s_key, rep);
        assert_eq!(res, pol, "trivialな暗号文を複号してみた");
    }
}
