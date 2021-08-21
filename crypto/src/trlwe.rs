use std::ops::{Add, Sub};

use array_macro::array;
use num::{ToPrimitive,Zero};

use crate::tlwe::TLWERep;

use super::digest::{Crypto, Encryptable, Encrypted};
use utils::math::{Binary, Cross, ModDistribution, Polynomial, Random, Torus};
use utils::{pol, torus};

pub struct TRLWE<const N: usize>;
macro_rules! trlwe_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TRLWE<N>> for $t {}
    };
}
trlwe_encryptable!(Polynomial<Torus, N>);
trlwe_encryptable!(Polynomial<Binary, N>);

#[derive(Debug, Clone, Copy)]
pub struct TRLWERep<const N: usize> {
    cipher: Polynomial<Torus, N>,
    p_key: Polynomial<Torus, N>,
}
impl<const N: usize> Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>> for TRLWERep<N> {
    fn cipher(&self) -> &Polynomial<Torus, N> {
        &self.cipher
    }
    fn p_key(&self) -> &Polynomial<Torus, N> {
        &self.p_key
    }
    fn get_and_drop(self) -> (Polynomial<Torus, N>, Polynomial<Torus, N>) {
        (self.cipher, self.p_key)
    }
}
impl<const N: usize> TRLWERep<N> {
    pub fn new(cipher: Polynomial<Torus, N>, p_key: Polynomial<Torus, N>) -> Self {
        TRLWERep { cipher, p_key }
    }
    pub fn map<F:Fn(&Polynomial<Torus, N>) -> Polynomial<Torus, N>>(&self,f:F) -> Self{
        TRLWERep::new(f(self.cipher()),f(self.p_key()))
    }
    pub fn trivial_one(text: Polynomial<Torus,N>)->Self {
        TRLWERep::new(text,pol!([Torus::zero();N]))
    }
}
impl<const N: usize> Add for TRLWERep<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        TRLWERep::new(self.cipher + rhs.cipher, self.p_key + rhs.p_key)
    }
}
impl<const N: usize> Sub for TRLWERep<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        TRLWERep::new(self.cipher - rhs.cipher, self.p_key - rhs.p_key)
    }
}

pub struct TRLWEHelper;
impl TRLWEHelper {
    pub const N: usize = 1024;
    pub const ALPHA: f32 = 1.0 / (2_u32.pow(23) as f32); // 2^{-25}
    pub fn binary_pol2torus_pol<const M: usize>(
        pol: Polynomial<Binary, M>,
    ) -> Polynomial<Torus, M> {
        let l = array![i => {
            torus!(match pol.coef_(i) {
                Binary::One => 1.0 / 8.0,
                Binary::Zero => -1.0 / 8.0,
            })
        };M];
        pol!(l)
    }
    pub fn torus_pol2binary_pol<const M: usize>(
        pol: Polynomial<Torus, M>,
    ) -> Polynomial<Binary, M> {
        let l = array![ i => {
            let f = pol.coef_(i).to_f32().unwrap();
            if f < 0.5 {
                Binary::One
            } else {
                Binary::Zero
            }
        };M];
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
        let (cipher, p_key) = self.get_and_drop();
        let a_ = array![ i => {
            if i <= index {
                p_key.coef_(index-i)
            }
            else {
                -p_key.coef_(N+index -i)
            }
        };N];
        let b_ = cipher.coef_(index);
        TLWERep::new(b_, a_)
    }
}
impl<const N: usize> Crypto<Polynomial<Torus, N>> for TRLWE<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRLWERep<N>;

    fn encrypto(&self, key: &Self::SecretKey, rep: Polynomial<Torus, N>) -> Self::Representation {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TRLWEHelper::ALPHA);

        let a = pol!(unif.gen_n::<N>());
        let e = pol!(norm.gen_n::<N>());

        let b = a.cross(&key) + rep + e;

        TRLWERep::new(b, a)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Polynomial<Torus, N> {
        let (cipher, p_key) = rep.get_and_drop();
        let m_with_e = cipher - p_key.cross(&s_key);
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

            let res_trlwe: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, rep);
            assert_eq!(res_trlwe, item, "Trlwe is Wrong,");
            for i in 0..N {
                let encrypted = rep.sample_extract_index(i);
                let res_tlwe: Binary = Cryptor::decrypto(TLWE::<N>, s_key.coefficient(), encrypted);

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
        let pol = pol!([torus!(0.5);N]);
        let rep = TRLWERep::trivial_one(pol);
        let res: Polynomial<Torus,N> = Cryptor::decrypto(TRLWE, &s_key, rep);
        assert_eq!(res,pol,"trivialな暗号文を複号してみた");
    }
}
