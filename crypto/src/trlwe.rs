use array_macro::array;
use num::ToPrimitive;
use std::ops::Neg;

use crate::digest::CryptoCore;

use super::digest::{Crypto, Encrypted};
use math_utils::{Binary, Cross, ModDistribution, Polynomial, Random, Torus};

use math_utils::{pol, torus};
pub struct TRLWE<const N: usize>();
impl<const N: usize> CryptoCore for TRLWE<N> {
    type Representation = Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>;
}
impl<const N: usize> TRLWE<N> {
    #[allow(dead_code)]
    pub const N: usize = 1024;
    const ALPHA: f32 = 0.000000119; // 2^{-23}
    pub fn new() -> Self {
        TRLWE()
    }
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
impl<CipherT: Copy, PublicKeyT: Copy + Neg<Output = PublicKeyT>, const N: usize>
    Encrypted<Polynomial<CipherT, N>, Polynomial<PublicKeyT, N>>
{
    /**
    TRLWEのX^indexの部分だけ見ると、TLWEになっている。
    そこを取り出す。
    */
    pub fn sample_extract_index(&self, index: usize) -> Encrypted<CipherT, [PublicKeyT; N]> {
        let Encrypted(cipher, p_key) = self;
        let a_: [PublicKeyT; N] = array![ i => {
            if i <= index {
                p_key.coef_(index-i)
            }
            else {
                -p_key.coef_(N+index -i)
            }
        };N];
        let b_ = cipher.coef_(index);
        Encrypted(b_, a_)
    }
}
impl<const N: usize> Crypto<Polynomial<Torus, N>> for TRLWE<N> {
    type SecretKey = Polynomial<Binary, N>;

    fn encrypto(
        &self,
        key: &Self::SecretKey,
        rep: Polynomial<Torus, N>,
    ) -> <Self as CryptoCore>::Representation {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TRLWE::<0>::ALPHA);

        let a = pol!(unif.gen_n::<N>());
        let e = pol!(norm.gen_n::<N>());

        let b = a.cross(&key) + rep + e;

        Encrypted(b, a)
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: <Self as CryptoCore>::Representation,
    ) -> Polynomial<Torus, N> {
        let (cipher, p_key) = rep.get_and_drop();
        let m_with_e = cipher - p_key.cross(&s_key);
        m_with_e
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRLWE<N> {
    type SecretKey = Polynomial<Binary, N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> <Self as CryptoCore>::Representation {
        self.encrypto(s_key, TRLWE::<0>::binary_pol2torus_pol(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: <Self as CryptoCore>::Representation,
    ) -> Polynomial<Binary, N> {
        TRLWE::<0>::torus_pol2binary_pol(self.decrypto(s_key, rep))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use math_utils::*;

    #[test]
    fn trlwe_sample_extract_index() {
        const N: usize = TRLWE::<0>::N;

        let mut b_unif = BinaryDistribution::uniform();
        let trlwe = TRLWE::new();
        let tlwe: tlwe::TLWE<N> = tlwe::TLWE::new();

        let mut test = |item: Polynomial<Binary, N>| {
            let s_key = pol!(b_unif.gen_n::<N>());
            let rep = trlwe.encrypto(&s_key, item.clone());

            let res_trlwe: Polynomial<Binary, N> = trlwe.decrypto(&s_key, rep.clone());
            assert_eq!(res_trlwe, item, "Trlwe is Wrong,");
            for i in 0..N {
                let encrypted = rep.sample_extract_index(i);
                let res_tlwe: Binary = tlwe.decrypto(s_key.coefficient(), encrypted);

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
        const N: usize = TRLWE::<0>::N;
        let mut b_unif = BinaryDistribution::uniform();
        let trlwe = TRLWE::new();

        let mut test = |item: Polynomial<Binary, N>| {
            let s_key = pol!(b_unif.gen_n::<N>());
            let rep = trlwe.encrypto(&s_key, item.clone());
            let res: Polynomial<Binary, N> = trlwe.decrypto(&s_key, rep);

            assert!(res == item, "trlwe failed");
        };

        let mut b_unif = BinaryDistribution::uniform();
        for _ in 0..10 {
            test(pol!(b_unif.gen_n::<N>()))
        }
    }
}
