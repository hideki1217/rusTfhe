use array_macro::array;
use num::ToPrimitive;
use std::ops::Neg;

use super::digest::{Crypto, Encrypted};
use math_utils::{Binary, Cross, ModDistribution, Polynomial, Random, Torus};

use math_utils::{torus,pol};
pub struct TRLWE();
impl TRLWE {
    #[allow(dead_code)]
    const N: usize = 1024;
    const ALPHA: f32 = 0.000000119; // 2^{-23}
    pub fn new() -> Self {
        TRLWE()
    }
    pub fn binary_pol2torus_pol<const N: usize>(pol: Polynomial<Binary, N>) -> Polynomial<Torus, N> {
        let l: [Torus; N] = array![i => {
            torus!(match pol.coef_(i) {
                Binary::One => 1.0 / 8.0,
                Binary::Zero => -1.0 / 8.0,
            })
        };N];
        pol!(l)
    }
    pub fn torus_pol2binary_pol<const N: usize>(pol: Polynomial<Torus, N>) -> Polynomial<Binary, N> {
        let l: [Binary; N] = array![ i => {
            let f = pol.coef_(i).to_f32().unwrap();
            if f < 0.5 {
                Binary::One
            } else {
                Binary::Zero
            }
        };N];
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
impl Default for TRLWE {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Crypto<Polynomial<Torus, N>> for TRLWE {
    type SecretKey = Polynomial<Binary, N>;
    type Cipher = Polynomial<Torus, N>;
    type PublicKey = Polynomial<Torus, N>;

    fn encrypto(
        &self,
        key: &Self::SecretKey,
        rep: Polynomial<Torus, N>,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TRLWE::ALPHA);

        let a = pol!(unif.gen_n::<N>());
        let e = pol!(norm.gen_n::<N>());

        let b = a.cross(&key) + rep + e;

        Encrypted(b, a)
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Polynomial<Torus, N> {
        let m_with_e = cipher - p_key.cross(&s_key);
        m_with_e
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRLWE {
    type SecretKey = Polynomial<Binary, N>;
    type Cipher = Polynomial<Torus, N>;
    type PublicKey = Polynomial<Torus, N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        self.encrypto(s_key, TRLWE::binary_pol2torus_pol(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Polynomial<Binary, N> {
        TRLWE::torus_pol2binary_pol(self.decrypto(s_key, p_key, cipher))
    }
}

#[cfg(test)]
mod tests {
    use math_utils::*;
    use super::super::*;
    use super::*;

    #[test]
    fn trlwe_sample_extract_index() {
        let mut b_unif = BinaryDistribution::uniform();
        let trlwe = TRLWE::new();
        let tlwe: tlwe::TLWE<{ TRLWE::N }> = tlwe::TLWE::new();

        let mut test = |item: Polynomial<Binary, { TRLWE::N }>| {
            let s_key = pol!(b_unif.gen_n::<{ TRLWE::N }>());
            let encrypted = trlwe.encrypto(&s_key, item.clone());

            let Encrypted(cipher, p_key) = &encrypted;
            let res_trlwe:Polynomial<Binary,{ TRLWE::N }> = trlwe.decrypto(&s_key, p_key, cipher.clone());
            assert_eq!(res_trlwe, item, "Trlwe is Wrong,");
            for i in 0..TRLWE::N {
                let Encrypted(cipher, p_key) = encrypted.sample_extract_index(i);
                let res_tlwe: Binary = tlwe.decrypto(s_key.coefficient(), &p_key, cipher);

                assert_eq!(
                    res_tlwe,
                    res_trlwe.coef_(i),
                    "Wrong culc. trlwe'res[{}] != tlwe's_sample_res",
                    i
                );
            }
        };

        let mut b_unif = BinaryDistribution::uniform();
        test(pol!(b_unif.gen_n::<{ TRLWE::N }>()))
    }

    #[test]
    fn trlwe_test() {
        let mut b_unif = BinaryDistribution::uniform();
        let trlwe = TRLWE::new();

        let mut test = |item: Polynomial<Binary, { TRLWE::N }>| {
            let s_key = pol!(b_unif.gen_n::<{ TRLWE::N }>());
            let Encrypted(cipher, p_key) = trlwe.encrypto(&s_key, item.clone());
            let res: Polynomial<Binary,{ TRLWE::N }> = trlwe.decrypto(&s_key, &p_key, cipher.clone());

            assert!(res == item, "cipher={:?}\np_key={:?}", cipher, p_key);
        };

        let mut b_unif = BinaryDistribution::uniform();
        for _ in 0..10 {
            test(pol!(b_unif.gen_n::<{ TRLWE::N }>()))
        }
    }
}
