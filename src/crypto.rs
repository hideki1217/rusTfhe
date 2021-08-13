use std::ops::{Add, Neg};

use self::math::{Binary, Cross, ModDistribution, Polynomial, Random, Torus};
use array_macro::array;
use num::{ToPrimitive, Zero};

mod math;

pub struct Encrypted<Cipher, PublicKey>(Cipher, PublicKey);
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
    type Representation;
    type SecretKey;
    type Cipher;
    type PublicKey;
    fn encode(&self, item: Item) -> Self::Representation;
    fn do_encrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Encrypted<Self::Cipher, Self::PublicKey>;
    fn do_decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Self::Representation;
    fn decode(&self, rep: Self::Representation) -> Item;

    fn encrypto(
        &self,
        key: &Self::SecretKey,
        item: Item,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        self.do_encrypto(key, self.encode(item))
    }
    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Item {
        self.decode(self.do_decrypto(s_key, p_key, cipher))
    }
}

struct TLWE<const N: usize>;
impl<const N: usize> TLWE<N> {
    const N: usize = 635;
    const ALPHA: f32 = 1e-15;
    fn new() -> Self {
        TLWE
    }
}
impl<const N: usize> Default for TLWE<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Crypto<math::Binary> for TLWE<N> {
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
        let mut unif = math::ModDistribution::uniform();
        let mut norm = math::ModDistribution::gaussian(TLWE::<N>::ALPHA);

        let a: [math::Torus; N] = unif.gen_n();
        let m = rep;
        let e = norm.gen();
        let b = a
            .iter()
            .zip(key.iter())
            .map(|(&a, &b)| a * b.to::<u32>())
            .fold(math::Torus::zero(), |s, x| s + x)
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
    fn decode(&self, rep: Self::Representation) -> math::Binary {
        let f = rep.to_f32().unwrap();
        if f < 0.5 {
            Binary::One
        } else {
            Binary::Zero
        }
    }
}

pub struct TRLWE();
impl TRLWE {
    #[allow(dead_code)]
    const N: usize = 1024;
    const ALPHA: f32 = 0.000000119;
    pub fn new() -> Self {
        TRLWE()
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
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRLWE {
    type Representation = Polynomial<Torus, N>;
    type SecretKey = Polynomial<Binary, N>;
    type Cipher = Polynomial<Torus, N>;
    type PublicKey = Polynomial<Torus, N>;

    fn encode(&self, item: Polynomial<Binary, N>) -> Self::Representation {
        let l: [Torus; N] = array![i => {
            Torus::from_f32(match item.coef_(i) {
                Binary::One => 1.0 / 8.0,
                Binary::Zero => -1.0 / 8.0,
            })
        };N];
        Polynomial::new(l)
    }

    fn do_encrypto(
        &self,
        key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Encrypted<Self::Cipher, Self::PublicKey> {
        let mut unif = ModDistribution::uniform();
        let mut norm = ModDistribution::gaussian(TRLWE::ALPHA);

        let a = Polynomial::new(unif.gen_n::<N>());
        let e = Polynomial::new(norm.gen_n::<N>());

        let b = a.cross(&key) + rep + e;

        Encrypted(b, a)
    }

    fn do_decrypto(
        &self,
        s_key: &Self::SecretKey,
        p_key: &Self::PublicKey,
        cipher: Self::Cipher,
    ) -> Self::Representation {
        let m_with_e = cipher - p_key.cross(&s_key);
        m_with_e
    }

    fn decode(&self, rep: Self::Representation) -> Polynomial<Binary, N> {
        let l: [Binary; N] = array![ i => {
            let f = rep.coef_(i).to_f32().unwrap();
            if f < 0.5 {
                Binary::One
            } else {
                Binary::Zero
            }
        };N];
        Polynomial::new(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trlwe_sample_extract_index() {
        let mut b_unif = math::BinaryDistribution::uniform();
        let trlwe = TRLWE::new();
        let tlwe: TLWE<{ TRLWE::N }> = TLWE::new();

        let mut test = |item: Polynomial<Binary, { TRLWE::N }>| {
            let s_key = Polynomial::new(b_unif.gen_n::<{ TRLWE::N }>());
            let encrypted = trlwe.encrypto(&s_key, item.clone());

            let Encrypted(cipher, p_key) = &encrypted;
            let res_trlwe = trlwe.decrypto(&s_key, &p_key, cipher.clone());
            assert_eq!(res_trlwe, item, "Trlwe is Wrong,");
            for i in 0..TRLWE::N {
                let Encrypted(cipher, p_key) = encrypted.sample_extract_index(i);
                let res_tlwe = tlwe.decrypto(&s_key.coefficient(), &p_key, cipher);

                assert_eq!(
                    res_tlwe,
                    res_trlwe.coef_(i),
                    "Wrong culc. trlwe'res[{}] != tlwe's_sample_res",
                    i
                );
            }
        };

        let mut b_unif = math::BinaryDistribution::uniform();
        test(Polynomial::new(b_unif.gen_n::<{ TRLWE::N }>()))
    }

    #[test]
    fn trlwe_test() {
        let mut b_unif = math::BinaryDistribution::uniform();
        let trlwe = TRLWE::new();

        let mut test = |item: Polynomial<Binary, { TRLWE::N }>| {
            let s_key = Polynomial::new(b_unif.gen_n::<{ TRLWE::N }>());
            let Encrypted(cipher, p_key) = trlwe.encrypto(&s_key, item.clone());
            let res = trlwe.decrypto(&s_key, &p_key, cipher.clone());

            assert!(res == item, "cipher={:?}\np_key={:?}", cipher, p_key);
        };

        let mut b_unif = math::BinaryDistribution::uniform();
        for _ in 0..10 {
            test(Polynomial::new(b_unif.gen_n::<{ TRLWE::N }>()))
        }
    }

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
