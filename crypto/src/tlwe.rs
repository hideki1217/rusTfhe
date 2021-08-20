use super::digest::{Crypto, Encryptable, Encrypted};
use crate::digest::Cryptor;
use itertools::iproduct;
use num::{ToPrimitive, Zero};
use std::mem::MaybeUninit;
use std::ops::{Add, Mul, Sub};
use utils::math::{Binary, ModDistribution, Random, Torus};
use utils::torus;

pub struct TLWE<const N: usize>;
macro_rules! tlwe_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TLWE<N>> for $t {}
    };
}
tlwe_encryptable!(Binary);
tlwe_encryptable!(Torus);

pub struct TLWERep<const N: usize> {
    cipher: Torus,
    p_key: [Torus; N],
}
impl<const N: usize> Encrypted<Torus, [Torus; N]> for TLWERep<N> {
    fn cipher(&self) -> &Torus {
        &self.cipher
    }
    fn p_key(&self) -> &[Torus; N] {
        &self.p_key
    }
    fn get_and_drop(self) -> (Torus, [Torus; N]) {
        (self.cipher, self.p_key)
    }
}
impl<const N: usize> TLWERep<N> {
    pub fn new(cipher: Torus, p_key: [Torus; N]) -> Self {
        TLWERep { cipher, p_key }
    }

    const IKS_L: usize = 8;
    const IKS_BASEBIT: u32 = 2;
    const IKS_T: usize = 2_usize.pow(Self::IKS_BASEBIT);
    pub fn identity_key_switch<const M: usize>(
        self,
        ks: &[[[TLWERep<M>; Self::IKS_T]; Self::IKS_L]; N],
    ) -> TLWERep<M> {
        const BITS: u32 = u32::BITS;
        const BASEBIT: u32 = TLWERep::<0>::IKS_BASEBIT;
        const IKS_T: u32 = TLWERep::<0>::IKS_T as u32;
        const IKS_L: usize = TLWERep::<0>::IKS_L;
        const ROUND: u32 = 1 << (BITS - (1 + BASEBIT * IKS_T));

        let (b_, a_) = self.get_and_drop();
        let tlwe_init = TLWERep::new(b_, [Torus::zero(); M]);
        let tlwe = a_.iter().enumerate().fold(tlwe_init, |tlwe, (i, a_i)| {
            let a_i = a_i.inner() + ROUND;
            (0..IKS_L).fold(tlwe, |tlwe_, j| {
                // a_i.decomposition(BASEBIT)[j]
                let a_i_j = (a_i >> (BITS - (j as u32 + 1) * BASEBIT)) & (IKS_T as u32 - 1);
                tlwe_
                    - unsafe {
                        ks.get_unchecked(i)
                            .get_unchecked(j)
                            .get_unchecked(a_i_j as usize)
                    }
            })
        });
        tlwe
    }

    pub fn into_key_switching_key<const M: usize>(
        pre_s_key: [Binary; N],
        next_s_key: [Binary; M],
    ) -> [[[TLWERep<M>; Self::IKS_T]; Self::IKS_L]; N] {
        const BASEBIT: i32 = TLWERep::<0>::IKS_BASEBIT as i32;
        const T: usize = TLWERep::<0>::IKS_T;
        const L: usize = TLWERep::<0>::IKS_L;

        let culc_tlwe = |s_i: Binary, l: i32, t: u32| {
            // t*s_i/2^{basebit * l}
            let item = torus!(s_i.to::<f32>() * 0.5_f32.powi(BASEBIT * l) * t as f32);
            let tlwe = Cryptor::encrypto(TLWE, &next_s_key, item);
            tlwe
        };
        let mut arr: [[[MaybeUninit<TLWERep<M>>; T]; L]; N] =
            unsafe { MaybeUninit::uninit().assume_init() };
        // TODO: マルチスレッドで計算できる
        for (&s_i, arr_i) in pre_s_key.iter().zip(arr.iter_mut()) {
            for (l, arr_i_l) in arr_i.iter_mut().enumerate() {
                for (t, arr_i_l_t) in arr_i_l.iter_mut().enumerate() {
                    *arr_i_l_t = MaybeUninit::new(culc_tlwe(
                        s_i,
                        l as i32,
                        1 + t as u32, /* t=0のときはarr_i_l_0 = 0なので計算しない */
                    ));
                }
            }
        }
        utils::mem::transmute::<_, [[[TLWERep<M>; T]; L]; N]>(arr)
    }
}
impl<const N: usize> Add for TLWERep<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let (b, a) = self.get_and_drop();
        let (b_, a_) = rhs.get_and_drop();
        let mut a_res = a;
        a_res
            .iter_mut()
            .zip(a_.iter())
            .for_each(|(x, &y)| *x = *x + y);
        TLWERep::new(b + b_, a_res)
    }
}
impl<const N: usize> Add<&Self> for TLWERep<N> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        let (b, a) = self.get_and_drop();
        let (b_, a_) = rhs.get_ref();
        let mut a_res = a;
        a_res
            .iter_mut()
            .zip(a_.iter())
            .for_each(|(x, &y)| *x = *x + y);
        TLWERep::new(b + *b_, a_res)
    }
}
impl<const N: usize> Sub for TLWERep<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let (b, a) = self.get_and_drop();
        let (b_, a_) = rhs.get_and_drop();
        let mut a_res = a;
        a_res
            .iter_mut()
            .zip(a_.iter())
            .for_each(|(x, &y)| *x = *x - y);
        TLWERep::new(b + b_, a_res)
    }
}
impl<const N: usize> Sub<&Self> for TLWERep<N> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        let (b, a) = self.get_and_drop();
        let (b_, a_) = rhs.get_ref();
        let mut a_res = a;
        a_res
            .iter_mut()
            .zip(a_.iter())
            .for_each(|(x, &y)| *x = *x - y);
        TLWERep::new(b + *b_, a_res)
    }
}
impl<const N: usize, Int: Copy> Mul<Int> for TLWERep<N>
where
    Torus: Mul<Int, Output = Torus>,
{
    type Output = Self;
    fn mul(self, rhs: Int) -> Self::Output {
        let (b, mut a) = self.get_and_drop();
        a.iter_mut().for_each(|a_| *a_ = *a_ * rhs);
        TLWERep::new(b * rhs, a)
    }
}

pub struct TLWEHelper;
impl TLWEHelper {
    pub const N: usize = 635;
    pub const ALPHA: f32 = 1.0 / (2_u32.pow(15) as f32); // 2^{-15}
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
