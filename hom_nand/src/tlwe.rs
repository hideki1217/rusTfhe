use super::digest::{Crypto, Encryptable, Encrypted, Cryptor};
use num::Zero;
use std::ops::{Add, Mul, Neg, Sub};
use utils::{math::{Binary, ModDistribution, Random, Torus}, torus, traits::AsLogic};

pub struct TLWE<const N: usize>;
macro_rules! tlwe_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TLWE<N>> for $t {}
    };
}
tlwe_encryptable!(Binary);
tlwe_encryptable!(Torus);

#[derive(Clone)]
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

    pub fn identity_key_switch<const M: usize>(self, ks: &KeySwitchingKey<N, M>) -> TLWERep<M> {
        const BASEBIT: u32 = TLWEHelper::IKS_BASEBIT;
        const IKS_L: usize = TLWEHelper::IKS_L;

        let (b_, a_) = self.get_and_drop();
        let tlwe_init = TLWERep::new(b_, [Torus::zero(); M]);
        let tlwe = a_.iter().enumerate().fold(tlwe_init, |tlwe, (i, &a_i)| {
            let a_i_decomp = a_i.decomposition_u32::<IKS_L>(BASEBIT);
            (0..IKS_L)
                .zip(a_i_decomp)
                .fold(tlwe, |tlwe_, (l, a_i_decomp_l)| {
                    if a_i_decomp_l != 0 {
                        tlwe_ - ks.get(i, l, a_i_decomp_l as usize)/*TODO: unsafe { ks.get_unchecked(i, l, a_i_decomp_l as usize) }*/
                    }
                    else {
                        tlwe_
                    }
                })
        });
        tlwe
    }

    #[inline]
    pub fn trivial(text: Torus) -> Self {
        TLWERep::new(text, [Torus::zero(); N])
    }
}
impl<const N: usize> AsLogic for TLWERep<N>{
    fn logic_true() -> Self {
        Self::trivial(TLWEHelper::binary2torus(Binary::One))
    }
    fn logic_false() -> Self {
        Self::trivial(TLWEHelper::binary2torus(Binary::Zero))
    }
}
impl<const N: usize> Add for TLWERep<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
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
        self - &rhs
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
        TLWERep::new(b - *b_, a_res)
    }
}
impl<const N:usize> Neg for TLWERep<N>{
    type Output=Self;
    fn neg(self) -> Self::Output {
        let (mut b,mut a) = self.get_and_drop();
        b = -b;
        a.iter_mut().for_each(|x|*x = -*x);
        TLWERep::new(b,a)
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
impl<const N: usize> Zero for TLWERep<N> {
    fn zero() -> Self {
        TLWERep::new(Torus::zero(), [Torus::zero(); N])
    }
    fn is_zero(&self) -> bool {
        let TLWERep {
            cipher: b,
            p_key: a,
        } = self;
        b.is_zero() & a.iter().all(|x| x.is_zero())
    }
}

pub struct TLWEHelper;
impl TLWEHelper {
    pub const N: usize = 635;
    pub const ALPHA: f32 = 1.0 / (2_u32.pow(15) as f32); // 2^{-15}

    pub const IKS_L: usize = 8;
    pub const IKS_BASEBIT: u32 = 2;
    pub const IKS_T: usize = 2_usize.pow(Self::IKS_BASEBIT);
    pub fn binary2torus(bin: Binary) -> Torus {
        torus!(match bin {
            Binary::One => 1.0 / 8.0,
            Binary::Zero => -1.0 / 8.0,
        })
    }
    pub fn torus2binary(torus: Torus) -> Binary {
        let f:f32 = torus.into();
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
            .filter(|(_, &b)| b == Binary::One)
            .fold(Torus::zero(), |s, (&x, _)| s + x)
            + e
            + m;
        TLWERep::new(b, a)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Torus {
        let (cipher, p_key) = rep.get_and_drop();
        let a_cross_s = p_key
            .iter()
            .zip(s_key.iter())
            .filter(|(_, &b)| b == Binary::One)
            .fold(Torus::zero(), |s, (&x, _)| s + x);
        let m_with_e = cipher - a_cross_s;

        m_with_e
    }
}

pub struct KeySwitchingKey<const N: usize, const M: usize>(
    Vec<[[TLWERep<M>; TLWEHelper::IKS_T]; TLWEHelper::IKS_L]>,
);
impl<const N: usize, const M: usize> KeySwitchingKey<N, M> {
    pub fn new(pre_s_key: [Binary; N], next_s_key: &[Binary; M]) -> Self {
        const BASEBIT: i32 = TLWEHelper::IKS_BASEBIT as i32;
        const T: usize = TLWEHelper::IKS_T;
        const L: usize = TLWEHelper::IKS_L;

        let culc_tlwe = |s_i: Binary, l: u32, t: u32| {
            let s_i: f32 = s_i.into();
            // t*s_i/2^{basebit * l}
            let item:Torus = torus!(s_i * 0.5_f32.powi(BASEBIT * l as i32) * t as f32);
            let tlwe = Cryptor::encrypto(TLWE, next_s_key, item);
            tlwe
        };

        let mut ks = Vec::<[[TLWERep<M>; T]; L]>::with_capacity(N);
        unsafe { ks.set_len(N) }; // 初期化せずにアクセスするためのunsafe

        for (&s_i, ks_i) in pre_s_key.iter().zip(ks.iter_mut()) {
            // TODO: マルチスレッドで計算できる
            for (l, ks_i_l) in ks_i.iter_mut().enumerate() {
                for (t, ks_i_l_t) in ks_i_l.iter_mut().enumerate() {
                    // KS[i][l][t] = TLWE((t+1)*s_i/(2^{bit*(l+1)}))を計算
                    *ks_i_l_t = culc_tlwe(
                        s_i,
                        1 + l as u32, /* l >= 1について上式をTLWEしたものを計算 */
                        1 + t as u32, /* t=0のときはarr_i_l_0 = 0なので計算しない */
                    );
                }
            }
        }
        KeySwitchingKey(ks)
    }
    /// 引数についての境界チェックあり
    /// # Return
    /// get(i,l,t) = KS\[i\]\[l\]\[t-1\] = TLWE::encrypto(t\*s_i/(2^{bit\*(l+1)}))
    pub fn get(&self, i: usize, l: usize, t: usize) -> &TLWERep<M> {
        &self.0[i][l][t as usize - 1]
    }
    /// 引数についての境界チェックをしない
    /// # Return
    /// get_unchecked(i,l,t) = KS\[i\]\[l\]\[t-1\] = TLWE::encrypto(t\*s_i/(2^{bit\*(l+1)}))
    pub unsafe fn get_unchecked(&self, i: usize, l: usize, t: usize) -> &TLWERep<M> {
        self.0
            .get_unchecked(i)
            .get_unchecked(l)
            .get_unchecked(t as usize - 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::{digest::Cryptor, trlwe::TRLWEHelper};

    use super::*;
    use utils::math::*;

    #[test]
    fn tlwerep_op() {
        let l = TLWERep::new(torus!(0.5), [torus!(0.5), torus!(0.25)]);
        let r = TLWERep::new(torus!(0.25), [torus!(0.125), torus!(0.5)]);

        let res = l.clone() + r.clone();
        assert!(res.cipher.is_in(torus!(0.75), 1e-9));
        assert!(res.p_key[0].is_in(torus!(0.625), 1e-9));
        assert!(res.p_key[1].is_in(torus!(0.75), 1e-9));

        let res = l.clone() - r.clone();
        assert!(res.cipher.is_in(torus!(0.25), 1e-9));
        assert!(res.p_key[0].is_in(torus!(0.375), 1e-9));
        assert!(res.p_key[1].is_in(torus!(0.75), 1e-9));

        let res = l.clone() * 3;
        assert!(res.cipher.is_in(torus!(0.5), 1e-9));
        assert!(res.p_key[0].is_in(torus!(0.5), 1e-9));
        assert!(res.p_key[1].is_in(torus!(0.75), 1e-9));

        let res = l.clone() * 0;
        assert!(res.cipher.is_in(torus!(0.0), 1e-9));
        assert!(res.p_key[0].is_in(torus!(0.0), 1e-9));
        assert!(res.p_key[1].is_in(torus!(0.0), 1e-9));
    }

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

    #[test]
    fn tlwe_identity_key_switching() {
        {
            const N: usize = TRLWEHelper::N;
            const M: usize = TLWEHelper::N;
            let mut b_uniform = BinaryDistribution::uniform();
            let s_key_tlwelv1 = b_uniform.gen_n::<N>();
            let s_key_tlwelv0 = b_uniform.gen_n::<M>();

            let ks = KeySwitchingKey::new(s_key_tlwelv1, &s_key_tlwelv0);

            let test = |item: Binary| {
                let rep_tlwelv1 = Cryptor::encrypto(TLWE, &s_key_tlwelv1, item);
                {
                    let test: Binary =
                        Cryptor::decrypto(TLWE::<N>, &s_key_tlwelv1, rep_tlwelv1.clone());
                    assert_eq!(test, item, "Part1.tlweのテスト, item={}", item);
                }
                let rep_tlwelv0 = rep_tlwelv1.identity_key_switch(&ks);
                let result: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_tlwelv0);
                assert_eq!(result, item, "Part1.keyを変えてもidenitity, item={}", item);
            };

            test(Binary::One);
            test(Binary::Zero);
        }
        {
            const N: usize = 256;
            const M: usize = 60;
            let mut b_uniform = BinaryDistribution::uniform();
            let s_key_tlwelv1 = b_uniform.gen_n::<N>();
            let s_key_tlwelv0 = b_uniform.gen_n::<M>();

            let ks = KeySwitchingKey::new(s_key_tlwelv1, &s_key_tlwelv0);

            let test = |item: Binary| {
                let rep_tlwelv1 = Cryptor::encrypto(TLWE, &s_key_tlwelv1, item);
                {
                    let test: Binary =
                        Cryptor::decrypto(TLWE::<N>, &s_key_tlwelv1, rep_tlwelv1.clone());
                    assert_eq!(test, item, "Part2.tlweのテスト, item={}", item);
                }
                let rep_tlwelv0 = rep_tlwelv1.identity_key_switch(&ks);
                let result: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_tlwelv0);
                assert_eq!(result, item, "Part2.keyを変えてもidenitity, item={}", item);
            };

            test(Binary::One);
            test(Binary::Zero);
        }
    }
}
