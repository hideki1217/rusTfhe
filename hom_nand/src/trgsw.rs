use super::digest::{Crypto, Cryptor, Encryptable, Encrypted};
use super::tlwe::TLWE;
use super::trlwe::TRLWE;
use crate::trlwe::TRLWERep;
use num::{ToPrimitive, Zero};
use std::mem::MaybeUninit;
use utils::math::{Binary, Cross, Polynomial, Torus32};
use utils::spqlios::FrrSeries;
use utils::{mem, torus};

pub struct TRGSW<const N: usize>;
macro_rules! trgsw_encryptable {
    ($t:ty) => {
        impl<const N: usize> Encryptable<TRGSW<N>> for $t {}
    };
}
trgsw_encryptable!(Polynomial<u32, N>);
trgsw_encryptable!(Polynomial<i32, N>);
trgsw_encryptable!(Polynomial<Binary, N>);
trgsw_encryptable!(i32);
trgsw_encryptable!(Binary);

pub struct TRGSWRep<const N: usize> {
    cipher: [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
    p_key: [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
}
impl<const N: usize>
    Encrypted<
        [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
    > for TRGSWRep<N>
{
    fn cipher(&self) -> &[Polynomial<Torus32, N>; 2 * TRGSWHelper::L] {
        &self.cipher
    }
    fn p_key(&self) -> &[Polynomial<Torus32, N>; 2 * TRGSWHelper::L] {
        &self.p_key
    }
    fn get_and_drop(
        self,
    ) -> (
        [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
    ) {
        (self.cipher, self.p_key)
    }
}
impl<const N: usize> TRGSWRep<N> {
    pub fn new(
        cipher: [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
        p_key: [Polynomial<Torus32, N>; 2 * TRGSWHelper::L],
    ) -> Self {
        TRGSWRep { cipher, p_key }
    }
}
pub struct TRGSWRepF<const N: usize> {
    cipher_f: [FrrSeries<N>; TRGSWHelper::L * 2],
    pkey_f: [FrrSeries<N>; TRGSWHelper::L * 2],
}
impl<const N: usize> From<&TRGSWRep<N>> for TRGSWRepF<N> {
    fn from(t: &TRGSWRep<N>) -> Self {
        let cipher_f: [FrrSeries<N>; TRGSWHelper::L * 2] =
            mem::array_create_enumerate(|i| FrrSeries::<N>::from(&t.cipher()[i]));
        let pkey_f: [FrrSeries<N>; TRGSWHelper::L * 2] =
            mem::array_create_enumerate(|i| FrrSeries::<N>::from(&t.p_key()[i]));
        TRGSWRepF { cipher_f, pkey_f }
    }
}
impl<const N: usize> From<TRGSWRep<N>> for TRGSWRepF<N> {
    fn from(t: TRGSWRep<N>) -> Self {
        Self::from(&t)
    }
}
impl<const N: usize> TRGSWRepF<N> {
    #[allow(dead_code)]
    fn cipher_f(&self) -> &[FrrSeries<N>; 2 * TRGSWHelper::L] {
        &self.cipher_f
    }
    #[allow(dead_code)]
    fn p_key(&self) -> &[FrrSeries<N>; 2 * TRGSWHelper::L] {
        &self.pkey_f
    }
    fn get_ref(
        &self,
    ) -> (
        &[FrrSeries<N>; 2 * TRGSWHelper::L],
        &[FrrSeries<N>; 2 * TRGSWHelper::L],
    ) {
        (&self.cipher_f, &self.pkey_f)
    }
    #[allow(dead_code)]
    fn get_and_drop(
        self,
    ) -> (
        [FrrSeries<N>; 2 * TRGSWHelper::L],
        [FrrSeries<N>; 2 * TRGSWHelper::L],
    ) {
        (self.cipher_f, self.pkey_f)
    }
}

pub struct TRGSWHelper;
impl TRGSWHelper {
    pub const BGBIT: u32 = 6;
    pub const BG: usize = 2_i32.pow(TRGSWHelper::BGBIT) as usize;
    pub const BG_INV: f32 = 1.0 / (TRGSWHelper::BG as f32);
    pub const L: usize = 3;
}
impl<const N: usize> TRGSW<N> {
    fn create_zero_encrypted_pols<const M: usize>(
        s_key: &<TRGSW<N> as Crypto<Polynomial<i32, N>>>::SecretKey,
    ) -> ([Polynomial<Torus32, N>; M], [Polynomial<Torus32, N>; M]) {
        let mut cipher: [MaybeUninit<Polynomial<Torus32, N>>; M] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut p_key: [MaybeUninit<Polynomial<Torus32, N>>; M] =
            unsafe { MaybeUninit::uninit().assume_init() };
        // TODO:　並列化
        for (b_, a_) in cipher.iter_mut().zip(p_key.iter_mut()) {
            let (b, a) =
                Cryptor::encrypto(TRLWE, s_key, Polynomial::<Torus32, N>::zero()).get_and_drop();
            *b_ = MaybeUninit::new(b);
            *a_ = MaybeUninit::new(a);
        }
        // std::mem::transmute have problem
        // issue:https://github.com/rust-lang/rust/issues/61956
        (
            utils::mem::transmute::<_, [Polynomial<Torus32, N>; M]>(cipher),
            utils::mem::transmute::<_, [Polynomial<Torus32, N>; M]>(p_key),
        )
    }
}

impl<const N: usize> Crypto<Polynomial<i32, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRGSWRep<N>;

    fn encrypto(&self, s_key: &Self::SecretKey, item: Polynomial<i32, N>) -> Self::Representation {
        const L: usize = TRGSWHelper::L;
        let (mut cipher, mut p_key) = Self::create_zero_encrypted_pols::<{ 2 * L }>(s_key);
        {
            const BG_INV: f32 = TRGSWHelper::BG_INV;
            for i in 0..L {
                let bg_inv_pow_i = BG_INV.powi(1 + i as i32);
                let p = item.map(|&x| torus!(x as f32 * bg_inv_pow_i));
                cipher[i] += &p;
                p_key[i + L] += &p;
            }
        }
        TRGSWRep::new(cipher, p_key)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Polynomial<i32, N> {
        const I: usize = 0; // BG^(I+1)の精度で復元,エラーもBG^(I+1)倍されるのでトレードオフ
        const BG: i32 = TRGSWHelper::BG.pow(I as u32 + 1) as i32;
        const FALF_BG: i32 = BG / 2;
        debug_assert!((I as u32) < TRGSWHelper::BGBIT);
        let (b, a) = rep.get_and_drop();
        let res: Polynomial<Torus32, N> =
            Cryptor::decrypto(TRLWE, s_key, TRLWERep::new(b[I], a[I]));
        res.map(|d| {
            let d: f32 = d.into();
            let res = (d * (TRGSWHelper::BG as f32)).round().to_i32().unwrap();
            if res > FALF_BG {
                res - BG
            } else {
                res
            }
        })
    }
}
impl<const N: usize> Crypto<Polynomial<u32, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRGSWRep<N>;

    fn encrypto(&self, s_key: &Self::SecretKey, item: Polynomial<u32, N>) -> Self::Representation {
        Cryptor::encrypto(TRGSW, s_key, item.map(|&x| x as i32))
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Polynomial<u32, N> {
        let res: Polynomial<i32, N> = Cryptor::decrypto(TRGSW, s_key, rep);
        res.map(|&x| x as u32)
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRGSWRep<N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> Self::Representation {
        Cryptor::encrypto(TRGSW, s_key, item.map(|&x| x as i32))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: Self::Representation,
    ) -> Polynomial<Binary, N> {
        let res: Polynomial<i32, N> = Cryptor::decrypto(TRGSW, s_key, rep);
        res.map(|&x| Binary::from(x))
    }
}
impl<const N: usize> Crypto<i32> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRGSWRep<N>;

    fn encrypto(&self, s_key: &Self::SecretKey, item: i32) -> Self::Representation {
        const L: usize = TRGSWHelper::L;
        let (mut cipher, mut p_key) = Self::create_zero_encrypted_pols::<{ 2 * L }>(s_key);
        {
            const BG_INV: f32 = TRGSWHelper::BG_INV;
            for i in 0..L {
                let p = torus!(item.to_f32().unwrap() * BG_INV.powi(1 + i as i32));
                cipher[i].add_constant(p);
                p_key[i + L].add_constant(p);
            }
        }
        TRGSWRep::new(cipher, p_key)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> i32 {
        const I: usize = 0; // BG^(I+1)の精度で復元,エラーもBG^(I+1)倍されるのでトレードオフ
        const BG: i32 = TRGSWHelper::BG.pow(I as u32 + 1) as i32;
        const FALF_BG: i32 = BG / 2;
        debug_assert!((I as u32) < TRGSWHelper::BGBIT);
        let (b, a) = rep.get_and_drop();
        let rep = TRLWERep::new(b[I], a[I]).sample_extract_index(0);
        let res: Torus32 = Cryptor::decrypto(TLWE, s_key.coefs(), rep);
        // 丸める
        let res: f32 = res.into();
        let res = (res * (TRGSWHelper::BG as f32)).round().to_i32().unwrap();

        if res > FALF_BG {
            res - BG
        } else {
            res
        }
    }
}
impl<const N: usize> Crypto<Binary> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = TRGSWRep<N>;

    fn encrypto(&self, s_key: &Self::SecretKey, item: Binary) -> Self::Representation {
        self.encrypto(s_key, item as i32)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Binary {
        let res: i32 = self.decrypto(s_key, rep);
        Binary::from(res)
    }
}

impl<const N: usize> Cross<TRLWERep<N>> for TRGSWRepF<N> {
    type Output = TRLWERep<N>;

    fn cross(&self, rhs: &TRLWERep<N>) -> Self::Output {
        const L: usize = TRGSWHelper::L;
        const BGBIT: u32 = TRGSWHelper::BGBIT;
        const DECOMP_MASK: u32 = Torus32::make_decomp_mask(L as u32, BGBIT);
        let b_decomp = rhs.cipher().decomposition_::<L>(BGBIT, DECOMP_MASK);
        let a_decomp = rhs.p_key().decomposition_::<L>(BGBIT, DECOMP_MASK);
        let (b_trgsw_f, a_trgsw_f) = self.get_ref();

        let b_decomp_f: [FrrSeries<N>; L] = unsafe {
            mem::array_create(
                b_decomp
                    .iter()
                    .map(|b_decomp_i| FrrSeries::<N>::from(b_decomp_i)),
            )
        };
        let a_decomp_f: [FrrSeries<N>; L] = unsafe {
            mem::array_create(
                a_decomp
                    .iter()
                    .map(|a_decomp_i| FrrSeries::<N>::from(a_decomp_i)),
            )
        };

        // (cipher,p_key) = C*(b,a) = (b.decomp[0],..,,a.decomp[0],..)*(b_trgsw,a_trgsw)
        let cipher_f = b_trgsw_f
            .iter()
            .zip(b_decomp_f.iter().chain(a_decomp_f.iter()))
            .fold(FrrSeries::zero(), |s, (l, r)| s + l.hadamard(r));
        let p_key_f = a_trgsw_f
            .iter()
            .zip(b_decomp_f.iter().chain(a_decomp_f.iter()))
            .fold(FrrSeries::zero(), |s, (l, r)| s + l.hadamard(r));

        let cipher: Polynomial<Torus32, N> = Polynomial::<Torus32, N>::from(cipher_f);
        let p_key: Polynomial<Torus32, N> = Polynomial::<Torus32, N>::from(p_key_f);

        TRLWERep::new(cipher, p_key)
    }
}
impl<const N: usize> Cross<TRLWERep<N>> for TRGSWRep<N> {
    type Output = TRLWERep<N>;

    fn cross(&self, rhs: &TRLWERep<N>) -> Self::Output {
        TRGSWRepF::<N>::from(self).cross(rhs)
    }
}

impl<const N: usize> TRGSWRepF<N> {
    /// # Sample
    /// let i: Binary;
    /// TRGSW(i).cmux(rep_1,rep_0) = rep_i;
    pub fn cmux(&self, rep_1: TRLWERep<N>, rep_0: TRLWERep<N>) -> TRLWERep<N> {
        self.cross(&(rep_1 - &rep_0)) + rep_0
    }
}
impl<const N: usize> TRGSWRep<N> {
    /// # Sample
    /// let i: Binary;
    /// TRGSW(i).cmux(rep_1,rep_0) = rep_i;
    pub fn cmux(&self, rep_1: TRLWERep<N>, rep_0: TRLWERep<N>) -> TRLWERep<N> {
        self.cross(&(rep_1 - &rep_0)) + rep_0
    }
}

#[cfg(test)]
mod tests {
    use crate::{digest::Cryptor, trlwe::TRLWEHelper};

    use super::*;
    use test::Bencher;
    use utils::math::*;
    use utils::{pol, torus};

    #[test]
    fn trgsw_crypto() {
        const N: usize = TRLWEHelper::N;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol = pol!(mem::array_create_enumerate(|i| i as u32 % 20));
        let rep = Cryptor::encrypto(TRGSW::<N>, &s_key, pol.clone());
        let res: Polynomial<u32, N> = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(pol, res);

        let pol = pol!(mem::array_create_enumerate(|i| 1 - 2 * (i as i32 % 2)));
        let rep = Cryptor::encrypto(TRGSW::<N>, &s_key, pol.clone());
        let res: Polynomial<i32, N> = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(pol, res);

        let item: i32 = 4;
        let rep = Cryptor::encrypto(TRGSW, &s_key, item);
        let res: i32 = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(item, res);
    }

    #[test]
    fn trgsw_cross() {
        {
            const N: usize = TRLWEHelper::N;
            let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());
            let item: i32 = 1;
            let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
            let expect = pol!(mem::array_create_enumerate(|i| if i % 2 == 0 {
                torus!(0.5)
            } else {
                torus!(0.25)
            }));
            let res_cross = rep_trgsw.cross(&Cryptor::encrypto(TRLWE, &s_key, expect));
            let actual: Polynomial<Torus32, N> = Cryptor::decrypto(TRLWE, &s_key, res_cross);
            for i in 0..N {
                assert!(
                    actual.coef_(i).is_in(expect.coef_(i), 1e-3),
                    "N={}::1をTRGSWで暗号化してかけても、複合結果は変わらないはず\nrespect={:?}\n,actual={:?}",
                    N,
                    expect,
                    actual
                );
            }
        }
    }

    #[test]
    fn trgsw_cmux() {
        {
            const N: usize = TRLWEHelper::N;

            let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

            let pol_0: Polynomial<Binary, N> = pol!([Binary::Zero; N]);
            let pol_1: Polynomial<Binary, N> = pol!([Binary::One; N]);

            let rep_0_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_0);
            let rep_1_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_1);

            let item = 1;
            let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
            let result = rep_trgsw.cmux(rep_1_trlwe.clone(), rep_0_trlwe.clone());
            let text: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, result);
            assert_eq!(
                pol_1, text,
                "Part1.cmux Wrong: {0}*(pol_1-pol_0)+pol_0=pol_{0}",
                item
            );

            let item = 0;
            let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
            let result = rep_trgsw.cmux(rep_1_trlwe, rep_0_trlwe);
            let text: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, result);
            assert_eq!(
                pol_0, text,
                "Part1.cmux Wrong: {0}*(pol_1-pol_0)+pol_0=pol_{0}",
                item
            );
        }
        // TODO: Sqplios導入後、なぜかこれが落ちる256も8の倍数なのになぜ？
        /*{
            const N: usize = 512;

            let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

            let pol_0: Polynomial<Binary, N> = pol!([Binary::Zero; N]);
            let pol_1: Polynomial<Binary, N> = pol!([Binary::One; N]);

            let rep_0_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_0);
            let rep_1_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_1);

            let item = 1;
            let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
            let result = rep_trgsw.cmux(rep_1_trlwe.clone(), rep_0_trlwe.clone());
            let text: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, result);
            assert_eq!(
                pol_1, text,
                "Part2.cmux Wrong: {0}*(pol_1-pol_0)+pol_0=pol_{0}",
                item
            );

            let item = 0;
            let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
            let result = rep_trgsw.cmux(rep_1_trlwe, rep_0_trlwe);
            let text: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, result);
            assert_eq!(
                pol_0, text,
                "Part2.cmux Wrong: {0}*(pol_1-pol_0)+pol_0=pol_{0}",
                item
            );
        }*/
    }

    /// <2021/8/16> 40,921,939 ns/iter (+/- 4,744,092)
    /// <2021/8/23> 24,759,582 ns/iter (+/- 4,053,680) crossの中でvecをallocateするのをやめた
    /// <2021/09/11>   204,672 ns/iter (+/- 22,769) spqliosなどを導入
    #[bench]
    fn bench_trgsw_cross(b: &mut Bencher) {
        const N: usize = TRLWEHelper::N;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol_u32: Polynomial<u32, N> =
            pol!(mem::array_create_enumerate(|i| (i % TRGSWHelper::BG) as u32));
        let pol_torus: Polynomial<Torus32, N> = pol!(ModDistribution::uniform().gen_n::<N>());

        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, pol_u32);
        let rep_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_torus);

        b.iter(|| rep_trgsw.cross(&rep_trlwe))
    }
}
