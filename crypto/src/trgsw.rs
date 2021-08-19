
use num::{ToPrimitive, Zero};
use std::mem::MaybeUninit;

use super::digest::{Crypto, Cryptor, Encryptable, Encrypted};
use super::tlwe::TLWE;
use super::trlwe::TRLWE;
use utils::math::{Binary, Cross, Polynomial, Torus};
use utils::torus;

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

pub struct TRGSWHelper;
impl TRGSWHelper {
    const BGBIT: u32 = 6;
    const BG: usize = 2_i32.pow(TRGSWHelper::BGBIT) as usize;
    const BG_INV: f32 = 1.0 / (TRGSWHelper::BG as f32);
    const L: usize = 3;
}
impl<const NN: usize> TRGSW<NN> {
    fn create_zero_encrypted_pols<const M: usize, const N: usize>(
        s_key: &<TRGSW<N> as Crypto<Polynomial<i32, N>>>::SecretKey,
    ) -> ([Polynomial<Torus, N>; M], [Polynomial<Torus, N>; M]) {
        let mut cipher: [MaybeUninit<Polynomial<Torus, N>>; M] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut p_key: [MaybeUninit<Polynomial<Torus, N>>; M] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for (b_, a_) in cipher.iter_mut().zip(p_key.iter_mut()) {
            let Encrypted(b, a) = Cryptor::encrypto(TRLWE, s_key, Polynomial::<Torus, N>::zero());
            *b_ = MaybeUninit::new(b);
            *a_ = MaybeUninit::new(a);
        }
        // std::mem::transmute have problem
        // issue:https://github.com/rust-lang/rust/issues/61956
        (
            utils::mem::transmute::<_, [Polynomial<Torus, N>; M]>(cipher),
            utils::mem::transmute::<_, [Polynomial<Torus, N>; M]>(p_key),
        )
    }
}

impl<const N: usize> Crypto<Polynomial<i32, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

    fn encrypto(&self, s_key: &Self::SecretKey, item: Polynomial<i32, N>) -> Self::Representation {
        const L: usize = TRGSWHelper::L;
        let (mut cipher, mut p_key) = Self::create_zero_encrypted_pols::<{ 2 * L }, N>(s_key);
        {
            let mut bg: f32 = 1.0;
            for i in 0..L {
                bg *= TRGSWHelper::BG_INV;
                let p = item.map(|&x| torus!(x as f32 * bg));
                cipher[i] = cipher[i] + p;
                p_key[i + L] = p_key[i + L] + p;
            }
        }
        Encrypted(cipher, p_key)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Polynomial<i32, N> {
        const I: usize = 0; // BG^(I+1)の精度で復元,エラーもBG^(I+1)倍されるのでトレードオフ
        const BG: i32 = TRGSWHelper::BG.pow(I as u32 + 1) as i32;
        const FALF_BG: i32 = BG / 2;
        debug_assert!((I as u32) < TRGSWHelper::BGBIT);
        let (b, a) = rep.get_and_drop();
        let res: Polynomial<Torus, N> = Cryptor::decrypto(TRLWE, s_key, Encrypted(b[I], a[I]));
        res.map(|d| {
            let res = (d.to_f32().unwrap() * (TRGSWHelper::BG as f32))
                .round()
                .to_i32()
                .unwrap();
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
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

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
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> Self::Representation {
        Cryptor::encrypto(TRGSW, s_key, item.map(|x| x.to::<i32>()))
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
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

    fn encrypto(&self, s_key: &Self::SecretKey, item: i32) -> Self::Representation {
        const L: usize = TRGSWHelper::L;
        let (mut cipher, mut p_key) = Self::create_zero_encrypted_pols::<{ 2 * L }, N>(s_key);
        {
            let mut bg: f32 = 1.0;
            for i in 0..L {
                bg *= TRGSWHelper::BG_INV;
                let p = torus!(item as f32 * bg); //item.map(|&x| torus!(x as f32 * bg));
                cipher[i] = cipher[i].add_constant(p);
                p_key[i + L] = p_key[i + L].add_constant(p);
            }
        }
        Encrypted(cipher, p_key)
    }

    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> i32 {
        const I: usize = 0; // BG^(I+1)の精度で復元,エラーもBG^(I+1)倍されるのでトレードオフ
        const BG: i32 = TRGSWHelper::BG.pow(I as u32 + 1) as i32;
        const FALF_BG: i32 = BG / 2;
        debug_assert!((I as u32) < TRGSWHelper::BGBIT);
        let (b, a) = rep.get_and_drop();
        let rep = Encrypted(b[I], a[I]).sample_extract_index(0);
        let res: Torus = Cryptor::decrypto(TLWE, s_key.coefficient(), rep);
        // 丸める
        let res = (res.to_f32().unwrap() * (TRGSWHelper::BG as f32))
            .round()
            .to_i32()
            .unwrap();

        if res > FALF_BG {
            res - BG
        } else {
            res
        }
    }
}

impl<const N: usize>
    Cross<
        /*<TRLWE as CryptoCore>::Representation*/
        Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
    > for <TRGSW<N> as Crypto<Polynomial<Binary, N>>>::Representation
{
    type Output = Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>;

    fn cross(&self, rhs: &Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>) -> Self::Output {
        const L: usize = TRGSWHelper::L;
        const BGBIT: u32 = TRGSWHelper::BGBIT;
        let b_decomp = rhs.cipher().decomposition::<L>(BGBIT);
        let a_decomp = rhs.p_key().decomposition::<L>(BGBIT);
        let (b_trgsw, a_trgsw) = self.get_ref();

        let mut cipher = Polynomial::<Torus, N>::zero();
        let mut p_key = Polynomial::<Torus, N>::zero();

        // (cipher,p_key) = C*(b,a) = (b.decomp[0],..,,a.decomp[0],..)*(b_trgsw,a_trgsw)
        for i in 0..L {
            cipher = cipher + b_trgsw[i].cross(&b_decomp[i]);
            cipher = cipher + b_trgsw[i + L].cross(&a_decomp[i]);

            p_key = p_key + a_trgsw[i].cross(&b_decomp[i]);
            p_key = p_key + a_trgsw[i + L].cross(&a_decomp[i]);
        }
        Encrypted(cipher, p_key)
    }
}

impl<const N: usize>
    Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >
{
    pub fn cmux(
        &self,
        rep_1: Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
        rep_0: Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
    ) -> Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>> {
        self.cross(&(rep_1 - rep_0.clone())) + rep_0
    }
}

#[cfg(test)]
mod tests {
    use crate::{digest::Cryptor, trlwe::TRLWEHelper};

    use super::*;
    use test::Bencher;
    use utils::{pol,torus};
    use array_macro::array;
    use utils::math::*;

    #[test]
    fn trgsw_crypto() {
        const N: usize = 3;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol: Polynomial<u32, N> = pol!([5, 15, 20]);
        let rep = Cryptor::encrypto(TRGSW::<N>, &s_key, pol.clone());
        let res: Polynomial<u32, N> = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(pol, res);

        let pol: Polynomial<i32, N> = pol!([1, -1, -1]);
        let rep = Cryptor::encrypto(TRGSW::<N>, &s_key, pol.clone());
        let res: Polynomial<i32, N> = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(pol, res);

        let item:i32 = 3;
        let rep = Cryptor::encrypto(TRGSW, &s_key, item);
        let res:i32 = Cryptor::decrypto(TRGSW, &s_key, rep);
        assert_eq!(item,res);
    }

    #[test]
    fn trgsw_cross() {
        const N: usize = 3;
        let acc = 1e-6;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let item: i32 = 1;
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);
        let respect: Polynomial<Torus, N> = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
        let rep_trlwe = Cryptor::encrypto(TRLWE, &s_key, respect);
        let res_cross = rep_trgsw.cross(&rep_trlwe);
        let actual: Polynomial<Torus, N> = Cryptor::decrypto(TRLWE, &s_key, res_cross);
        for i in 0..N {
            assert!(
                actual.coef_(i).is_in(respect.coef_(i), acc),
                "1をTRGSWで暗号化してかけても、複合結果は変わらないはず\nrespect={:?},actual={:?}",
                respect,
                actual
            );
        }

        let pol_i32: Polynomial<i32, N> = pol!([1, -1, 1]);
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, pol_i32.clone());
        let pol_torus: Polynomial<Torus, N> = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
        let rep_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_torus);
        let res_cross = rep_trgsw.cross(&rep_trlwe);
        let actual: Polynomial<Torus, N> = Cryptor::decrypto(TRLWE, &s_key, res_cross);
        let respect = pol_torus.cross(&pol_i32);
        for i in 0..N {
            assert!(
                actual.coef_(i).is_in(respect.coef_(i), acc),
                "多項式をTRGSWで暗号化してかけたものを復号化\nrespect={:?},actual={:?}",
                respect,
                actual
            );
        }
    }

    #[test]
    #[ignore]
    fn trgsw_cmux() {
        const N: usize = TRLWEHelper::N;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let item: i32 = 1;
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);

        let pol_0: Polynomial<Binary, N> = pol!([Binary::Zero; N]);
        let rep_0_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_0.clone());

        let pol_1: Polynomial<Binary, N> = pol!([Binary::One; N]);
        let rep_1_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_1.clone());

        let result = rep_trgsw.cmux(rep_1_trlwe, rep_0_trlwe);
        let text: Polynomial<Binary, N> = Cryptor::decrypto(TRLWE, &s_key, result);

        assert_eq!(
            pol_1, text,
            "cmux Wrong: {0}*(pol_1-pol_0)+pol_0=pol_{0}",
            item
        );
    }

    /// <2021/8/16> 40,921,939 ns/iter (+/- 4,744,092)
    #[bench]
    fn bench_trgsw_cross(b: &mut Bencher) {
        const N: usize = TRLWEHelper::N;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol: Polynomial<u32, N> = pol!(array![ i => (i%TRGSWHelper::BG)as u32;N]);
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, pol);

        let pol: Polynomial<Torus, N> = pol!(ModDistribution::uniform().gen_n::<N>());
        let rep_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol);

        b.iter(|| rep_trgsw.cross(&rep_trlwe))
    }
}
