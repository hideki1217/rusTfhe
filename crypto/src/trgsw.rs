use array_macro::array;
use num::cast::AsPrimitive;
use num::Zero;
use std::mem::MaybeUninit;

use super::digest::{Crypto, Cryptor, Encryptable, Encrypted};
use super::trlwe::TRLWE;
use math_utils::{pol, torus, Binary, Cross, Polynomial, Torus};

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
impl<const N: usize> TRGSW<N> {}

impl<const N: usize, Int: AsPrimitive<f32>> Crypto<Polynomial<Int, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

    fn encrypto(&self, s_key: &Self::SecretKey, item: Polynomial<Int, N>) -> Self::Representation {
        const L: usize = TRGSWHelper::L;
        fn create_zero_encrypted_pols<const M: usize, const N: usize>(
            s_key: &<TRGSW<N> as Crypto<Polynomial<i32, N>>>::SecretKey,
        ) -> ([Polynomial<Torus, N>; M], [Polynomial<Torus, N>; M]) {
            let mut cipher: [MaybeUninit<Polynomial<Torus, N>>; M] =
                unsafe { MaybeUninit::uninit().assume_init() };
            let mut p_key: [MaybeUninit<Polynomial<Torus, N>>; M] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for (b_, a_) in cipher.iter_mut().zip(p_key.iter_mut()) {
                let Encrypted(b, a) =
                    Cryptor::encrypto(TRLWE, s_key, Polynomial::<Torus, N>::zero());
                *b_ = MaybeUninit::new(b);
                *a_ = MaybeUninit::new(a);
            }
            unsafe {
                // std::mem::transmute have problem
                // issue:https://github.com/rust-lang/rust/issues/61956
                let ptr = &mut cipher as *mut _ as *mut [Polynomial<Torus, N>; M];
                let res_cipher = ptr.read();

                let ptr = &mut p_key as *mut _ as *mut [Polynomial<Torus, N>; M];
                let res_p_key = ptr.read();

                core::mem::forget(cipher);
                core::mem::forget(p_key);

                (res_cipher, res_p_key)
            }
        }
        let (mut cipher, mut p_key) = create_zero_encrypted_pols::<{ 2 * L }, N>(s_key);
        {
            let mut bg: f32 = 1.0;
            for i in 0..L {
                bg *= TRGSWHelper::BG_INV;
                let p = pol!(array![ i => torus!(item.coef_(i).as_()*bg);N]);
                cipher[i] = cipher[i] + p;
                p_key[i + L] = p_key[i + L] + p;
            }
        }
        Encrypted(cipher, p_key)
    }
    #[allow(unused_variables)]
    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> Polynomial<Int, N> {
        todo!()
    }
}
impl<const N: usize> Crypto<i32> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >;

    fn encrypto(&self, s_key: &Self::SecretKey, item: i32) -> Self::Representation {
        let text = pol!(array![i => if i==0 {item} else {i32::zero()};N]);
        Cryptor::encrypto(TRGSW, s_key, text)
    }

    #[allow(unused_variables)]
    fn decrypto(&self, s_key: &Self::SecretKey, rep: Self::Representation) -> i32 {
        todo!()
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
        let b_trlwe = rhs.cipher().decomposition::<L>(BGBIT);
        let a_trlwe = rhs.p_key().decomposition::<L>(BGBIT);
        let (b_trgsw, a_trgsw) = self.get_ref();

        let mut cipher = Polynomial::<Torus, N>::zero();
        let mut p_key = Polynomial::<Torus, N>::zero();

        for i in 0..L {
            cipher = cipher + b_trgsw[i].cross(&b_trlwe[i]);
            cipher = cipher + b_trgsw[i + L].cross(&a_trlwe[i]);

            p_key = p_key + a_trgsw[i].cross(&b_trlwe[i]);
            p_key = p_key + a_trgsw[i + L].cross(&a_trlwe[i]);
        }
        Encrypted(cipher, p_key)
    }
}
/*<TRGSW<N> as CryptoCore>::Representation*/
impl<const N: usize>
    Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
        [Polynomial<Torus, N>; 2 * TRGSWHelper::L],
    >
{
    pub fn cmux(
        &self,
        rep_0: Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
        rep_1: Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
    ) -> Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>> {
        self.cross(&(rep_1 - rep_0.clone())) + rep_0
    }
}

#[cfg(test)]
mod tests {
    use crate::{digest::Cryptor, trlwe::TRLWEHelper};

    use super::*;
    use math_utils::*;
    use test::Bencher;

    #[test]
    fn trgsw_encrypto() {
        const N: usize = 3;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());
        let pol: Polynomial<u32, N> = pol!([5, 15, 20]);
        let _rep = Cryptor::encrypto(TRGSW::<N>, &s_key, pol);
    }

    #[test]
    fn trgsw_cross() {
        const N: usize = 3;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol: Polynomial<u32, N> = pol!([5, 15, 20]);
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, pol);

        let pol: Polynomial<Torus, N> = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
        let rep_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol);

        let _res_cross = rep_trgsw.cross(&rep_trlwe);
    }

    #[test]
    #[ignore]
    fn trgsw_cmux() {
        const N: usize = TRLWEHelper::N;

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let item: i32 = 1;
        let rep_trgsw = Cryptor::encrypto(TRGSW, &s_key, item);

        let pol_0: Polynomial<Binary, N> = pol!([Binary::Zero; N]);
        let rep_0_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_0);

        let pol_1: Polynomial<Binary, N> = pol!([Binary::One; N]);
        let rep_1_trlwe = Cryptor::encrypto(TRLWE, &s_key, pol_1);

        let result = rep_trgsw.cmux(rep_0_trlwe, rep_1_trlwe);
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
