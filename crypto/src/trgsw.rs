use array_macro::array;
use num::{ToPrimitive, Zero};

use crate::digest::CryptoCore;

use super::digest::{Crypto, Encrypted};
use super::trlwe::TRLWE;
use math_utils::{pol, torus, Binary, Cross, Polynomial, Torus};

pub struct TRGSW<const N: usize>;
impl<const N: usize> TRGSW<N> {
    const BGBIT: u32 = 6;
    const BG: usize = 2_i32.pow(TRGSW::<0>::BGBIT) as usize;
    const BG_INV: f32 = 1.0 / (TRGSW::<0>::BG as f32);
    const L: usize = 3;
    pub fn new() -> Self {
        TRGSW::<N>
    }
    pub fn binary_pol2u32_pol<const M: usize>(pol: Polynomial<Binary, M>) -> Polynomial<u32, M> {
        pol!(array![ i => pol.coef_(i).to_u32().unwrap() ;M])
    }
    fn u32_pol2binary_pol<const M: usize>(pol: Polynomial<u32, M>) -> Polynomial<Binary, M> {
        pol!(array![ i => Binary::from(pol.coef_(i)) ; M])
    }
}
impl<const N: usize> CryptoCore for TRGSW<N> {
    type Representation = Encrypted<
        [Polynomial<Torus, N>; 2 * TRGSW::<0>::L],
        [Polynomial<Torus, N>; 2 * TRGSW::<0>::L],
    >;
}
impl<const N: usize> Crypto<Polynomial<u32, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<u32, N>,
    ) -> <Self as CryptoCore>::Representation {
        const L: usize = TRGSW::<0>::L;

        let trlwe = TRLWE::new();

        let mut cipher = [Polynomial::<Torus, N>::zero(); 2 * L]; // TODO: コピーしすぎ,unsafeでかくべし
        let mut p_key = [Polynomial::<Torus, N>::zero(); 2 * L]; // TODO: コピーしすぎ,unsafeでかくべし
        for i in 0..2 * L {
            let Encrypted(b, a) = trlwe.encrypto(s_key, Polynomial::<Torus, N>::zero());
            cipher[i] = cipher[i] + b;
            p_key[i] = p_key[i] + a;
        }
        {
            let mut bg: f32 = 1.0;
            for i in 0..L {
                bg *= TRGSW::<0>::BG_INV;
                let p = pol!(array![ i => torus!((item.coef_(i) as f32)*bg);N]);
                cipher[i] = cipher[i] + p;
                p_key[i + L] = p_key[i + L] + p;
            }
        }
        Encrypted(cipher, p_key)
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: <Self as CryptoCore>::Representation,
    ) -> Polynomial<u32, N> {
        todo!()
    }
}
impl<const N: usize> Crypto<Polynomial<Binary, N>> for TRGSW<N> {
    type SecretKey = Polynomial<Binary, N>;

    fn encrypto(
        &self,
        s_key: &Self::SecretKey,
        item: Polynomial<Binary, N>,
    ) -> <Self as CryptoCore>::Representation {
        self.encrypto(s_key, TRGSW::<0>::binary_pol2u32_pol(item))
    }

    fn decrypto(
        &self,
        s_key: &Self::SecretKey,
        rep: <Self as CryptoCore>::Representation,
    ) -> Polynomial<Binary, N> {
        TRGSW::<0>::u32_pol2binary_pol(self.decrypto(s_key, rep))
    }
}

impl<const N: usize>
    Cross<
        /*<TRLWE as CryptoCore>::Representation*/
        Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>,
    > for <TRGSW<N> as CryptoCore>::Representation
{
    type Output = Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>;

    fn cross(&self, rhs: &Encrypted<Polynomial<Torus, N>, Polynomial<Torus, N>>) -> Self::Output {
        const L: usize = TRGSW::<0>::L;
        const BGBIT: u32 = TRGSW::<0>::BGBIT;
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

#[cfg(test)]
mod tests {
    use super::*;
    use math_utils::*;
    use test::Bencher;

    #[test]
    fn trgsw_encrypto() {
        const N: usize = 3;
        let trgsw = TRGSW::<N>::new();

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());
        let pol: Polynomial<u32, N> = pol!([5, 15, 20]);
        let rep = trgsw.encrypto(&s_key, pol);
    }

    #[test]
    fn trgsw_cross() {
        const N: usize = 3;
        let trgsw = TRGSW::<N>::new();
        let trlwe = TRLWE::<N>::new();

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol: Polynomial<u32, N> = pol!([5, 15, 20]);
        let rep_trgsw = trgsw.encrypto(&s_key, pol);

        let pol: Polynomial<Torus, N> = pol!([torus!(0.5), torus!(0.25), torus!(0.125)]);
        let rep_trlwe = trlwe.encrypto(&s_key, pol);

        let res_cross = rep_trgsw.cross(&rep_trlwe);
    }

    /// <2021/8/16> 40,921,939 ns/iter (+/- 4,744,092)
    #[bench]
    fn bench_trgsw_cross(b: &mut Bencher) {
        const N: usize = TRLWE::<0>::N;
        let trgsw = TRGSW::<N>::new();
        let trlwe = TRLWE::<N>::new();

        let s_key = pol!(BinaryDistribution::uniform().gen_n::<N>());

        let pol: Polynomial<u32, N> = pol!(array![ i => (i%TRGSW::<0>::BG)as u32;N]);
        let rep_trgsw = trgsw.encrypto(&s_key, pol);

        let pol: Polynomial<Torus, N> = pol!(ModDistribution::uniform().gen_n::<N>());
        let rep_trlwe = trlwe.encrypto(&s_key, pol);

        b.iter(|| rep_trgsw.cross(&rep_trlwe))
    }
}
