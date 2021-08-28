use crate::digest::Cryptor;
use crate::tlwe::KeySwitchingKey;
use crate::trgsw::TRGSW;
use crate::{digest::Encrypted, tlwe::TLWERep, trgsw::TRGSWRep, trlwe::TRLWERep};
use num::ToPrimitive;
use utils::math::{Binary, Polynomial, Torus};
use utils::{pol, torus};

pub struct TFHE<const TLWE_N: usize, const TRLWE_N: usize>;

pub struct TFHEHelper;
impl TFHEHelper {
    pub const NBIT: u32 = 10; // = log_2(TRLWEHelper::N)
    pub const COEF: f32 = 1. / 8.;
}

impl<const TLWE_N: usize, const TRLWE_N: usize> TFHE<TLWE_N, TRLWE_N> {
    pub fn hom_nand(
        input_0: TLWERep<TLWE_N>,
        input_1: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
        ks: &KeySwitchingKey<TRLWE_N, TLWE_N>,
    ) -> TLWERep<TLWE_N>
    where
        [(); TRLWE_N / 2]: ,
    {
        let tlwelv0 = // 1 1 => < 0, other => > 0
            TLWERep::trivial_one(torus!(TFHEHelper::COEF)) - (input_0 + input_1);
        let tlwelv1 = Self::gate_bootstrapping_tlwe2tlwe(tlwelv0, bk);
        tlwelv1.identity_key_switch(ks)
    }
    fn gate_bootstrapping_tlwe2tlwe(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
    ) -> TLWERep<TRLWE_N>
    where
        [(); TRLWE_N / 2]: ,
    {
        let testvec = TRLWERep::trivial_one(pol!([torus!(TFHEHelper::COEF); TRLWE_N]));
        let trlwe = TFHE::blind_rotate(rep_tlwe, bk, testvec);
        trlwe.sample_extract_index(0)
    }
    fn blind_rotate(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
        base: TRLWERep<TRLWE_N>,
    ) -> TRLWERep<TRLWE_N>
    where
        [(); TRLWE_N / 2]: ,
    {
        const NBIT: u32 = TFHEHelper::NBIT;
        const BITS: u32 = u32::BITS;
        let (b, a) = rep_tlwe.get_and_drop();
        let b = (b.inner() >> (BITS - NBIT - 1)).to_i32().unwrap(); // floor(b * 2*2^(NBIT))
        let rotate = |rep: &TRLWERep<TRLWE_N>, n: i32| rep.map(|p| p.rotate(n));

        // 計算 X^{-2bg(b-a*s)}*base = X^{(2bg*a)*s-(2bg*b)}*base where bg = 2^{NBIT}
        let trlwe = a
            .iter()
            .zip(bk.iter())
            .fold(rotate(&base, -b), |trlwe, (a_i, bk_i)| {
                let a =
                    (a_i.inner().wrapping_add(1 << (BITS - NBIT - 2)) >> (BITS - NBIT - 1)) as i32; // a_i.rounnd() * 2^(NBIT)
                bk_i.cmux(rotate(&trlwe, a), trlwe)
            });

        trlwe
    }
}

pub struct BootstrappingKey<const PRE_N: usize, const N: usize>(Vec<TRGSWRep<N>>);

impl<const PRE_N: usize, const N: usize> BootstrappingKey<PRE_N, N> {
    pub fn new(s_key_tlwe: [Binary; PRE_N], s_key: &Polynomial<Binary, N>) -> Self
    where
        [(); N / 2]: ,
    {
        let mut vec = Vec::<TRGSWRep<N>>::with_capacity(PRE_N);
        for s_i in s_key_tlwe {
            vec.push(Cryptor::encrypto(TRGSW, s_key, s_i));
        }
        BootstrappingKey(vec)
    }
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, TRGSWRep<N>> {
        self.0.iter()
    }
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, TRGSWRep<N>> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use std::time;
    use utils::math::{BinaryDistribution, Random};
    use utils::timeit;

    use super::*;
    use crate::tlwe::{TLWEHelper, TLWE};
    use test::Bencher;

    #[bench]
    #[ignore = "a little late, for about 1 minute"]
    fn tfhe_hom_nand(_: &mut Bencher) {
        const TLWE_N: usize = TLWEHelper::N;
        const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
        let mut unif = BinaryDistribution::uniform();
        let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
        let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

        let ksk = timeit!(
            "make ksk",
            KeySwitchingKey::new(s_key_tlwelv1, &s_key_tlwelv0)
        );
        let bk = timeit!(
            "make bk",
            BootstrappingKey::new(s_key_tlwelv0, &pol!(s_key_tlwelv1))
        );

        {
            // Nandか確認
            let tlwelv0_1 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
            let tlwelv0_0 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);

            let rep_0_0 = timeit!(
                "hom nand 0 0",
                TFHE::hom_nand(tlwelv0_0(), tlwelv0_0(), &bk, &ksk)
            );
            let rep_0_1 = timeit!(
                "hom nand 0 1",
                TFHE::hom_nand(tlwelv0_0(), tlwelv0_1(), &bk, &ksk)
            );
            let rep_1_0 = timeit!(
                "hom nand 1 0",
                TFHE::hom_nand(tlwelv0_1(), tlwelv0_0(), &bk, &ksk)
            );
            let rep_1_1 = timeit!(
                "hom nand 1 1",
                TFHE::hom_nand(tlwelv0_1(), tlwelv0_1(), &bk, &ksk)
            );

            let res_0_0: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_0_0);
            let res_0_1: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_0_1);
            let res_1_0: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_1_0);
            let res_1_1: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep_1_1);

            assert_eq!(
                [res_0_0, res_0_1, res_1_0, res_1_1],
                [Binary::One, Binary::One, Binary::One, Binary::Zero],
                "0 nand 0 = 1 ?{} ,0 nand 1 = 1 ?{} ,1 nand 0 = 1 ?{} ,1 nand 1 = 0 ?{}",
                res_0_0,
                res_0_1,
                res_1_0,
                res_1_1
            );
        }
    }

    /// <2021/8/24> 15,593,340,479 ns/iter (+/- 4,537,182,672)
    /// <2021/8/25>  1,698,811,866 ns/iter (+/- 192,033,341) // FFT導入
    /// <2021/8/25>  1,643,367,136 ns/iter (+/- 686,612,125) // FFT_MAPを導入
    /// <2021/8/28>  1,500,582,227 ns/iter (+/- 39,434,083) // 事前計算を導入
    #[bench]
    #[ignore = "Too late. for about 1 hour"]
    fn tfhe_hom_nand_bench(bencher: &mut Bencher) {
        const TLWE_N: usize = TLWEHelper::N;
        const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
        let mut unif = BinaryDistribution::uniform();
        let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
        let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

        let ksk = timeit!(
            "make ksk",
            KeySwitchingKey::new(s_key_tlwelv1, &s_key_tlwelv0)
        );
        let bk = timeit!(
            "make bk",
            BootstrappingKey::new(s_key_tlwelv0, &pol!(s_key_tlwelv1))
        );

        {
            let tlwelv0_1 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
            let tlwelv0_0 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);

            bencher.iter(|| TFHE::hom_nand(tlwelv0_1.clone(), tlwelv0_0.clone(), &bk, &ksk));
        }
    }
}
