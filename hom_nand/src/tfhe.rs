use crate::digest::Cryptor;
use crate::tlwe::KeySwitchingKey;
use crate::trgsw::TRGSW;
use crate::{digest::Encrypted, tlwe::TLWERep, trgsw::TRGSWRepF, trlwe::TRLWERep};
use num::ToPrimitive;
use utils::math::{Binary, Polynomial, Torus32};
use utils::{pol, torus};

pub struct TFHE<const TLWE_N: usize, const TRLWE_N: usize> {
    bk: BootstrappingKey<TLWE_N, TRLWE_N>,
    ksk: KeySwitchingKey<TRLWE_N, TLWE_N>,
}

pub struct TFHEHelper;
impl TFHEHelper {
    pub const NBIT: u32 = 10; // = log_2(TRLWEHelper::N)
    pub const COEF: f32 = 1. / 8.;
}

impl<const TLWE_N: usize, const TRLWE_N: usize> TFHE<TLWE_N, TRLWE_N> {
    pub fn new(s_key_tlwelv0: [Binary; TLWE_N], s_key_tlwelv1: [Binary; TRLWE_N]) -> Self {
        let ksk = KeySwitchingKey::new(s_key_tlwelv1, &s_key_tlwelv0);
        let bk = BootstrappingKey::new(s_key_tlwelv0, &pol!(s_key_tlwelv1));
        TFHE { bk, ksk }
    }
    /// (input_1&control)|(input_0&!control)
    pub fn hom_mux(
        &self,
        control: TLWERep<TLWE_N>,
        input_0: TLWERep<TLWE_N>,
        input_1: TLWERep<TLWE_N>,
    ) -> TLWERep<TLWE_N> {
        let i_1 = self.hom_and(control.clone(), input_1);
        let i_0 = self.hom_and(-control, input_0);
        Self::bootstrap(
            i_1 + i_0 + TLWERep::trivial(torus!(TFHEHelper::COEF)),
            &self.bk,
            &self.ksk,
        )
    }
    pub fn hom_nand(&self, input_0: TLWERep<TLWE_N>, input_1: TLWERep<TLWE_N>) -> TLWERep<TLWE_N> {
        Self::bootstrap(
            TLWERep::trivial(torus!(TFHEHelper::COEF)) - (input_0 + input_1),
            &self.bk,
            &self.ksk,
        )
    }
    pub fn hom_and(&self, input_0: TLWERep<TLWE_N>, input_1: TLWERep<TLWE_N>) -> TLWERep<TLWE_N> {
        Self::bootstrap(
            (input_0 + input_1) - TLWERep::trivial(torus!(TFHEHelper::COEF)),
            &self.bk,
            &self.ksk,
        )
    }
    pub fn hom_or(&self, input_0: TLWERep<TLWE_N>, input_1: TLWERep<TLWE_N>) -> TLWERep<TLWE_N> {
        Self::bootstrap(
            (input_0 + input_1) + TLWERep::trivial(torus!(TFHEHelper::COEF)),
            &self.bk,
            &self.ksk,
        )
    }
    pub fn hom_xor(&self, input_0: TLWERep<TLWE_N>, input_1: TLWERep<TLWE_N>) -> TLWERep<TLWE_N> {
        Self::bootstrap(
            (input_0 + input_1) * 2 + TLWERep::trivial(torus!(2.0 * TFHEHelper::COEF)),
            &self.bk,
            &self.ksk,
        )
    }
    pub fn hom_not(&self, input: TLWERep<TLWE_N>) -> TLWERep<TLWE_N> {
        Self::bootstrap(-input, &self.bk, &self.ksk)
    }

    fn bootstrap(
        tlwelv0: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
        ks: &KeySwitchingKey<TRLWE_N, TLWE_N>,
    ) -> TLWERep<TLWE_N> {
        let tlwelv1 = Self::gate_bootstrapping_tlwe2tlwe(tlwelv0, bk);
        tlwelv1.identity_key_switch(ks)
    }
    fn gate_bootstrapping_tlwe2tlwe(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
    ) -> TLWERep<TRLWE_N> {
        let testvec = TRLWERep::trivial(pol!([torus!(TFHEHelper::COEF); TRLWE_N]));
        let trlwe = TFHE::blind_rotate(rep_tlwe, bk, testvec);
        trlwe.sample_extract_index(0)
    }
    fn blind_rotate(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N, TRLWE_N>,
        base: TRLWERep<TRLWE_N>,
    ) -> TRLWERep<TRLWE_N> {
        const NBIT: u32 = TFHEHelper::NBIT;
        const BITS: u32 = u32::BITS;
        let (b, a) = rep_tlwe.get_and_drop();
        let b = (b.inner() >> (BITS - NBIT - 1)).to_i32().unwrap(); // floor(b * 2*2^(NBIT))
        let rotate = |rep: &TRLWERep<TRLWE_N>, n: i32|{
            rep.map(|p|p.rotate(n) )
        };

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

pub struct BootstrappingKey<const PRE_N: usize, const N: usize>(Vec<TRGSWRepF<N>>);

impl<const PRE_N: usize, const N: usize> BootstrappingKey<PRE_N, N> {
    pub fn new(s_key_tlwe: [Binary; PRE_N], s_key: &Polynomial<Binary, N>) -> Self {
        let mut vec = Vec::<TRGSWRepF<N>>::with_capacity(PRE_N);
        for s_i in s_key_tlwe {
            let trgsw_ = Cryptor::encrypto(TRGSW, s_key, s_i);
            vec.push(TRGSWRepF::<N>::from(trgsw_));
        }
        BootstrappingKey(vec)
    }
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, TRGSWRepF<N>> {
        self.0.iter()
    }
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, TRGSWRepF<N>> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use std::time;
    use utils::math::{BinaryDistribution, Random};
    use utils::{mem, timeit};

    use super::*;
    use crate::tlwe::{TLWEHelper, TLWE};
    use test::Bencher;

    #[bench]
    //#[ignore = "a little late, for about 1 minute"]
    fn tfhe_hom_nand(_: &mut Bencher) {
        const TLWE_N: usize = TLWEHelper::N;
        const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
        let mut unif = BinaryDistribution::uniform();
        let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
        let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

        let tfhe = TFHE::new(s_key_tlwelv0, s_key_tlwelv1);

        let tlwelv0_1 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
        let tlwelv0_0 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);
        let tlwelv0_ = |b: Binary| match b {
            Binary::One => tlwelv0_1(),
            Binary::Zero => tlwelv0_0(),
        };
        {
            let title = "nand";
            let rep: [TLWERep<TLWE_N>; 4] = mem::array_create_enumerate(|i| {
                let input_0 = Binary::from(i & 0b01);
                let input_1 = Binary::from(i & 0b10);
                let input_0_tlwe = tlwelv0_(input_0);
                let input_1_tlwe = tlwelv0_(input_1);
                timeit!(
                    format!("{} {} {}", title, input_0, input_1),
                    tfhe.hom_nand(input_0_tlwe, input_1_tlwe)
                )
            });
            let res = mem::array_create_enumerate(|i| {
                let res: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep[i].clone());
                res
            });

            let expect = [Binary::One, Binary::One, Binary::One, Binary::Zero];
            assert_eq!(
                res, expect,
                "{}: 0 * 0 = {} ?{} ,0 * 1 = {} ?{} ,1 * 0 = {} ?{} ,1 * 1 = {} ?{}",
                title, expect[0], res[0], expect[1], res[1], expect[2], res[2], expect[3], res[3]
            );
        }
        {
            let title = "and";
            let rep: [TLWERep<TLWE_N>; 4] = mem::array_create_enumerate(|i| {
                let input_0 = Binary::from(i & 0b01);
                let input_1 = Binary::from(i & 0b10);
                let input_0_tlwe = tlwelv0_(input_0);
                let input_1_tlwe = tlwelv0_(input_1);
                timeit!(
                    format!("{} {} {}", title, input_0, input_1),
                    tfhe.hom_and(input_0_tlwe, input_1_tlwe)
                )
            });
            let res = mem::array_create_enumerate(|i| {
                let res: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep[i].clone());
                res
            });

            let expect = [Binary::Zero, Binary::Zero, Binary::Zero, Binary::One];
            assert_eq!(
                res, expect,
                "{}: 0 * 0 = {} ?{} ,0 * 1 = {} ?{} ,1 * 0 = {} ?{} ,1 * 1 = {} ?{}",
                title, expect[0], res[0], expect[1], res[1], expect[2], res[2], expect[3], res[3]
            );
        }
        {
            let title = "or";
            let rep: [TLWERep<TLWE_N>; 4] = mem::array_create_enumerate(|i| {
                let input_0 = Binary::from(i & 0b01);
                let input_1 = Binary::from(i & 0b10);
                let input_0_tlwe = tlwelv0_(input_0);
                let input_1_tlwe = tlwelv0_(input_1);
                timeit!(
                    format!("{} {} {}", title, input_0, input_1),
                    tfhe.hom_or(input_0_tlwe, input_1_tlwe)
                )
            });
            let res = mem::array_create_enumerate(|i| {
                let res: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep[i].clone());
                res
            });

            let expect = [Binary::Zero, Binary::One, Binary::One, Binary::One];
            assert_eq!(
                res, expect,
                "{}: 0 * 0 = {} ?{} ,0 * 1 = {} ?{} ,1 * 0 = {} ?{} ,1 * 1 = {} ?{}",
                title, expect[0], res[0], expect[1], res[1], expect[2], res[2], expect[3], res[3]
            );
        }
        {
            let title = "xor";
            let rep: [TLWERep<TLWE_N>; 4] = mem::array_create_enumerate(|i| {
                let input_0 = Binary::from(i & 0b01);
                let input_1 = Binary::from(i & 0b10);
                let input_0_tlwe = tlwelv0_(input_0);
                let input_1_tlwe = tlwelv0_(input_1);
                timeit!(
                    format!("{} {} {}", title, input_0, input_1),
                    tfhe.hom_xor(input_0_tlwe, input_1_tlwe)
                )
            });
            let res = mem::array_create_enumerate(|i| {
                let res: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep[i].clone());
                res
            });

            let expect = [Binary::Zero, Binary::One, Binary::One, Binary::Zero];
            assert_eq!(
                res, expect,
                "{}: 0 * 0 = {} ?{} ,0 * 1 = {} ?{} ,1 * 0 = {} ?{} ,1 * 1 = {} ?{}",
                title, expect[0], res[0], expect[1], res[1], expect[2], res[2], expect[3], res[3]
            );
        }
        {
            let title = "not";
            let rep: [TLWERep<TLWE_N>; 2] = mem::array_create_enumerate(|i| {
                let input = Binary::from(i & 0b1);
                let input_tlwe = tlwelv0_(input);
                timeit!(format!("{} {}", title, input), tfhe.hom_not(input_tlwe))
            });
            let res = mem::array_create_enumerate(|i| {
                let res: Binary = Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep[i].clone());
                res
            });

            let expect = [Binary::One, Binary::Zero];
            assert_eq!(
                res, expect,
                "{}: ~0 = {} ?{} ,~1 = {} ?{}",
                title, expect[0], res[0], expect[1], res[1]
            );
        }
    }

    /// - <2021/8/24> 15,593,340,479 ns/iter (+/- 4,537,182,672)
    /// - <2021/8/25>  1,698,811,866 ns/iter (+/- 192,033,341) // FFT導入
    /// - <2021/8/25>  1,643,367,136 ns/iter (+/- 686,612,125) // FFT_MAPを導入
    /// - <2021/8/28>  1,500,582,227 ns/iter (+/- 39,434,083) // 事前計算を導入
    /// - <2021/8/29>    400,571,320 ns/iter (+/- 40,190,736) // FloatとDecimalの変換を高速化
    /// - <2021/8/31>    379,600,929 ns/iter (+/- 45,192,670) // 変換を簡略化
    /// - <2021/9/4>     120,941,429 ns/iter (+/- 8,804,684)  // 逆FFTのタイミングをずらした
    /// - <2021/9/11>     77,693,595 ns/iter (+/- 30,553,478) // spqlios導入
    /// - <2021/9/11>     63,989,293 ns/iter (+/- 25,612,018) // BootStrappingKeyに事前計算を導入
    /// - <2021/9/12>     54,927,599 ns/iter (+/- 1,924,566) // decompotisionを最適化
    /// - <2021/9/12>     46,745,865 ns/iter (+/- 10,219,869) // decompotisionのarrayマクロをMaybeUninitで書き直す
    /// - <2021/9/13>     43,258,837 ns/iter (+/- 2,158,570) // utilsからarray!を削除
    /// - <2021/9/15>     37,276,167 ns/iter (+/- 4,091,762) // pol::decompotisionをinline化,hadamardを修正,全体からarray!を削除
    /// - <2021/9/15>     36,041,455 ns/iter (+/- 1,390,477) // identity key switching を早くした
    /// - <2021/9/15>     34,990,505 ns/iter (+/- 4,284,517) // TRGSWRepF::crossをちょいsimd化しやすいように直した
    /// - <2021/9/15>     34,468,102 ns/iter (+/- 5,501,576) // rotateを実装そのままでifを消去
    /// - <2021/9/15>     30,558,481 ns/iter (+/- 7,033,099) // 無駄な配列のコピーを見つけた
    #[bench]
    //#[ignore = "Too late. for about 1 hour"]
    fn tfhe_hom_nand_bench(bencher: &mut Bencher) {
        const TLWE_N: usize = TLWEHelper::N;
        const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
        let mut unif = BinaryDistribution::uniform();
        let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
        let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

        let tfhe = TFHE::new(s_key_tlwelv0, s_key_tlwelv1);

        {
            let tlwelv0_1 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
            let tlwelv0_0 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);

            bencher.iter(|| tfhe.hom_nand(tlwelv0_1.clone(), tlwelv0_0.clone()));
        }
    }
}
