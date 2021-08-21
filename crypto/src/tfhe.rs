use crate::tlwe::TLWEHelper;
use crate::{digest::Encrypted, tlwe::TLWERep, trgsw::TRGSWRep, trlwe::TRLWERep};
use utils::math::{Polynomial, Torus};
use utils::{pol, torus};

use num::Zero;

pub struct TFHE<const N: usize>;

pub struct TFHEHelper;
impl TFHEHelper {
    pub const NBIT: u32 = 10;
    pub const COEF: f32 = 1. / 8.;
}

impl<const N: usize> TFHE<N> {
    pub fn gate_bootstrapping_tlwe2tlwe(
        rep_tlwe: TLWERep<N>,
        bk: [TRGSWRep<N>; TLWEHelper::N],
    ) -> TLWERep<N> {
        let testvec: TRLWERep<N> = TRLWERep::trivial_one(pol!([torus!(TFHEHelper::COEF);N]));
        let trlwe: TRLWERep<N> = TFHE::blind_rotate(rep_tlwe, bk, testvec);
        trlwe.sample_extract_index(0)
    }
    fn blind_rotate(
        rep_tlwe: TLWERep<N>,
        bk: [TRGSWRep<N>; TLWEHelper::N],
        base: TRLWERep<N>,
    ) -> TRLWERep<N> {
        const NBIT: u32 = TFHEHelper::NBIT;
        const BITS: u32 = u32::BITS;
        let (b, a) = rep_tlwe.get_and_drop();
        let b = (b.inner() >> (BITS - NBIT - 1)) as i32; // floor(b * 2^(NBIT))

        // 計算
        let trlwe = a.iter().zip(bk.iter()).fold(
            base.map(|p| p.rotate(b)),
            |trlwe, (a_i, s_i)| {
                let a_i = (a_i.inner() + (1 << (BITS - NBIT - 2)) >> (BITS - NBIT - 1)) as i32;
                s_i.cmux(trlwe.map(|p| p.rotate(a_i)), trlwe)
            },
        );

        trlwe
    }
}
