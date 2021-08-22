use crate::digest::Cryptor;
use crate::tlwe::{KeySwitchingKey};
use crate::trgsw::TRGSW;
use crate::{digest::Encrypted, tlwe::TLWERep, trgsw::TRGSWRep, trlwe::TRLWERep};
use array_macro::array;
use num::{ToPrimitive,Zero};
use utils::math::{Binary, Polynomial, Torus};
use utils::{pol, torus};


pub struct TFHE<const TLWE_N: usize,const TRLWE_N:usize>;

pub struct TFHEHelper;
impl TFHEHelper {
    pub const NBIT: u32 = 10;
    pub const COEF: f32 = 1. / 8.;
}

impl<const TLWE_N: usize,const TRLWE_N:usize> TFHE<TLWE_N,TRLWE_N> {
    pub fn hom_nand(input_0:TLWERep<TLWE_N>,input_1:TLWERep<TLWE_N>,bk:&BootstrappingKey<TLWE_N,TRLWE_N>,ks:&KeySwitchingKey<TRLWE_N,TLWE_N>){
        let tlwelv0 = TLWERep::new(torus!(1.0/8.0),[Torus::zero();TLWE_N]) - (input_0 + input_1);
        let tlwelv1 = Self::gate_bootstrapping_tlwe2tlwe(tlwelv0, bk);
        tlwelv1.identity_key_switch(ks);
    }
    fn gate_bootstrapping_tlwe2tlwe(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N,TRLWE_N>,
    ) -> TLWERep<TRLWE_N> {
        let testvec= TRLWERep::trivial_one(pol!([torus!(TFHEHelper::COEF);TRLWE_N]));
        let trlwe = TFHE::blind_rotate(rep_tlwe, bk, testvec);
        trlwe.sample_extract_index(0)
    }
    fn blind_rotate(
        rep_tlwe: TLWERep<TLWE_N>,
        bk: &BootstrappingKey<TLWE_N,TRLWE_N>,
        base: TRLWERep<TRLWE_N>,
    ) -> TRLWERep<TRLWE_N> {
        const NBIT: u32 = TFHEHelper::NBIT;
        const BITS: u32 = u32::BITS;
        let (b, a) = rep_tlwe.get_and_drop();
        let b = (b.inner() >> (BITS - NBIT - 1)).to_i32().unwrap(); // floor(b * 2^(NBIT))

        // 計算
        let trlwe = a.iter().zip(bk.iter()).fold(
            base.map(|p| p.rotate(b)),
            |trlwe, (a_i, s_i)| {
                let a_i = (a_i.inner() + (1 << (BITS - NBIT - 2)) >> (BITS - NBIT - 1)).to_i32().unwrap();
                s_i.cmux(trlwe.map(|p| p.rotate(a_i)), trlwe)
            },
        );

        trlwe
    }
}

pub struct BootstrappingKey<const PRE_N:usize,const N:usize>([TRGSWRep<N>; PRE_N]);

impl<const N:usize, const PRE_N:usize> BootstrappingKey<PRE_N, N> {
    pub fn new(s_key_tlwe:[Binary;PRE_N],s_key:&Polynomial<Binary,N>) -> Self{
        BootstrappingKey(array![ i => Cryptor::encrypto(TRGSW, s_key, s_key_tlwe[i]);PRE_N])
    }
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_,TRGSWRep<N>> {
        self.0.iter()
    }
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_,TRGSWRep<N>> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tfhe_hom_nand() {
    } 
}

