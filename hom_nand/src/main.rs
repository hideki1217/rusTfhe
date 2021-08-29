use hom_nand::{
    digest::Cryptor,
    tfhe::{TFHEHelper, TFHE},
    tlwe::{TLWEHelper, TLWE},
};
use std::time;
use utils::{
    math::{Binary, BinaryDistribution, Random}, timeit,
};

fn main() {
    const TLWE_N: usize = TLWEHelper::N;
    const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
    let mut unif = BinaryDistribution::uniform();
    let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
    let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

    let tfhe = TFHE::new(s_key_tlwelv0,s_key_tlwelv1);

    {
        // Nandか確認
        let tlwelv0_1 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
        let tlwelv0_0 = || Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);

        let rep_0_0 = timeit!(
            "hom nand 0 0",
            tfhe.hom_nand(tlwelv0_0(), tlwelv0_0())
        );
        let rep_0_1 = timeit!(
            "hom nand 0 1",
            tfhe.hom_nand(tlwelv0_0(), tlwelv0_1())
        );
        let rep_1_0 = timeit!(
            "hom nand 1 0",
            tfhe.hom_nand(tlwelv0_1(), tlwelv0_0())
        );
        let rep_1_1 = timeit!(
            "hom nand 1 1",
            tfhe.hom_nand(tlwelv0_1(), tlwelv0_1())
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