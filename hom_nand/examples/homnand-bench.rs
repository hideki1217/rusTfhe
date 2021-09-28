use hom_nand::{digest::Cryptor, tfhe::{TFHE, TFHEHelper}, tlwe::{TLWE, TLWEHelper, TLWERep}};
use utils::{math::{Binary, BinaryDistribution, Random}, mem, timeit};
use std::time;

extern crate hom_nand;

fn main() {
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