#![feature(adt_const_params)]
#![feature(generic_const_exprs)]

extern crate hom_nand;
extern crate utils;

use hom_nand::{
    digest::Cryptor,
    tfhe::{TFHEHelper, TFHE},
    tlwe::{TLWEHelper, TLWERep, TLWE},
};
use std::str::Chars;
use utils::{mem,math::{Binary, BinaryDistribution, Random}, timeit, traits::AsLogic};
use std::time;


/// ## Logical Processer ( LOGIP )
/// evaluate logical op
pub trait Logip
where
    Self::R: AsLogic + Clone,
{
    type R;
    fn nand(&self, lhs: Self::R, rhs: Self::R) -> Self::R;
    fn not(&self, b: Self::R) -> Self::R {
        self.nand(b.clone(), b)
    }
    fn and(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.not(self.nand(lhs, rhs))
    }
    fn or(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.nand(self.not(lhs), self.not(rhs))
    }
    fn xor(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        let x = self.nand(lhs.clone(), rhs.clone());
        self.nand(self.nand(lhs, x.clone()), self.nand(x, rhs))
    }
}

impl<const N: usize, const M: usize> Logip for TFHE<N, M> {
    type R = TLWERep<N>;

    fn nand(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.hom_nand(lhs, rhs)
    }

    fn not(&self, b: Self::R) -> Self::R {
        self.hom_not(b)
    }

    fn and(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.hom_and(lhs, rhs)
    }

    fn or(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.hom_or(lhs, rhs)
    }

    fn xor(&self, lhs: Self::R, rhs: Self::R) -> Self::R {
        self.hom_xor(lhs, rhs)
    }
}

pub enum LogicExpr<R: AsLogic> {
    Nand(Box<Self>, Box<Self>),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Leaf(R),
}
pub fn eval_logic_expr<P: Logip>(pros: &P, exp: LogicExpr<<P as Logip>::R>) -> <P as Logip>::R {
    match exp {
        LogicExpr::<<P as Logip>::R>::Nand(rhs, lhs) => {
            pros.nand(eval_logic_expr(pros, *lhs), eval_logic_expr(pros, *rhs))
        }
        LogicExpr::<<P as Logip>::R>::Not(lhs) => pros.not(eval_logic_expr(pros, *lhs)),
        LogicExpr::<<P as Logip>::R>::And(lhs, rhs) => {
            pros.and(eval_logic_expr(pros, *lhs), eval_logic_expr(pros, *rhs))
        }
        LogicExpr::<<P as Logip>::R>::Or(lhs, rhs) => {
            pros.or(eval_logic_expr(pros, *lhs), eval_logic_expr(pros, *rhs))
        }
        LogicExpr::<<P as Logip>::R>::Xor(lhs, rhs) => {
            pros.xor(eval_logic_expr(pros, *lhs), eval_logic_expr(pros, *rhs))
        }
        LogicExpr::<<P as Logip>::R>::Leaf(elem) => elem,
    }
}
pub fn parse_logic_expr<R: AsLogic>(l: &str) -> Result<LogicExpr<R>, &str> {
    const ZERO: char = '0';
    const ONE: char = '1';
    const AND: char = '&';
    const OR: char = '|';
    const XOR: char = '^';
    const NOT: char = '!';
    const NAND: char = '$';
    const LEFT: char = '(';
    const RIGHT: char = ')';
    let mut l = l.trim().to_string();
    l.retain(|c| !c.is_whitespace());
    let mut l = l.as_str().chars();

    return match parse_binary_op::<R>(&mut l) {
        Result::Ok(item) => Ok(*item),
        Result::Err(err) => Err(err),
    };

    fn parse_binary_op<R: AsLogic>(l: &mut Chars) -> Result<Box<LogicExpr<R>>, &'static str> {
        let mut lhs = parse_mono_op::<R>(l)?;
        loop {
            match l.clone().next() {
                Option::Some(c) => match c {
                    AND => {
                        l.next();
                        lhs = Box::new(LogicExpr::And(lhs, parse_mono_op(l)?));
                    }
                    OR => {
                        l.next();
                        lhs = Box::new(LogicExpr::Or(lhs, parse_mono_op(l)?));
                    }
                    XOR => {
                        l.next();
                        lhs = Box::new(LogicExpr::Xor(lhs, parse_mono_op(l)?));
                    }
                    NAND => {
                        l.next();
                        lhs = Box::new(LogicExpr::Nand(lhs, parse_mono_op(l)?));
                    }
                    _ => {
                        return Ok(lhs);
                    }
                },
                Option::None => {
                    l.next();
                    return Ok(lhs);
                }
            }
        }
    }
    fn parse_mono_op<R: AsLogic>(l: &mut Chars) -> Result<Box<LogicExpr<R>>, &'static str> {
        if let Some(c) = l.clone().next() {
            if c == NOT {
                l.next();
                return Ok(Box::new(LogicExpr::Not(parse_mono_op(l)?)));
            }
        }
        Ok(parse_elem(l)?)
    }
    fn parse_elem<R: AsLogic>(l: &mut Chars) -> Result<Box<LogicExpr<R>>, &'static str> {
        match l.next() {
            Option::Some(c) => match c {
                ZERO => Ok(Box::new(LogicExpr::Leaf(R::logic_false()))),
                ONE => Ok(Box::new(LogicExpr::Leaf(R::logic_true()))),
                LEFT => {
                    let e = parse_binary_op::<R>(l)?;
                    if let Some(c) = l.next() {
                        if c == RIGHT {
                            Ok(e)
                        } else {
                            Err("braket is not closed")
                        }
                    } else {
                        Err("braket is not closed")
                    }
                }
                _ => Err("invalid element"),
            },
            Option::None => Err("invalid element. this is none"),
        }
    }
}

#[cfg(feature = "profile")]
pub fn hom_nand_profile() {

    const TLWE_N: usize = TLWEHelper::N;
    const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
    let mut unif = BinaryDistribution::uniform();
    let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
    let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();

    let tfhe = TFHE::new(s_key_tlwelv0, s_key_tlwelv1);

    let tlwelv0_1 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::One);
    let tlwelv0_0 = Cryptor::encrypto(TLWE, &s_key_tlwelv0, Binary::Zero);
    {
        let _res = timeit!(
            "hom_nand",
            tfhe.hom_nand(tlwelv0_0.clone(), tlwelv0_1.clone())
        );
        for _ in 0..100 {
            let _res = tfhe.hom_nand(tlwelv0_0.clone(), tlwelv0_1.clone());
        }
    }

    //tfhe_hom_nand_test();
}

#[cfg(feature = "profile")]
fn tfhe_hom_nand_test() {

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

/*
pub trait Trait{
    type R;
    fn func(self)->Self::R;
}
pub struct TraitImpl<const N:usize>(pub i32);
impl<const N:usize> Trait for TraitImpl<N>
where [();N/2]:,
{
    type R = Self;
    fn func(self)->Self::R {
        self
    }
}
 */
