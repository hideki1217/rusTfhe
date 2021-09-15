use hom_nand::{
    digest::Cryptor,
    tfhe::{TFHEHelper, TFHE},
    tlwe::{TLWEHelper, TLWERep, TLWE},
};
use nander::{eval_logic_expr, parse_logic_expr, Logip};
use std::{
    array,
    io::{self, BufRead, Write},
};
use utils::{
    math::{Binary, BinaryDistribution, Random},
    timeit,
};

#[cfg(feature = "profile")]
use nander::hom_nand_profile;

#[cfg(not(feature = "profile"))]
fn nander_console<P, CreateP, CONVERT>(f: CreateP, g: CONVERT)
where
    P: Logip,
    CreateP: Fn() -> P,
    CONVERT: Fn(P::R) -> Binary,
{
    println!("Hello nander!!");
    println!("[Rule]1:true,0:false,&:and,$:nand,!:not,|:or,^:xor");
    println!("[Example]");
    println!("- 1&1 => 1");
    println!("- !(1|0)$0 => 1");
    println!("- 1&1$0 => (1&1)$0");

    let pros = f();

    let print_sufix = || {
        print!("nander>");
        io::stdout().flush().unwrap();
    };
    let mut stdin = std::io::BufReader::new(io::stdin());
    let mut buffer = String::new();
    loop {
        print_sufix();
        buffer.clear();
        let res = stdin.read_line(&mut buffer);
        match res {
            Ok(_) => {
                let exp = {
                    let res = parse_logic_expr(&buffer);
                    if let Err(err) = res {
                        println!("[Parse Error] {}", err);
                        continue;
                    }
                    res.unwrap()
                };

                let start = std::time::Instant::now();
                let z_ = eval_logic_expr(&pros, exp);
                let time_ms = start.elapsed().as_millis();

                let z: Binary = g(z_);

                println!("> {}", z);
                println!("culc time = {} milli sec", time_ms);
            }
            Err(error) => {
                println!("{}", error);
            }
        }
    }
}

#[cfg(feature = "profile")]
fn main() {
    hom_nand_profile();
}

#[cfg(not(feature = "profile"))]
fn main() {
    const TLWE_N: usize = TLWEHelper::N;
    const TRLWE_N: usize = 2_usize.pow(TFHEHelper::NBIT); //TRLWEHelper::N;
    let mut unif = BinaryDistribution::uniform();
    let s_key_tlwelv0 = unif.gen_n::<TLWE_N>();
    let s_key_tlwelv1 = unif.gen_n::<TRLWE_N>();
    let create_tfhe = || TFHE::new(s_key_tlwelv0, s_key_tlwelv1);
    let convert = |rep: TLWERep<TLWE_N>| Cryptor::decrypto(TLWE, &s_key_tlwelv0, rep);

    nander_console(create_tfhe, convert);
}

/*
fn sample<P,Convert>(p:P,f:Convert) -> i32 where P:Trait,Convert:Fn(P::R)->i32 {
    f(p.func())
}
fn main() {
    let t = TraitImpl::<10>(4);
    sample(t,|x|x.0);
}*/
